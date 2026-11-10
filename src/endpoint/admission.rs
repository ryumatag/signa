/*!
Client admission before command enqueue.

A reservation follows a request through the command queue, a pending connect
and the transaction table. Its count is returned only when the transaction
ends. Its bytes are returned once the machine drops its request, at the final
response of a non-INVITE or the first response of an INVITE. The caller's
response future owns neither reservation, so dropping it cannot release
capacity.

An INVITE also reserves one CANCEL transaction when it is admitted, so filling
client capacity with new requests cannot make an INVITE impossible to cancel.
That reservation lives in the INVITE's entry until the CANCEL takes it or the
INVITE ends.

The counters account for logical message content, not the backing allocations
of shared buffers or application Extensions. Channels transfer ownership and
synchronize data. The atomics only reserve capacity, so relaxed counter ordering
is sufficient. A count reserved while the byte reservation fails is rolled back.
*/

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bytes::Bytes;

use super::Error;
use crate::{
    Request,
    message::header::{CALL_ID, CSEQ, FROM, MAX_FORWARDS, ROUTE, TO},
};

#[derive(Clone, Debug)]
pub(super) struct ClientAdmission(Arc<Capacity>);

#[derive(Debug)]
struct Capacity {
    max_count: usize,
    max_bytes: usize,
    count: AtomicUsize,
    bytes: AtomicUsize,
    closed: AtomicBool,
}

impl ClientAdmission {
    pub(super) fn new(max_count: usize, max_bytes: usize) -> ClientAdmission {
        ClientAdmission(Arc::new(Capacity {
            max_count,
            max_bytes,
            count: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            closed: AtomicBool::new(false),
        }))
    }

    pub(super) fn acquire(
        &self,
        request: &Request<Bytes>,
    ) -> Result<Permit, Error> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(Error::closed());
        }

        reserve(&self.0.count, 1, self.0.max_count)?;
        let mut permit = Permit { admission: self.clone(), bytes: 0 };
        let bytes = request_bytes(request).ok_or_else(Error::busy)?;
        reserve(&self.0.bytes, bytes, self.0.max_bytes)?;
        permit.bytes = bytes;

        // Closing can race either reservation. This check also returns both
        // resources when shutdown won before the command could be queued.
        if self.0.closed.load(Ordering::Acquire) {
            return Err(Error::closed());
        }
        Ok(permit)
    }

    /// Reserves `request`, an INVITE, together with the CANCEL that may
    /// follow it. Both succeed or neither does.
    pub(super) fn acquire_invite(
        &self,
        request: &Request<Bytes>,
    ) -> Result<(Permit, Permit), Error> {
        let invite = self.acquire(request)?;

        reserve(&self.0.count, 1, self.0.max_count)?;
        let mut cancel = Permit { admission: self.clone(), bytes: 0 };
        let bytes = cancel_bytes(request).ok_or_else(Error::busy)?;
        reserve(&self.0.bytes, bytes, self.0.max_bytes)?;
        cancel.bytes = bytes;

        if self.0.closed.load(Ordering::Acquire) {
            return Err(Error::closed());
        }
        Ok((invite, cancel))
    }

    pub(super) fn close(&self) {
        self.0.closed.store(true, Ordering::Release);
    }
}

/// The driver closes admission on every exit, including forced task teardown.
pub(super) struct AdmissionOwner(pub(super) ClientAdmission);

impl Drop for AdmissionOwner {
    fn drop(&mut self) {
        self.0.close();
    }
}

#[derive(Debug)]
pub(super) struct Permit {
    admission: ClientAdmission,
    bytes: usize,
}

impl Permit {
    pub(super) fn release_bytes(&mut self) {
        if self.bytes != 0 {
            self.admission.0.bytes.fetch_sub(self.bytes, Ordering::Relaxed);
            self.bytes = 0;
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.release_bytes();
        self.admission.0.count.fetch_sub(1, Ordering::Relaxed);
    }
}

fn reserve(
    counter: &AtomicUsize,
    amount: usize,
    max: usize,
) -> Result<(), Error> {
    let mut used = counter.load(Ordering::Relaxed);
    loop {
        let total = used
            .checked_add(amount)
            .filter(|&total| total <= max)
            .ok_or_else(Error::busy)?;
        match counter.compare_exchange_weak(
            used,
            total,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(actual) => used = actual,
        }
    }
}

/// Stored input bytes, without encoding a second copy before admission.
pub(super) fn request_bytes(request: &Request<Bytes>) -> Option<usize> {
    let mut bytes = request.body().len();
    for part in [
        request.method().as_str(),
        request.uri().as_str(),
        request.version().as_str(),
    ] {
        bytes = bytes.checked_add(part.len())?;
    }
    for (name, value) in request.headers() {
        bytes = bytes
            .checked_add(name.as_str().len())?
            .checked_add(value.len())?;
    }
    Some(bytes)
}

/// The logical size of the CANCEL an INVITE may need, which copies the
/// INVITE's Request-URI, From, To, Call-ID, CSeq and Route
/// ([RFC 3261 section 9.1]). Max-Forwards is two digits, and the CSeq method
/// grows from INVITE to CANCEL by nothing. The Via is not counted, as for
/// every client request, since the driver adds it.
///
/// [RFC 3261 section 9.1]: https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1
pub(super) fn cancel_bytes(request: &Request<Bytes>) -> Option<usize> {
    let mut bytes = ["CANCEL", request.uri().as_str(), "SIP/2.0", "70"]
        .iter()
        .try_fold(0usize, |total, part| total.checked_add(part.len()))?;
    bytes = bytes.checked_add(MAX_FORWARDS.as_str().len())?;
    for (name, value) in request.headers() {
        if [FROM, TO, CALL_ID, CSEQ, ROUTE].contains(name) {
            bytes = bytes
                .checked_add(name.as_str().len())?
                .checked_add(value.len())?;
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request<Bytes> {
        Request::builder()
            .method("OPTIONS")
            .uri("sip:example.com")
            .body(Bytes::from_static(b"body"))
            .unwrap()
    }

    #[test]
    fn bytes_and_count_have_separate_lifetimes() {
        let request = request();
        let bytes = request_bytes(&request).unwrap();
        let admission = ClientAdmission::new(2, bytes);
        let mut first = admission.acquire(&request).unwrap();

        assert!(admission.acquire(&request).unwrap_err().is_busy());
        assert_eq!(admission.0.count.load(Ordering::Relaxed), 1);

        first.release_bytes();
        first.release_bytes();
        let second = admission.acquire(&request).unwrap();
        assert!(admission.acquire(&request).unwrap_err().is_busy());

        drop(first);
        drop(second);

        assert_eq!(admission.0.count.load(Ordering::Relaxed), 0);
        assert_eq!(admission.0.bytes.load(Ordering::Relaxed), 0);
        assert!(admission.acquire(&request).is_ok());
    }

    #[test]
    fn an_invite_reserves_its_cancel_or_nothing() {
        let invite = Request::builder()
            .method("INVITE")
            .uri("sip:bob@example.com")
            .header("Route", "<sip:proxy.example.com;lr>")
            .header("CSeq", "1 INVITE")
            .body(Bytes::from_static(b"v=0"))
            .unwrap();
        let invite_bytes = request_bytes(&invite).unwrap();
        let cancel = cancel_bytes(&invite).unwrap();
        assert!(cancel < invite_bytes + "Max-Forwards70".len());

        let admission = ClientAdmission::new(2, invite_bytes + cancel);
        let (first, reserved) = admission.acquire_invite(&invite).unwrap();
        assert_eq!(admission.0.count.load(Ordering::Relaxed), 2);
        assert_eq!(reserved.bytes, cancel);

        // Neither the count nor the bytes of a refused pair stay reserved.
        drop(first);
        assert!(admission.acquire_invite(&invite).unwrap_err().is_busy());
        assert_eq!(admission.0.count.load(Ordering::Relaxed), 1);
        assert_eq!(admission.0.bytes.load(Ordering::Relaxed), cancel);

        drop(reserved);
        let admission = ClientAdmission::new(3, invite_bytes + cancel - 1);
        assert!(admission.acquire_invite(&invite).unwrap_err().is_busy());
        assert_eq!(admission.0.count.load(Ordering::Relaxed), 0);
        assert_eq!(admission.0.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn owner_teardown_closes_admission_with_live_permits() {
        let admission = ClientAdmission::new(1, usize::MAX);
        let owner = AdmissionOwner(admission.clone());
        let permit = admission.acquire(&request()).unwrap();

        drop(owner);

        assert!(admission.acquire(&request()).unwrap_err().is_closed());
        drop(permit);
        assert_eq!(admission.0.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn arithmetic_overflow_and_zero_capacity_never_admit_work() {
        let counter = AtomicUsize::new(usize::MAX - 1);
        assert!(reserve(&counter, 2, usize::MAX).unwrap_err().is_busy());
        assert_eq!(counter.load(Ordering::Relaxed), usize::MAX - 1);
        assert!(
            ClientAdmission::new(0, usize::MAX).acquire(&request()).is_err()
        );
        assert!(ClientAdmission::new(1, 0).acquire(&request()).is_err());
    }

    #[test]
    fn content_budget_includes_start_line_fields_headers_and_body() {
        use crate::{HeaderName, HeaderValue};

        let mut request = request();
        request.headers_mut().insert(
            HeaderName::from_static("x-trace"),
            HeaderValue::from_static("opaque"),
        );
        // OPTIONS (7), URI (15), SIP/2.0 (7), body (4), header name/value (7+6).
        let exact = ClientAdmission::new(1, 46);
        let short = ClientAdmission::new(1, 45);

        assert!(exact.acquire(&request).is_ok());
        assert!(short.acquire(&request).unwrap_err().is_busy());
        assert_eq!(short.0.count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn concurrent_reservations_never_exceed_either_limit_or_leak() {
        let admission =
            ClientAdmission::new(4, 4 * request_bytes(&request()).unwrap());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let admission = admission.clone();
                std::thread::spawn(move || {
                    for _ in 0..if cfg!(miri) { 4 } else { 1000 } {
                        if let Ok(mut permit) = admission.acquire(&request()) {
                            assert!(
                                admission.0.count.load(Ordering::Relaxed) <= 4
                            );
                            assert!(
                                admission.0.bytes.load(Ordering::Relaxed)
                                    <= admission.0.max_bytes
                            );
                            permit.release_bytes();
                        }
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        assert_eq!(admission.0.count.load(Ordering::Relaxed), 0);
        assert_eq!(admission.0.bytes.load(Ordering::Relaxed), 0);
    }
}
