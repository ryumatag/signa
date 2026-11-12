/*!
Entry points for the fuzz targets in `fuzz/`. Unstable and not part of the
public API.

Each takes the bytes a fuzzer made. [`headers`] runs one request through the
readers of the headers a UA interprets and through the classification of a
request by an empty model, which finds no dialog. [`messages`] feeds a series
of requests to the state model as the runtime routes them, with an
application that decides each INVITE by a byte of the input and a runtime
whose jobs fail when the input says so, and checks that a termination then
leaves the model at rest. That covers the classification in a dialog too.
Neither needs a socket or a runtime, so a fuzzer runs them fast and the same
input always does the same.

The harness plays a UAS alone, as a UAC needs responses that the input does
not carry. The effects of a UAC are handled only so that every effect is.

The model's checks between its tables run in its tests only. Here an input
fails by a panic, or by a model that does not come to rest.
*/

use std::time::{Duration, Instant};

use bytes::Bytes;
use signa_core::{
    HeaderValue, Method, Request, StatusCode,
    transport::{Flow, Transport},
};

use crate::{
    error::Error,
    header,
    invite::{CancelResult, ExchangeKey},
    model::{
        Authority, ByeStarted, Command, Effect, Event, Limits, Model, Random,
    },
    negotiation::{Body, Description},
};

/// The bytes of a session description a UA keeps at most, as the runtime's
/// default.
const DESCRIPTION_LIMIT: usize = 32 * 1024;

/// Reads `data` as a request, and gives it to every reader of the headers
/// the UA interprets, to the reading of its body, and to the classification
/// of an empty model. Malformed input has to come back as an error.
pub fn headers(data: &[u8]) {
    let Ok(request) = Request::from_bytes(data) else {
        return;
    };
    let headers = request.headers();

    let _ = header::call_id(headers);
    let _ = header::from(headers);
    let _ = header::to(headers);
    let _ = header::contact(headers);
    let _ = header::cseq(headers);
    let _ = header::expires(headers);
    let _ = header::requires_extension(headers);
    let _ = header::content_type(headers);
    let _ = header::content_disposition(headers);
    let _ = header::encoded(headers);
    let _ = Body::read(headers, request.body(), DESCRIPTION_LIMIT);

    let model = model();
    let _ = model.classify(&request);
    let _ = model.knows_dialog(&request);
}

/// Feeds the requests in `data` to a fresh model, one after another.
///
/// `data` is a series of records, each a byte of choice, two bytes of
/// length, big-endian, and a request of that length. The bits of the choice
/// say, from the lowest:
///
/// * 0 and 1: how the application decides an INVITE the model takes:
///   accept, reject, answer with a provisional response, or hold.
/// * 2: whether the runtime's jobs fail while this record settles.
/// * 3 and 4: what the application does first with the oldest INVITE it
///   holds: nothing, accept, reject, or drop it.
/// * 5 to 7: how much time passes after the record.
///
/// After the last record the UA shuts down with a termination, and has to
/// come to rest.
pub fn messages(data: &[u8]) {
    let mut fuzzed = Fuzzed::new();
    let mut rest = data;
    while let [choice, high, low, after @ ..] = rest {
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        let (message, after) = after.split_at(length.min(after.len()));
        rest = after;
        fuzzed.failing = choice & 0b100 != 0;
        fuzzed.decide_held(*choice);
        fuzzed.receive(*choice, message);
        fuzzed.settle();
        fuzzed.pass(*choice);
    }
    fuzzed.failing = false;
    fuzzed.terminate();
}

/// Randomness that counts, so that an input always does the same.
struct Counter(u64);

impl Random for Counter {
    fn next_u64(&mut self) -> Option<u64> {
        self.0 = self.0.wrapping_add(1);
        Some(self.0)
    }
}

fn model() -> Model<Counter> {
    let limits = Limits {
        attempts: 4,
        incoming: 4,
        dialogs: 4,
        usages: 4,
        replays: 8,
        forks: 4,
        cleanups: 4,
        routes: 8,
        operations: 8,
        commands: 8,
        reinvites: 4,
        t1: Duration::from_millis(500),
        t2: Duration::from_secs(4),
        decision_timeout: Duration::from_secs(180),
    };
    Model::new(limits, "sip:ua@192.0.2.1".into(), Counter(0))
}

fn description() -> Description {
    Description::new(
        HeaderValue::from_static("application/sdp"),
        Bytes::from_static(b"v=0\r\n"),
    )
}

fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).expect("the harness picks valid codes")
}

/// The model, what the application holds, and what the runtime owes it.
struct Fuzzed {
    model: Model<Counter>,
    now: Instant,
    /// INVITEs the application has not decided.
    held: Vec<Authority>,
    /// Every INVITE the model took, which a CANCEL may name until the model
    /// lets go of it, as the core's transaction may outlive the decision.
    taken: Vec<ExchangeKey>,
    responses: Vec<ByeStarted>,
    /// Whether the runtime's jobs fail.
    failing: bool,
    /// How many dialogs the application was told were confirmed, which
    /// shows how far an input got.
    confirmed: usize,
}

impl Fuzzed {
    fn new() -> Fuzzed {
        Fuzzed {
            model: model(),
            now: Instant::now(),
            held: Vec::new(),
            taken: Vec::new(),
            responses: Vec::new(),
            failing: false,
            confirmed: 0,
        }
    }

    /// Takes in a request as the driver's `on_incoming` routes it.
    fn receive(&mut self, choice: u8, message: &[u8]) {
        let Ok(request) = Request::from_bytes(message) else {
            return;
        };
        let headers = request.headers();
        match *request.method() {
            Method::INVITE => {
                let body =
                    Body::read(headers, request.body(), DESCRIPTION_LIMIT);
                if let Ok(authority) =
                    self.model.receive_invite(&request, body, self.now)
                {
                    self.taken.push(authority.exchange());
                    self.decide(choice, authority);
                }
            }
            Method::ACK => {
                let answer = Body::description(
                    headers,
                    request.body(),
                    DESCRIPTION_LIMIT,
                );
                self.model.receive_ack_request(&request, answer);
            }
            // The core matches a CANCEL to the transaction of its INVITE,
            // which stands in here as one the model took.
            Method::CANCEL => {
                if !self.taken.is_empty() {
                    let index = usize::from(choice) % self.taken.len();
                    self.model.receive_cancel(self.taken[index]);
                }
            }
            // As `on_other`, the model sees only a BYE or an OPTIONS with a
            // To tag, a well-formed To and no Require. The runtime answers
            // the rest itself.
            Method::BYE | Method::OPTIONS => {
                let _ = self.model.knows_dialog(&request);
                let checked = header::to(headers).and_then(|to| {
                    Ok((
                        to.tag.is_some(),
                        header::requires_extension(headers)?,
                    ))
                });
                if let Ok((true, false)) = checked {
                    let _ = self.model.receive_request(&request, flow());
                }
            }
            _ => {}
        }
    }

    /// Decides an INVITE as the application would, by `choice`.
    fn decide(&mut self, choice: u8, authority: Authority) {
        let command = match choice % 4 {
            0 => Command::Accept { authority, answer: description() },
            1 => Command::Reject { authority, status: status(486) },
            2 => {
                let exchange = authority.exchange();
                self.held.push(authority);
                Command::Provisional {
                    exchange,
                    status: status(180),
                    preview: None,
                }
            }
            _ => {
                self.held.push(authority);
                return;
            }
        };
        self.command(command);
        self.settle();
    }

    /// Decides the oldest INVITE held, or drops it, by `choice`.
    fn decide_held(&mut self, choice: u8) {
        if self.held.is_empty() {
            return;
        }
        let command = match (choice >> 3) % 4 {
            0 => return,
            1 => Command::Accept {
                authority: self.held.remove(0),
                answer: description(),
            },
            2 => Command::Reject {
                authority: self.held.remove(0),
                status: status(486),
            },
            _ => {
                let authority = self.held.remove(0);
                self.model.abandon(authority.exchange());
                self.settle();
                return;
            }
        };
        self.command(command);
        self.settle();
    }

    fn command(&mut self, command: Command) {
        match self.model.try_submit(command) {
            Ok(_) => self.model.run_commands(),
            Err(refused) => {
                if let Command::Accept { authority, .. }
                | Command::Reject { authority, .. } = refused.command
                {
                    self.held.push(authority);
                }
            }
        }
    }

    /// Lets time pass by `choice`, up to past the ACK deadline of 64 T1 and
    /// the decision timeout.
    fn pass(&mut self, choice: u8) {
        let seconds = [0, 0, 1, 2, 5, 33, 200, 300][usize::from(choice >> 5)];
        self.now += Duration::from_secs(seconds);
        self.model.fire_timers(self.now);
        self.settle();
    }

    /// Carries out the effects until there are none, each as the runtime
    /// does once its job ends.
    fn settle(&mut self) {
        for _ in 0..1_000 {
            let effects = self.model.take_effects();
            if effects.is_empty() && self.responses.is_empty() {
                return;
            }
            for effect in effects {
                self.apply(effect);
            }
            for bye in std::mem::take(&mut self.responses) {
                let answered =
                    if self.failing { Err(Error::Timeout) } else { Ok(()) };
                self.model.bye_answered(bye, answered);
            }
        }
        panic!("the effects never settled");
    }

    fn apply(&mut self, effect: Effect) {
        let now = self.now;
        let failing = self.failing;
        let model = &mut self.model;
        match effect {
            Effect::SubmitFinal { exchange, .. } if failing => {
                model.final_refused(exchange, false);
            }
            Effect::SubmitFinal { exchange, .. } => {
                model.final_committed(exchange, now);
            }
            Effect::SubmitProvisional {
                exchange,
                status,
                preview,
                operation,
                ..
            } => {
                let result = if failing {
                    Err(Error::AlreadyFinalized)
                } else {
                    Ok(())
                };
                model.provisional_done(
                    exchange, status, preview, operation, result, now,
                );
            }
            Effect::StartInvite { attempt } => {
                if model.take_invite(attempt).is_some() {
                    model.invite_started(attempt);
                }
            }
            Effect::StartReinvite { exchange } => {
                if model.take_reinvite(exchange).is_some() {
                    model.reinvite_started(exchange, Ok(()), now);
                }
            }
            Effect::PrepareAnswer { replay, .. } => {
                model.answer_prepared(replay, Some(description()));
            }
            Effect::SendAck { replay } => {
                let written = model.ack_request(replay).is_some() && !failing;
                model.ack_written(replay, written);
            }
            Effect::SendBye { replay } => {
                let _ = model.bye_request(replay);
                model.bye_done(replay);
            }
            Effect::SendSessionBye { usage } => {
                let started = match model.session_bye_request(usage) {
                    Ok(_) if failing => Err(Error::TransportFailure),
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                };
                if let Some(bye) = model.bye_started(usage, started) {
                    self.responses.push(bye);
                }
            }
            Effect::CancelInvite { operation, .. } => {
                model.cancel_done(operation, Ok(CancelResult::Sent));
            }
            Effect::OperationEnded { operation } => {
                let _ = model.take_outcome(operation);
            }
            Effect::Notify(Event::DialogConfirmed { .. }) => {
                self.confirmed += 1;
            }
            Effect::Resend2xx { .. }
            | Effect::ResendAck { .. }
            | Effect::AttemptEnded { .. }
            | Effect::Notify(_)
            | Effect::Released(_) => {}
        }
    }

    /// Shuts the UA down with a termination, drops the INVITEs held, as an
    /// application that goes away does, and lets time pass until the model
    /// is idle, which counts its timers too.
    fn terminate(&mut self) {
        self.model.shut_down(true);
        for authority in std::mem::take(&mut self.held) {
            self.model.abandon(authority.exchange());
        }
        self.settle();
        for _ in 0..64 {
            if self.model.is_idle() {
                return;
            }
            self.now += Duration::from_secs(300);
            self.model.fire_timers(self.now);
            self.settle();
        }
        panic!("the model never came to rest");
    }
}

/// The flow a request arrived on, which the model only passes on.
fn flow() -> Flow {
    Flow {
        transport: Transport::Udp,
        local: "192.0.2.1:5060".parse().expect("a literal address"),
        remote: "192.0.2.9:5060".parse().expect("a literal address"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVITE: &str = "\
INVITE sip:bob@biloxi.example.com SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK776asdhds
Max-Forwards: 70
To: Bob <sip:bob@biloxi.example.com>
From: <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 314159 INVITE
Contact: <sip:alice@192.0.2.1>
Content-Type: application/sdp
Content-Length: 5

v=0
";

    /// A request of the caller in the dialog the first INVITE formed. The
    /// UA's first To tag is the first number of its counting randomness.
    fn in_dialog(method: &str, cseq: u32) -> String {
        format!(
            "{method} sip:bob@192.0.2.4 SIP/2.0
Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bK-{cseq}
Max-Forwards: 70
To: Bob <sip:bob@biloxi.example.com>;tag=0000000000000001
From: <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: {cseq} {method}
Content-Length: 0

"
        )
    }

    fn record(choice: u8, text: &str) -> Vec<u8> {
        let bytes = text.replace('\n', "\r\n").into_bytes();
        let length = u16::try_from(bytes.len()).unwrap().to_be_bytes();
        [&[choice], &length[..], &bytes].concat()
    }

    /// The records of [`messages`] reach the model as the seeds of the
    /// fuzz target assume: an accepted INVITE forms a session, its ACK
    /// keeps it, and the BYE of its dialog ends it.
    #[test]
    fn records_reach_a_session_and_its_end() {
        let data = [
            record(0, INVITE),
            record(0, &in_dialog("ACK", 314159)),
            record(0, &in_dialog("BYE", 314160)),
        ]
        .concat();

        let mut fuzzed = Fuzzed::new();
        let mut rest = &data[..];
        while let [choice, high, low, after @ ..] = rest {
            let length = usize::from(u16::from_be_bytes([*high, *low]));
            let (message, after) = after.split_at(length);
            rest = after;
            fuzzed.receive(*choice, message);
            fuzzed.settle();
        }

        assert_eq!(fuzzed.confirmed, 1);
        assert!(fuzzed.model.is_idle(), "the BYE ended the session");
        messages(&data);
    }

    /// An INVITE held and accepted by a later record, a failing job, and a
    /// request the runtime answers itself all leave the model at rest.
    #[test]
    fn held_invites_and_failing_jobs_come_to_rest() {
        let data = [
            record(3, INVITE),
            record(0b1000 | 0b100, &in_dialog("INFO", 314160)),
            record(0b1_1000, &in_dialog("ACK", 314159)),
        ]
        .concat();

        messages(&data);
        headers(INVITE.replace('\n', "\r\n").as_bytes());
    }
}
