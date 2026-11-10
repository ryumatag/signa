/*!
SIP response status code types.

This module defines [`StatusCode`], a value type for SIP response codes.
*/

use std::{
    fmt,
    num::NonZeroU16,
    str::{self, FromStr},
};

use crate::message::error::InvalidStatusCode;

/// A SIP response status code.
///
/// This type stores only the numeric status code. The reason phrase from a SIP
/// status line is not part of this type.
///
/// # Range
///
/// This implementation currently supports SIP response codes in the range
/// `100..=699`. The first digit determines the response class.
///
/// RFC 3261 leaves some room for interpretation here. The ABNF allows an
/// `extension-code = 3DIGIT`, while the prose defines six response classes
/// (`1xx` through `6xx`). This type intentionally follows the six-class
/// interpretation for now so that classification helpers remain strictly
/// protocol-oriented.
///
/// If interoperability requirements become clearer later, this range can be
/// relaxed to accept additional three-digit extension codes without breaking
/// existing callers.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(NonZeroU16);

impl StatusCode {
    /// Converts a `u16` to a `StatusCode`.
    ///
    /// Only codes in the range `100..=699` are currently accepted.
    pub const fn from_u16(src: u16) -> Result<StatusCode, InvalidStatusCode> {
        if let MIN_CODE..=MAX_CODE = src {
            if let Some(code) = NonZeroU16::new(src) {
                return Ok(StatusCode(code));
            }
        }

        Err(InvalidStatusCode::new())
    }

    /// Converts a byte slice to a `StatusCode`.
    pub fn from_bytes(src: &[u8]) -> Result<StatusCode, InvalidStatusCode> {
        if src.len() != 3 {
            return Err(InvalidStatusCode::new());
        }

        let a = src[0].wrapping_sub(b'0') as u16;
        let b = src[1].wrapping_sub(b'0') as u16;
        let c = src[2].wrapping_sub(b'0') as u16;

        if a == 0 || a > 6 || b > 9 || c > 9 {
            return Err(InvalidStatusCode::new());
        }

        let status = (a * 100) + (b * 10) + c;
        NonZeroU16::new(status)
            .map(StatusCode)
            .ok_or_else(InvalidStatusCode::new)
    }

    /// Returns the `u16` representation of this `StatusCode`.
    pub const fn as_u16(&self) -> u16 {
        self.0.get()
    }

    /// Returns the status code as a three-digit string.
    pub fn as_str(&self) -> &str {
        let offset = (self.0.get() - MIN_CODE) as usize * 3;

        // SAFETY: `StatusCode` guarantees `MIN_CODE..=MAX_CODE` (enforced by
        // every constructor). The offset therefore ranges from 0 to
        // `(MAX_CODE - MIN_CODE) * 3`, and the type of `CODE_DIGITS` makes it
        // `CODE_COUNT * 3` bytes long, so the slice is in bounds. Every byte
        // in `CODE_DIGITS` is an ASCII digit, so the slice is valid UTF-8.
        unsafe { str::from_utf8_unchecked(&CODE_DIGITS[offset..offset + 3]) }
    }

    /// Returns the reason phrase registered for this code with IANA, if any.
    ///
    /// This is meant as a default when building a status-line. The reason
    /// phrase is for humans, and [RFC 3261 section 7.2] does not require a
    /// receiver to read it, so any text may be sent instead. Codes that are
    /// valid but not registered return `None`.
    ///
    /// # Example
    ///
    /// ```
    /// use signa_core::StatusCode;
    ///
    /// assert_eq!(StatusCode::RINGING.canonical_reason(), Some("Ringing"));
    /// assert_eq!(StatusCode::from_u16(299)?.canonical_reason(), None);
    /// # Ok::<(), signa_core::message::error::InvalidStatusCode>(())
    /// ```
    ///
    /// [RFC 3261 section 7.2]: https://www.rfc-editor.org/rfc/rfc3261#section-7.2
    pub const fn canonical_reason(&self) -> Option<&'static str> {
        canonical_reason(self.0.get())
    }

    /// Returns `true` if this is a final response, that is, not `1xx`.
    ///
    /// [RFC 3261 section 7.2] splits responses into provisional (`1xx`) and
    /// final (`2xx` to `6xx`). A request can receive any number of provisional
    /// responses before its final one.
    ///
    /// [RFC 3261 section 7.2]: https://www.rfc-editor.org/rfc/rfc3261#section-7.2
    pub const fn is_final(&self) -> bool {
        self.0.get() >= 200
    }

    /// Returns `true` if this is a provisional response.
    pub fn is_provisional(&self) -> bool {
        (100..200).contains(&self.0.get())
    }

    /// Returns `true` if this is a success response.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0.get())
    }

    /// Returns `true` if this is a redirection response.
    pub fn is_redirection(&self) -> bool {
        (300..400).contains(&self.0.get())
    }

    /// Returns `true` if this is a client error response.
    pub fn is_client_error(&self) -> bool {
        (400..500).contains(&self.0.get())
    }

    /// Returns `true` if this is a server error response.
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.0.get())
    }

    /// Returns `true` if this is a global failure response.
    pub fn is_global_failure(&self) -> bool {
        (600..700).contains(&self.0.get())
    }
}

impl fmt::Debug for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq<u16> for StatusCode {
    fn eq(&self, other: &u16) -> bool {
        self.as_u16() == *other
    }
}

impl PartialEq<StatusCode> for u16 {
    fn eq(&self, other: &StatusCode) -> bool {
        *self == other.as_u16()
    }
}

impl From<StatusCode> for u16 {
    fn from(status: StatusCode) -> u16 {
        status.as_u16()
    }
}

impl TryFrom<u16> for StatusCode {
    type Error = InvalidStatusCode;

    fn try_from(src: u16) -> Result<StatusCode, InvalidStatusCode> {
        StatusCode::from_u16(src)
    }
}

impl TryFrom<&[u8]> for StatusCode {
    type Error = InvalidStatusCode;

    fn try_from(src: &[u8]) -> Result<StatusCode, InvalidStatusCode> {
        StatusCode::from_bytes(src)
    }
}

impl TryFrom<&str> for StatusCode {
    type Error = InvalidStatusCode;

    fn try_from(src: &str) -> Result<StatusCode, InvalidStatusCode> {
        TryFrom::try_from(src.as_bytes())
    }
}

impl FromStr for StatusCode {
    type Err = InvalidStatusCode;

    fn from_str(src: &str) -> Result<StatusCode, InvalidStatusCode> {
        TryFrom::try_from(src)
    }
}

// Adapted from the `status_codes!` macro in the `http` crate. Each row also
// carries the reason phrase from the IANA registry, so the constants and
// `canonical_reason` come from one table and cannot drift.
macro_rules! status_codes {
    (
        $(
            $(#[$docs:meta])*
            ($num:literal, $konst:ident, $phrase:literal);
        )+
    ) => {
        impl StatusCode {
        $(
            $(#[$docs])*
            pub const $konst: StatusCode = match StatusCode::from_u16($num) {
                Ok(code) => code,
                Err(_) => panic!("status code constant out of range"),
            };
        )+
        }

        const fn canonical_reason(code: u16) -> Option<&'static str> {
            match code {
                $(
                    $num => Some($phrase),
                )+
                _ => None,
            }
        }

        #[cfg(test)]
        const REGISTERED: &[(StatusCode, &str)] = &[
            $(
                (StatusCode::$konst, $phrase),
            )+
        ];
    }
}

// This list follows the IANA SIP Response Codes registry. Core codes come
// from RFC 3261 and the rest from later RFCs.
// https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-7
status_codes! {
    /// 100 Trying ([RFC 3261, Section 21.1.1]).
    ///
    /// [RFC 3261, Section 21.1.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.1.1
    (100, TRYING, "Trying");
    /// 180 Ringing ([RFC 3261, Section 21.1.2]).
    ///
    /// [RFC 3261, Section 21.1.2]: https://www.rfc-editor.org/rfc/rfc3261#section-21.1.2
    (180, RINGING, "Ringing");
    /// 181 Call Is Being Forwarded ([RFC 3261, Section 21.1.3]).
    ///
    /// [RFC 3261, Section 21.1.3]: https://www.rfc-editor.org/rfc/rfc3261#section-21.1.3
    (181, CALL_IS_BEING_FORWARDED, "Call Is Being Forwarded");
    /// 182 Queued ([RFC 3261, Section 21.1.4]).
    ///
    /// [RFC 3261, Section 21.1.4]: https://www.rfc-editor.org/rfc/rfc3261#section-21.1.4
    (182, QUEUED, "Queued");
    /// 183 Session Progress ([RFC 3261, Section 21.1.5]).
    ///
    /// [RFC 3261, Section 21.1.5]: https://www.rfc-editor.org/rfc/rfc3261#section-21.1.5
    (183, SESSION_PROGRESS, "Session Progress");
    /// 199 Early Dialog Terminated ([RFC 6228]).
    ///
    /// [RFC 6228]: https://www.rfc-editor.org/rfc/rfc6228
    (199, EARLY_DIALOG_TERMINATED, "Early Dialog Terminated");
    /// 200 OK ([RFC 3261, Section 21.2.1]).
    ///
    /// [RFC 3261, Section 21.2.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.2.1
    (200, OK, "OK");
    /// 202 Accepted ([RFC 6665, Section 8.3.1]).
    ///
    /// [RFC 6665, Section 8.3.1]: https://www.rfc-editor.org/rfc/rfc6665#section-8.3.1
    (202, ACCEPTED, "Accepted");
    /// 204 No Notification ([RFC 5839]).
    ///
    /// [RFC 5839]: https://www.rfc-editor.org/rfc/rfc5839
    (204, NO_NOTIFICATION, "No Notification");
    /// 300 Multiple Choices ([RFC 3261, Section 21.3.1]).
    ///
    /// [RFC 3261, Section 21.3.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.3.1
    (300, MULTIPLE_CHOICES, "Multiple Choices");
    /// 301 Moved Permanently ([RFC 3261, Section 21.3.2]).
    ///
    /// [RFC 3261, Section 21.3.2]: https://www.rfc-editor.org/rfc/rfc3261#section-21.3.2
    (301, MOVED_PERMANENTLY, "Moved Permanently");
    /// 302 Moved Temporarily ([RFC 3261, Section 21.3.3]).
    ///
    /// [RFC 3261, Section 21.3.3]: https://www.rfc-editor.org/rfc/rfc3261#section-21.3.3
    (302, MOVED_TEMPORARILY, "Moved Temporarily");
    /// 305 Use Proxy ([RFC 3261, Section 21.3.4]).
    ///
    /// [RFC 3261, Section 21.3.4]: https://www.rfc-editor.org/rfc/rfc3261#section-21.3.4
    (305, USE_PROXY, "Use Proxy");
    /// 380 Alternative Service ([RFC 3261, Section 21.3.5]).
    ///
    /// [RFC 3261, Section 21.3.5]: https://www.rfc-editor.org/rfc/rfc3261#section-21.3.5
    (380, ALTERNATIVE_SERVICE, "Alternative Service");
    /// 400 Bad Request ([RFC 3261, Section 21.4.1]).
    ///
    /// [RFC 3261, Section 21.4.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.1
    (400, BAD_REQUEST, "Bad Request");
    /// 401 Unauthorized ([RFC 3261, Section 21.4.2]).
    ///
    /// [RFC 3261, Section 21.4.2]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.2
    (401, UNAUTHORIZED, "Unauthorized");
    /// 402 Payment Required ([RFC 3261, Section 21.4.3]).
    ///
    /// [RFC 3261, Section 21.4.3]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.3
    (402, PAYMENT_REQUIRED, "Payment Required");
    /// 403 Forbidden ([RFC 3261, Section 21.4.4]).
    ///
    /// [RFC 3261, Section 21.4.4]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.4
    (403, FORBIDDEN, "Forbidden");
    /// 404 Not Found ([RFC 3261, Section 21.4.5]).
    ///
    /// [RFC 3261, Section 21.4.5]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.5
    (404, NOT_FOUND, "Not Found");
    /// 405 Method Not Allowed ([RFC 3261, Section 21.4.6]).
    ///
    /// [RFC 3261, Section 21.4.6]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.6
    (405, METHOD_NOT_ALLOWED, "Method Not Allowed");
    /// 406 Not Acceptable ([RFC 3261, Section 21.4.7]).
    ///
    /// [RFC 3261, Section 21.4.7]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.7
    (406, NOT_ACCEPTABLE, "Not Acceptable");
    /// 407 Proxy Authentication Required ([RFC 3261, Section 21.4.8]).
    ///
    /// [RFC 3261, Section 21.4.8]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.8
    (407, PROXY_AUTHENTICATION_REQUIRED, "Proxy Authentication Required");
    /// 408 Request Timeout ([RFC 3261, Section 21.4.9]).
    ///
    /// [RFC 3261, Section 21.4.9]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.9
    (408, REQUEST_TIMEOUT, "Request Timeout");
    /// 410 Gone ([RFC 3261, Section 21.4.10]).
    ///
    /// [RFC 3261, Section 21.4.10]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.10
    (410, GONE, "Gone");
    /// 412 Conditional Request Failed ([RFC 3903]).
    ///
    /// [RFC 3903]: https://www.rfc-editor.org/rfc/rfc3903
    (412, CONDITIONAL_REQUEST_FAILED, "Conditional Request Failed");
    /// 413 Request Entity Too Large ([RFC 3261, Section 21.4.11]).
    ///
    /// [RFC 3261, Section 21.4.11]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.11
    (413, REQUEST_ENTITY_TOO_LARGE, "Request Entity Too Large");
    /// 414 Request-URI Too Long ([RFC 3261, Section 21.4.12]).
    ///
    /// [RFC 3261, Section 21.4.12]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.12
    (414, REQUEST_URI_TOO_LONG, "Request-URI Too Long");
    /// 415 Unsupported Media Type ([RFC 3261, Section 21.4.13]).
    ///
    /// [RFC 3261, Section 21.4.13]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.13
    (415, UNSUPPORTED_MEDIA_TYPE, "Unsupported Media Type");
    /// 416 Unsupported URI Scheme ([RFC 3261, Section 21.4.14]).
    ///
    /// [RFC 3261, Section 21.4.14]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.14
    (416, UNSUPPORTED_URI_SCHEME, "Unsupported URI Scheme");
    /// 417 Unknown Resource-Priority ([RFC 4412]).
    ///
    /// [RFC 4412]: https://www.rfc-editor.org/rfc/rfc4412
    (417, UNKNOWN_RESOURCE_PRIORITY, "Unknown Resource-Priority");
    /// 420 Bad Extension ([RFC 3261, Section 21.4.15]).
    ///
    /// [RFC 3261, Section 21.4.15]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.15
    (420, BAD_EXTENSION, "Bad Extension");
    /// 421 Extension Required ([RFC 3261, Section 21.4.16]).
    ///
    /// [RFC 3261, Section 21.4.16]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.16
    (421, EXTENSION_REQUIRED, "Extension Required");
    /// 422 Session Interval Too Small ([RFC 4028]).
    ///
    /// [RFC 4028]: https://www.rfc-editor.org/rfc/rfc4028
    (422, SESSION_INTERVAL_TOO_SMALL, "Session Interval Too Small");
    /// 423 Interval Too Brief ([RFC 3261, Section 21.4.17]).
    ///
    /// [RFC 3261, Section 21.4.17]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.17
    (423, INTERVAL_TOO_BRIEF, "Interval Too Brief");
    /// 424 Bad Location Information ([RFC 6442]).
    ///
    /// [RFC 6442]: https://www.rfc-editor.org/rfc/rfc6442
    (424, BAD_LOCATION_INFORMATION, "Bad Location Information");
    /// 425 Bad Alert Message ([RFC 8876]).
    ///
    /// [RFC 8876]: https://www.rfc-editor.org/rfc/rfc8876
    (425, BAD_ALERT_MESSAGE, "Bad Alert Message");
    /// 428 Use Identity Header ([RFC 8224]).
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (428, USE_IDENTITY_HEADER, "Use Identity Header");
    /// 429 Provide Referrer Identity ([RFC 3892]).
    ///
    /// [RFC 3892]: https://www.rfc-editor.org/rfc/rfc3892
    (429, PROVIDE_REFERRER_IDENTITY, "Provide Referrer Identity");
    /// 430 Flow Failed ([RFC 5626]).
    ///
    /// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
    (430, FLOW_FAILED, "Flow Failed");
    /// 433 Anonymity Disallowed ([RFC 5079]).
    ///
    /// [RFC 5079]: https://www.rfc-editor.org/rfc/rfc5079
    (433, ANONYMITY_DISALLOWED, "Anonymity Disallowed");
    /// 436 Bad Identity Info ([RFC 8224]).
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (436, BAD_IDENTITY_INFO, "Bad Identity Info");
    /// 437 Unsupported Credential ([RFC 8224]).
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (437, UNSUPPORTED_CREDENTIAL, "Unsupported Credential");
    /// 438 Invalid Identity Header ([RFC 8224]).
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (438, INVALID_IDENTITY_HEADER, "Invalid Identity Header");
    /// 439 First Hop Lacks Outbound Support ([RFC 5626]).
    ///
    /// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
    (439, FIRST_HOP_LACKS_OUTBOUND_SUPPORT, "First Hop Lacks Outbound Support");
    /// 440 Max-Breadth Exceeded ([RFC 5393]).
    ///
    /// [RFC 5393]: https://www.rfc-editor.org/rfc/rfc5393
    (440, MAX_BREADTH_EXCEEDED, "Max-Breadth Exceeded");
    /// 469 Bad Info Package ([RFC 6086]).
    ///
    /// [RFC 6086]: https://www.rfc-editor.org/rfc/rfc6086
    (469, BAD_INFO_PACKAGE, "Bad Info Package");
    /// 470 Consent Needed ([RFC 5360]).
    ///
    /// [RFC 5360]: https://www.rfc-editor.org/rfc/rfc5360
    (470, CONSENT_NEEDED, "Consent Needed");
    /// 480 Temporarily Unavailable ([RFC 3261, Section 21.4.18]).
    ///
    /// [RFC 3261, Section 21.4.18]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.18
    (480, TEMPORARILY_UNAVAILABLE, "Temporarily Unavailable");
    /// 481 Call/Transaction Does Not Exist ([RFC 3261, Section 21.4.19]).
    ///
    /// [RFC 3261, Section 21.4.19]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.19
    (481, CALL_OR_TRANSACTION_DOES_NOT_EXIST, "Call/Transaction Does Not Exist");
    /// 482 Loop Detected ([RFC 3261, Section 21.4.20]).
    ///
    /// [RFC 3261, Section 21.4.20]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.20
    (482, LOOP_DETECTED, "Loop Detected");
    /// 483 Too Many Hops ([RFC 3261, Section 21.4.21]).
    ///
    /// [RFC 3261, Section 21.4.21]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.21
    (483, TOO_MANY_HOPS, "Too Many Hops");
    /// 484 Address Incomplete ([RFC 3261, Section 21.4.22]).
    ///
    /// [RFC 3261, Section 21.4.22]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.22
    (484, ADDRESS_INCOMPLETE, "Address Incomplete");
    /// 485 Ambiguous ([RFC 3261, Section 21.4.23]).
    ///
    /// [RFC 3261, Section 21.4.23]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.23
    (485, AMBIGUOUS, "Ambiguous");
    /// 486 Busy Here ([RFC 3261, Section 21.4.24]).
    ///
    /// [RFC 3261, Section 21.4.24]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.24
    (486, BUSY_HERE, "Busy Here");
    /// 487 Request Terminated ([RFC 3261, Section 21.4.25]).
    ///
    /// [RFC 3261, Section 21.4.25]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.25
    (487, REQUEST_TERMINATED, "Request Terminated");
    /// 488 Not Acceptable Here ([RFC 3261, Section 21.4.26]).
    ///
    /// [RFC 3261, Section 21.4.26]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.26
    (488, NOT_ACCEPTABLE_HERE, "Not Acceptable Here");
    /// 489 Bad Event ([RFC 6665, Section 8.3.2]).
    ///
    /// [RFC 6665, Section 8.3.2]: https://www.rfc-editor.org/rfc/rfc6665#section-8.3.2
    (489, BAD_EVENT, "Bad Event");
    /// 491 Request Pending ([RFC 3261, Section 21.4.27]).
    ///
    /// [RFC 3261, Section 21.4.27]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.27
    (491, REQUEST_PENDING, "Request Pending");
    /// 493 Undecipherable ([RFC 3261, Section 21.4.28]).
    ///
    /// [RFC 3261, Section 21.4.28]: https://www.rfc-editor.org/rfc/rfc3261#section-21.4.28
    (493, UNDECIPHERABLE, "Undecipherable");
    /// 494 Security Agreement Required ([RFC 3329]).
    ///
    /// [RFC 3329]: https://www.rfc-editor.org/rfc/rfc3329
    (494, SECURITY_AGREEMENT_REQUIRED, "Security Agreement Required");
    /// 500 Server Internal Error ([RFC 3261, Section 21.5.1]).
    ///
    /// [RFC 3261, Section 21.5.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.1
    (500, SERVER_INTERNAL_ERROR, "Server Internal Error");
    /// 501 Not Implemented ([RFC 3261, Section 21.5.2]).
    ///
    /// [RFC 3261, Section 21.5.2]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.2
    (501, NOT_IMPLEMENTED, "Not Implemented");
    /// 502 Bad Gateway ([RFC 3261, Section 21.5.3]).
    ///
    /// [RFC 3261, Section 21.5.3]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.3
    (502, BAD_GATEWAY, "Bad Gateway");
    /// 503 Service Unavailable ([RFC 3261, Section 21.5.4]).
    ///
    /// [RFC 3261, Section 21.5.4]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.4
    (503, SERVICE_UNAVAILABLE, "Service Unavailable");
    /// 504 Server Time-out ([RFC 3261, Section 21.5.5]).
    ///
    /// [RFC 3261, Section 21.5.5]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.5
    (504, SERVER_TIME_OUT, "Server Time-out");
    /// 505 Version Not Supported ([RFC 3261, Section 21.5.6]).
    ///
    /// [RFC 3261, Section 21.5.6]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.6
    (505, VERSION_NOT_SUPPORTED, "Version Not Supported");
    /// 513 Message Too Large ([RFC 3261, Section 21.5.7]).
    ///
    /// [RFC 3261, Section 21.5.7]: https://www.rfc-editor.org/rfc/rfc3261#section-21.5.7
    (513, MESSAGE_TOO_LARGE, "Message Too Large");
    /// 555 Push Notification Service Not Supported ([RFC 8599]).
    ///
    /// [RFC 8599]: https://www.rfc-editor.org/rfc/rfc8599
    (555, PUSH_NOTIFICATION_SERVICE_NOT_SUPPORTED, "Push Notification Service Not Supported");
    /// 580 Precondition Failure ([RFC 3312]).
    ///
    /// [RFC 3312]: https://www.rfc-editor.org/rfc/rfc3312
    (580, PRECONDITION_FAILURE, "Precondition Failure");
    /// 600 Busy Everywhere ([RFC 3261, Section 21.6.1]).
    ///
    /// [RFC 3261, Section 21.6.1]: https://www.rfc-editor.org/rfc/rfc3261#section-21.6.1
    (600, BUSY_EVERYWHERE, "Busy Everywhere");
    /// 603 Decline ([RFC 3261, Section 21.6.2]).
    ///
    /// [RFC 3261, Section 21.6.2]: https://www.rfc-editor.org/rfc/rfc3261#section-21.6.2
    (603, DECLINE, "Decline");
    /// 604 Does Not Exist Anywhere ([RFC 3261, Section 21.6.3]).
    ///
    /// [RFC 3261, Section 21.6.3]: https://www.rfc-editor.org/rfc/rfc3261#section-21.6.3
    (604, DOES_NOT_EXIST_ANYWHERE, "Does Not Exist Anywhere");
    /// 606 Not Acceptable ([RFC 3261, Section 21.6.4]).
    ///
    /// [RFC 3261, Section 21.6.4]: https://www.rfc-editor.org/rfc/rfc3261#section-21.6.4
    (606, GLOBAL_NOT_ACCEPTABLE, "Not Acceptable");
    /// 607 Unwanted ([RFC 8197]).
    ///
    /// [RFC 8197]: https://www.rfc-editor.org/rfc/rfc8197
    (607, UNWANTED, "Unwanted");
    /// 608 Rejected ([RFC 8688]).
    ///
    /// [RFC 8688]: https://www.rfc-editor.org/rfc/rfc8688
    (608, REJECTED, "Rejected");
}

/// Lowest accepted status code value.
const MIN_CODE: u16 = 100;

/// Highest accepted status code value.
const MAX_CODE: u16 = 699;

/// Number of distinct codes in `MIN_CODE..=MAX_CODE`.
const CODE_COUNT: usize = (MAX_CODE - MIN_CODE + 1) as usize;

/// Pre-computed ASCII digit triples for every code in `MIN_CODE..=MAX_CODE`.
const CODE_DIGITS: [u8; CODE_COUNT * 3] = {
    let mut digits = [0; CODE_COUNT * 3];
    let mut code = MIN_CODE;
    let mut offset = 0;

    while code <= MAX_CODE {
        digits[offset] = b'0' + (code / 100) as u8;
        digits[offset + 1] = b'0' + ((code / 10) % 10) as u8;
        digits[offset + 2] = b'0' + (code % 10) as u8;
        code += 1;
        offset += 3;
    }

    digits
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u16_accepts_range_boundaries() {
        assert!(StatusCode::from_u16(100).is_ok());
        assert!(StatusCode::from_u16(699).is_ok());
    }

    #[test]
    fn from_u16_rejects_out_of_range() {
        assert!(StatusCode::from_u16(0).is_err());
        assert!(StatusCode::from_u16(99).is_err());
        assert!(StatusCode::from_u16(700).is_err());
        assert!(StatusCode::from_u16(u16::MAX).is_err());
    }

    #[test]
    fn from_bytes_accepts_valid_three_digits() {
        let s = StatusCode::from_bytes(b"200").unwrap();
        assert_eq!(s.as_u16(), 200);
        assert_eq!(s.as_str(), "200");
    }

    #[test]
    fn from_bytes_rejects_invalid_length() {
        assert!(StatusCode::from_bytes(b"").is_err());
        assert!(StatusCode::from_bytes(b"20").is_err());
        assert!(StatusCode::from_bytes(b"2000").is_err());
    }

    #[test]
    fn from_bytes_rejects_non_digits() {
        assert!(StatusCode::from_bytes(b"2a0").is_err());
        assert!(StatusCode::from_bytes(b" 20").is_err());
        assert!(StatusCode::from_bytes(b"+20").is_err());
        assert!(StatusCode::from_bytes(b"20\n").is_err());
    }

    #[test]
    fn from_bytes_rejects_out_of_supported_classes() {
        assert!(StatusCode::from_bytes(b"000").is_err());
        assert!(StatusCode::from_bytes(b"099").is_err());
        assert!(StatusCode::from_bytes(b"700").is_err());
        assert!(StatusCode::from_bytes(b"999").is_err());
    }

    #[test]
    fn classification_boundaries() {
        assert!(StatusCode::from_u16(100).unwrap().is_provisional());
        assert!(StatusCode::from_u16(199).unwrap().is_provisional());
        assert!(StatusCode::from_u16(200).unwrap().is_success());
        assert!(StatusCode::from_u16(299).unwrap().is_success());
        assert!(StatusCode::from_u16(300).unwrap().is_redirection());
        assert!(StatusCode::from_u16(399).unwrap().is_redirection());
        assert!(StatusCode::from_u16(400).unwrap().is_client_error());
        assert!(StatusCode::from_u16(499).unwrap().is_client_error());
        assert!(StatusCode::from_u16(500).unwrap().is_server_error());
        assert!(StatusCode::from_u16(599).unwrap().is_server_error());
        assert!(StatusCode::from_u16(600).unwrap().is_global_failure());
        assert!(StatusCode::from_u16(699).unwrap().is_global_failure());
    }

    #[test]
    fn is_final_is_everything_but_1xx() {
        assert!(!StatusCode::TRYING.is_final());
        assert!(!StatusCode::from_u16(199).unwrap().is_final());
        assert!(StatusCode::OK.is_final());
        assert!(StatusCode::from_u16(699).unwrap().is_final());

        for code in 100..=699 {
            let status = StatusCode::from_u16(code).unwrap();
            assert_eq!(status.is_final(), !status.is_provisional());
        }
    }

    #[test]
    fn canonical_reason_covers_every_constant() {
        for &(status, phrase) in REGISTERED {
            assert_eq!(status.canonical_reason(), Some(phrase));
        }
    }

    #[test]
    fn canonical_reason_of_unregistered_codes() {
        assert_eq!(
            StatusCode::from_u16(299).unwrap().canonical_reason(),
            None
        );
        assert_eq!(
            StatusCode::from_u16(699).unwrap().canonical_reason(),
            None
        );
    }

    #[test]
    fn display_and_debug() {
        let s = StatusCode::from_u16(486).unwrap();
        assert_eq!(s.to_string(), "486");
        assert_eq!(format!("{s:?}"), "486");
    }

    #[test]
    fn eq() {
        let a = StatusCode::from_u16(200).unwrap();
        let b = StatusCode::from_bytes(b"200").unwrap();
        let c = StatusCode::from_str("200").unwrap();
        let d = StatusCode::try_from("200").unwrap();

        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(c, d);
        assert_eq!(200, a);
        assert_eq!(d, 200);
    }
}
