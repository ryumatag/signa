use std::{
    fmt,
    str::{self, FromStr},
};

use siparse::check;

use crate::message::{byte_str::ByteStr, error::InvalidHeaderName};

/// A SIP header field name.
///
/// This type models the semantic header name rather than its original wire
/// spelling. Parsing is case-insensitive, standard compact forms normalize to
/// their long-form standard headers, and custom header names are normalized to
/// lowercase.
///
/// # Equality
///
/// A `HeaderName` equals a string when [`HeaderName::from_bytes`] would read
/// the string as that name. The comparison ignores ASCII case, a compact form
/// equals its long form, and a string that is not a valid name equals nothing.
/// [`HeaderMap`](super::HeaderMap) looks up rows by string the same way.
///
/// # Example
///
/// ```
/// use signa_core::message::header::{HeaderName, VIA};
///
/// assert_eq!(VIA, "Via");
/// assert_eq!(VIA, "VIA");
/// assert_eq!(VIA, "v");
/// assert_ne!(VIA, "Via:");
///
/// let account = HeaderName::from_static("x-account-id");
/// assert_eq!(account, "X-Account-ID");
/// ```
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct HeaderName(Repr);

#[derive(Clone, Eq, Hash, PartialEq)]
enum Repr {
    Standard(StandardHeader),
    Custom(Custom),
}

/// A custom (non-standard) SIP header name backed by [`Bytes`](bytes::Bytes).
///
/// Invariant: the contained bytes are valid lowercase SIP token characters
/// (RFC 3261, Section 25.1) and therefore valid UTF-8.
#[derive(Clone, Eq, Hash, PartialEq)]
struct Custom(ByteStr);

impl Custom {
    fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[derive(Clone)]
struct TestHeader {
    canonical: &'static str,
    lower: &'static str,
    compact: Option<&'static str>,
    header: HeaderName,
}

macro_rules! standard_headers {
    (
        $(
            $(#[$docs:meta])*
            ($variant:ident, $konst:ident, $canonical:literal,
             $lower:literal $(, compact = $compact:literal)?);
        )+
    ) => {
        // Every name in the table must be a valid SIP token, and the lowercase
        // name must match the canonical one case-insensitively. Checking this
        // at compile time is what makes the `from_utf8_unchecked` calls below
        // sound, since token bytes are ASCII. `HeaderName::from_bytes` also
        // relies on every standard name fitting in its scratch buffer.
        const _: () = {
            $(
                assert!(check::header_name_const($canonical).is_ok());
                assert!(eq_lowercase_bytes($canonical, $lower));
                assert!($lower.len() <= SCRATCH_BUF_SIZE);
                $(assert!(check::header_name_const($compact).is_ok());)?
            )+
        };

        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        enum StandardHeader {
            $(
                $variant,
            )+
        }

        impl StandardHeader {
            // Matches against pre-lowercased input. Long-form names and
            // compact forms are unified in a single match so the compiler can
            // emit one optimized jump table.
            const fn from_bytes(src: &[u8]) -> Option<StandardHeader> {
                match src {
                    $(
                        $lower $(| $compact)? =>
                            Some(StandardHeader::$variant),
                    )+
                    _ => None,
                }
            }

            const fn from_bytes_case_insensitive(
                src: &[u8],
            ) -> Option<StandardHeader> {
                $(
                    if eq_lowercase_bytes(src, $lower)
                        $(|| eq_lowercase_bytes(src, $compact))?
                    {
                        return Some(StandardHeader::$variant);
                    }
                )+

                None
            }

            const fn as_str(self) -> &'static str {
                match self {
                    $(
                        // SAFETY: The table check above ensures `$canonical`
                        // is an ASCII token.
                        StandardHeader::$variant => unsafe {
                            std::str::from_utf8_unchecked($canonical)
                        },
                    )+
                }
            }

            const fn compact_form(self) -> Option<&'static str> {
                match self {
                    $(
                        StandardHeader::$variant =>
                            standard_headers!(@compact_option $($compact)?),
                    )+
                }
            }
        }

        pub(super) mod konst {
            use super::{HeaderName, Repr, StandardHeader};

            $(
                $(#[$docs])*
                pub const $konst: HeaderName =
                    HeaderName(Repr::Standard(StandardHeader::$variant));
            )+
        }

        #[cfg(test)]
        const TEST_HEADERS: &[TestHeader] = &[
            $(
                TestHeader {
                    // SAFETY: The table check above ensures both names are
                    // ASCII tokens.
                    canonical: unsafe {
                        std::str::from_utf8_unchecked($canonical)
                    },
                    // SAFETY: As above.
                    lower: unsafe {
                        std::str::from_utf8_unchecked($lower)
                    },
                    compact: standard_headers!(@compact_option $($compact)?),
                    header: HeaderName(Repr::Standard(StandardHeader::$variant)),
                },
            )+
        ];
    };
    (@compact_option) => { None };
    (@compact_option $compact:literal) => {
        // SAFETY: The table check in `standard_headers!` ensures `$compact`
        // is an ASCII token.
        Some(unsafe { std::str::from_utf8_unchecked($compact) })
    };
}

standard_headers! {
    /// The `Accept` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Accept, ACCEPT, b"Accept", b"accept");
    /// The `Accept-Contact` header field ([RFC 3841]).
    ///
    /// [RFC 3841]: https://www.rfc-editor.org/rfc/rfc3841
    (AcceptContact, ACCEPT_CONTACT, b"Accept-Contact", b"accept-contact", compact = b"a");
    /// The `Accept-Encoding` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (AcceptEncoding, ACCEPT_ENCODING, b"Accept-Encoding", b"accept-encoding");
    /// The `Accept-Language` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (AcceptLanguage, ACCEPT_LANGUAGE, b"Accept-Language", b"accept-language");
    /// The `Accept-Resource-Priority` header field ([RFC 4412]).
    ///
    /// [RFC 4412]: https://www.rfc-editor.org/rfc/rfc4412
    (AcceptResourcePriority, ACCEPT_RESOURCE_PRIORITY, b"Accept-Resource-Priority", b"accept-resource-priority");
    /// The `Additional-Identity` header field ([3GPP TS 24.229 v16.7.0]).
    ///
    /// [3GPP TS 24.229 v16.7.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (AdditionalIdentity, ADDITIONAL_IDENTITY, b"Additional-Identity", b"additional-identity");
    /// The `Alert-Info` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (AlertInfo, ALERT_INFO, b"Alert-Info", b"alert-info");
    /// The `AlertMsg-Error` header field ([RFC 8876]).
    ///
    /// [RFC 8876]: https://www.rfc-editor.org/rfc/rfc8876
    (AlertMsgError, ALERTMSG_ERROR, b"AlertMsg-Error", b"alertmsg-error");
    /// The `Allow` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Allow, ALLOW, b"Allow", b"allow");
    /// The `Allow-Events` header field ([RFC 6665]).
    ///
    /// [RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
    (AllowEvents, ALLOW_EVENTS, b"Allow-Events", b"allow-events", compact = b"u");
    /// The `Answer-Mode` header field ([RFC 5373]).
    ///
    /// [RFC 5373]: https://www.rfc-editor.org/rfc/rfc5373
    (AnswerMode, ANSWER_MODE, b"Answer-Mode", b"answer-mode");
    /// The `Attestation-Info` header field ([3GPP TS 24.229 v15.11.0]).
    ///
    /// [3GPP TS 24.229 v15.11.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (AttestationInfo, ATTESTATION_INFO, b"Attestation-Info", b"attestation-info");
    /// The `Authentication-Info` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (AuthenticationInfo, AUTHENTICATION_INFO, b"Authentication-Info", b"authentication-info");
    /// The `Authorization` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Authorization, AUTHORIZATION, b"Authorization", b"authorization");
    /// The `Call-ID` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (CallId, CALL_ID, b"Call-ID", b"call-id", compact = b"i");
    /// The `Call-Info` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (CallInfo, CALL_INFO, b"Call-Info", b"call-info");
    /// The `Cellular-Network-Info` header field ([3GPP TS 24.229 v13.9.0]).
    ///
    /// [3GPP TS 24.229 v13.9.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (CellularNetworkInfo, CELLULAR_NETWORK_INFO, b"Cellular-Network-Info", b"cellular-network-info");
    /// The `Contact` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Contact, CONTACT, b"Contact", b"contact", compact = b"m");
    /// The `Content-Disposition` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ContentDisposition, CONTENT_DISPOSITION, b"Content-Disposition", b"content-disposition");
    /// The `Content-Encoding` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ContentEncoding, CONTENT_ENCODING, b"Content-Encoding", b"content-encoding", compact = b"e");
    /// The `Content-ID` header field ([RFC 8262]).
    ///
    /// [RFC 8262]: https://www.rfc-editor.org/rfc/rfc8262
    (ContentId, CONTENT_ID, b"Content-ID", b"content-id");
    /// The `Content-Language` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ContentLanguage, CONTENT_LANGUAGE, b"Content-Language", b"content-language");
    /// The `Content-Length` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ContentLength, CONTENT_LENGTH, b"Content-Length", b"content-length", compact = b"l");
    /// The `Content-Type` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ContentType, CONTENT_TYPE, b"Content-Type", b"content-type", compact = b"c");
    /// The `CSeq` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Cseq, CSEQ, b"CSeq", b"cseq");
    /// The `Date` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Date, DATE, b"Date", b"date");
    /// The `DC-Info` header field ([3GPP TS 24.229 v19.4.1]).
    ///
    /// [3GPP TS 24.229 v19.4.1]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (DcInfo, DC_INFO, b"DC-Info", b"dc-info");
    /// The `Encryption` header field from RFC 2543, removed by [RFC 3261].
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Encryption, ENCRYPTION, b"Encryption", b"encryption");
    /// The `Error-Info` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ErrorInfo, ERROR_INFO, b"Error-Info", b"error-info");
    /// The `Event` header field ([RFC 6665] and [RFC 6446]).
    ///
    /// [RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
    /// [RFC 6446]: https://www.rfc-editor.org/rfc/rfc6446
    (Event, EVENT, b"Event", b"event", compact = b"o");
    /// The `Expires` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Expires, EXPIRES, b"Expires", b"expires");
    /// The `Feature-Caps` header field ([RFC 6809]).
    ///
    /// [RFC 6809]: https://www.rfc-editor.org/rfc/rfc6809
    (FeatureCaps, FEATURE_CAPS, b"Feature-Caps", b"feature-caps");
    /// The `Flow-Timer` header field ([RFC 5626]).
    ///
    /// [RFC 5626]: https://www.rfc-editor.org/rfc/rfc5626
    (FlowTimer, FLOW_TIMER, b"Flow-Timer", b"flow-timer");
    /// The `From` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (From, FROM, b"From", b"from", compact = b"f");
    /// The `Geolocation` header field ([RFC 6442]).
    ///
    /// [RFC 6442]: https://www.rfc-editor.org/rfc/rfc6442
    (Geolocation, GEOLOCATION, b"Geolocation", b"geolocation");
    /// The `Geolocation-Error` header field ([RFC 6442]).
    ///
    /// [RFC 6442]: https://www.rfc-editor.org/rfc/rfc6442
    (GeolocationError, GEOLOCATION_ERROR, b"Geolocation-Error", b"geolocation-error");
    /// The `Geolocation-Routing` header field ([RFC 6442]).
    ///
    /// [RFC 6442]: https://www.rfc-editor.org/rfc/rfc6442
    (GeolocationRouting, GEOLOCATION_ROUTING, b"Geolocation-Routing", b"geolocation-routing");
    /// The `Hide` header field from RFC 2543, removed by [RFC 3261].
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Hide, HIDE, b"Hide", b"hide");
    /// The `History-Info` header field ([RFC 7044]).
    ///
    /// [RFC 7044]: https://www.rfc-editor.org/rfc/rfc7044
    (HistoryInfo, HISTORY_INFO, b"History-Info", b"history-info");
    /// The `Identity` header field ([RFC 8224]).
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (Identity, IDENTITY, b"Identity", b"identity", compact = b"y");
    /// The `Identity-Info` header field, deprecated by [RFC 8224].
    ///
    /// [RFC 8224]: https://www.rfc-editor.org/rfc/rfc8224
    (IdentityInfo, IDENTITY_INFO, b"Identity-Info", b"identity-info");
    /// The `Info-Package` header field ([RFC 6086]).
    ///
    /// [RFC 6086]: https://www.rfc-editor.org/rfc/rfc6086
    (InfoPackage, INFO_PACKAGE, b"Info-Package", b"info-package");
    /// The `In-Reply-To` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (InReplyTo, IN_REPLY_TO, b"In-Reply-To", b"in-reply-to");
    /// The `Join` header field ([RFC 3911]).
    ///
    /// [RFC 3911]: https://www.rfc-editor.org/rfc/rfc3911
    (Join, JOIN, b"Join", b"join");
    /// The `Max-Breadth` header field ([RFC 5393]).
    ///
    /// [RFC 5393]: https://www.rfc-editor.org/rfc/rfc5393
    (MaxBreadth, MAX_BREADTH, b"Max-Breadth", b"max-breadth");
    /// The `Max-Forwards` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (MaxForwards, MAX_FORWARDS, b"Max-Forwards", b"max-forwards");
    /// The `MIME-Version` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (MimeVersion, MIME_VERSION, b"MIME-Version", b"mime-version");
    /// The `Min-Expires` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (MinExpires, MIN_EXPIRES, b"Min-Expires", b"min-expires");
    /// The `Min-SE` header field ([RFC 4028]).
    ///
    /// [RFC 4028]: https://www.rfc-editor.org/rfc/rfc4028
    (MinSe, MIN_SE, b"Min-SE", b"min-se");
    /// The `Organization` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Organization, ORGANIZATION, b"Organization", b"organization");
    /// The `Origination-Id` header field ([3GPP TS 24.229 v15.11.0]).
    ///
    /// [3GPP TS 24.229 v15.11.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (OriginationId, ORIGINATION_ID, b"Origination-Id", b"origination-id");
    /// The `P-Access-Network-Info` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PAccessNetworkInfo, P_ACCESS_NETWORK_INFO, b"P-Access-Network-Info", b"p-access-network-info");
    /// The `P-Answer-State` header field ([RFC 4964]).
    ///
    /// [RFC 4964]: https://www.rfc-editor.org/rfc/rfc4964
    (PAnswerState, P_ANSWER_STATE, b"P-Answer-State", b"p-answer-state");
    /// The `P-Asserted-Identity` header field ([RFC 3325]).
    ///
    /// [RFC 3325]: https://www.rfc-editor.org/rfc/rfc3325
    (PAssertedIdentity, P_ASSERTED_IDENTITY, b"P-Asserted-Identity", b"p-asserted-identity");
    /// The `P-Asserted-Service` header field ([RFC 6050]).
    ///
    /// [RFC 6050]: https://www.rfc-editor.org/rfc/rfc6050
    (PAssertedService, P_ASSERTED_SERVICE, b"P-Asserted-Service", b"p-asserted-service");
    /// The `P-Associated-URI` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PAssociatedUri, P_ASSOCIATED_URI, b"P-Associated-URI", b"p-associated-uri");
    /// The `P-Called-Party-ID` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PCalledPartyId, P_CALLED_PARTY_ID, b"P-Called-Party-ID", b"p-called-party-id");
    /// The `P-Charge-Info` header field ([RFC 8496]).
    ///
    /// [RFC 8496]: https://www.rfc-editor.org/rfc/rfc8496
    (PChargeInfo, P_CHARGE_INFO, b"P-Charge-Info", b"p-charge-info");
    /// The `P-Charging-Function-Addresses` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PChargingFunctionAddresses, P_CHARGING_FUNCTION_ADDRESSES, b"P-Charging-Function-Addresses", b"p-charging-function-addresses");
    /// The `P-Charging-Vector` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PChargingVector, P_CHARGING_VECTOR, b"P-Charging-Vector", b"p-charging-vector");
    /// The `P-DCS-Trace-Party-ID` header field ([RFC 5503]).
    ///
    /// [RFC 5503]: https://www.rfc-editor.org/rfc/rfc5503
    (PDcsTracePartyId, P_DCS_TRACE_PARTY_ID, b"P-DCS-Trace-Party-ID", b"p-dcs-trace-party-id");
    /// The `P-DCS-OSPS` header field ([RFC 5503]).
    ///
    /// [RFC 5503]: https://www.rfc-editor.org/rfc/rfc5503
    (PDcsOsps, P_DCS_OSPS, b"P-DCS-OSPS", b"p-dcs-osps");
    /// The `P-DCS-Billing-Info` header field ([RFC 5503]).
    ///
    /// [RFC 5503]: https://www.rfc-editor.org/rfc/rfc5503
    (PDcsBillingInfo, P_DCS_BILLING_INFO, b"P-DCS-Billing-Info", b"p-dcs-billing-info");
    /// The `P-DCS-LAES` header field ([RFC 5503]).
    ///
    /// [RFC 5503]: https://www.rfc-editor.org/rfc/rfc5503
    (PDcsLaes, P_DCS_LAES, b"P-DCS-LAES", b"p-dcs-laes");
    /// The `P-DCS-Redirect` header field ([RFC 5503]).
    ///
    /// [RFC 5503]: https://www.rfc-editor.org/rfc/rfc5503
    (PDcsRedirect, P_DCS_REDIRECT, b"P-DCS-Redirect", b"p-dcs-redirect");
    /// The `P-Early-Media` header field ([RFC 5009]).
    ///
    /// [RFC 5009]: https://www.rfc-editor.org/rfc/rfc5009
    (PEarlyMedia, P_EARLY_MEDIA, b"P-Early-Media", b"p-early-media");
    /// The `P-Media-Authorization` header field ([RFC 3313]).
    ///
    /// [RFC 3313]: https://www.rfc-editor.org/rfc/rfc3313
    (PMediaAuthorization, P_MEDIA_AUTHORIZATION, b"P-Media-Authorization", b"p-media-authorization");
    /// The `P-Preferred-Identity` header field ([RFC 3325]).
    ///
    /// [RFC 3325]: https://www.rfc-editor.org/rfc/rfc3325
    (PPreferredIdentity, P_PREFERRED_IDENTITY, b"P-Preferred-Identity", b"p-preferred-identity");
    /// The `P-Preferred-Service` header field ([RFC 6050]).
    ///
    /// [RFC 6050]: https://www.rfc-editor.org/rfc/rfc6050
    (PPreferredService, P_PREFERRED_SERVICE, b"P-Preferred-Service", b"p-preferred-service");
    /// The `P-Private-Network-Indication` header field ([RFC 7316]).
    ///
    /// [RFC 7316]: https://www.rfc-editor.org/rfc/rfc7316
    (PPrivateNetworkIndication, P_PRIVATE_NETWORK_INDICATION, b"P-Private-Network-Indication", b"p-private-network-indication");
    /// The `P-Profile-Key` header field ([RFC 5002]).
    ///
    /// [RFC 5002]: https://www.rfc-editor.org/rfc/rfc5002
    (PProfileKey, P_PROFILE_KEY, b"P-Profile-Key", b"p-profile-key");
    /// The `P-Refused-URI-List` header field ([RFC 5318]).
    ///
    /// [RFC 5318]: https://www.rfc-editor.org/rfc/rfc5318
    (PRefusedUriList, P_REFUSED_URI_LIST, b"P-Refused-URI-List", b"p-refused-uri-list");
    /// The `P-Served-User` header field ([RFC 5502] and [RFC 8498]).
    ///
    /// [RFC 5502]: https://www.rfc-editor.org/rfc/rfc5502
    /// [RFC 8498]: https://www.rfc-editor.org/rfc/rfc8498
    (PServedUser, P_SERVED_USER, b"P-Served-User", b"p-served-user");
    /// The `P-User-Database` header field ([RFC 4457]).
    ///
    /// [RFC 4457]: https://www.rfc-editor.org/rfc/rfc4457
    (PUserDatabase, P_USER_DATABASE, b"P-User-Database", b"p-user-database");
    /// The `P-Visited-Network-ID` header field ([RFC 7315]).
    ///
    /// [RFC 7315]: https://www.rfc-editor.org/rfc/rfc7315
    (PVisitedNetworkId, P_VISITED_NETWORK_ID, b"P-Visited-Network-ID", b"p-visited-network-id");
    /// The `Path` header field ([RFC 3327]).
    ///
    /// [RFC 3327]: https://www.rfc-editor.org/rfc/rfc3327
    (Path, PATH, b"Path", b"path");
    /// The `Permission-Missing` header field ([RFC 5360]).
    ///
    /// [RFC 5360]: https://www.rfc-editor.org/rfc/rfc5360
    (PermissionMissing, PERMISSION_MISSING, b"Permission-Missing", b"permission-missing");
    /// The `Policy-Contact` header field ([RFC 6794]).
    ///
    /// [RFC 6794]: https://www.rfc-editor.org/rfc/rfc6794
    (PolicyContact, POLICY_CONTACT, b"Policy-Contact", b"policy-contact");
    /// The `Policy-ID` header field ([RFC 6794]).
    ///
    /// [RFC 6794]: https://www.rfc-editor.org/rfc/rfc6794
    (PolicyId, POLICY_ID, b"Policy-ID", b"policy-id");
    /// The `Priority` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Priority, PRIORITY, b"Priority", b"priority");
    /// The `Priority-Share` header field ([3GPP TS 24.229 v13.16.0]).
    ///
    /// [3GPP TS 24.229 v13.16.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (PriorityShare, PRIORITY_SHARE, b"Priority-Share", b"priority-share");
    /// The `Priority-Verstat` header field ([3GPP TS 24.229]).
    ///
    /// [3GPP TS 24.229]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (PriorityVerstat, PRIORITY_VERSTAT, b"Priority-Verstat", b"priority-verstat");
    /// The `Priv-Answer-Mode` header field ([RFC 5373]).
    ///
    /// [RFC 5373]: https://www.rfc-editor.org/rfc/rfc5373
    (PrivAnswerMode, PRIV_ANSWER_MODE, b"Priv-Answer-Mode", b"priv-answer-mode");
    /// The `Privacy` header field ([RFC 3323]).
    ///
    /// [RFC 3323]: https://www.rfc-editor.org/rfc/rfc3323
    (Privacy, PRIVACY, b"Privacy", b"privacy");
    /// The `Proxy-Authenticate` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ProxyAuthenticate, PROXY_AUTHENTICATE, b"Proxy-Authenticate", b"proxy-authenticate");
    /// The `Proxy-Authorization` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ProxyAuthorization, PROXY_AUTHORIZATION, b"Proxy-Authorization", b"proxy-authorization");
    /// The `Proxy-Require` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ProxyRequire, PROXY_REQUIRE, b"Proxy-Require", b"proxy-require");
    /// The `RAck` header field ([RFC 3262]).
    ///
    /// [RFC 3262]: https://www.rfc-editor.org/rfc/rfc3262
    (Rack, RACK, b"RAck", b"rack");
    /// The `Reason` header field ([RFC 3326]).
    ///
    /// [RFC 3326]: https://www.rfc-editor.org/rfc/rfc3326
    (Reason, REASON, b"Reason", b"reason");
    /// The `Record-Route` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (RecordRoute, RECORD_ROUTE, b"Record-Route", b"record-route");
    /// The `Recv-Info` header field ([RFC 6086]).
    ///
    /// [RFC 6086]: https://www.rfc-editor.org/rfc/rfc6086
    (RecvInfo, RECV_INFO, b"Recv-Info", b"recv-info");
    /// The `Refer-Events-At` header field ([RFC 7614]).
    ///
    /// [RFC 7614]: https://www.rfc-editor.org/rfc/rfc7614
    (ReferEventsAt, REFER_EVENTS_AT, b"Refer-Events-At", b"refer-events-at");
    /// The `Refer-Sub` header field ([RFC 4488]).
    ///
    /// [RFC 4488]: https://www.rfc-editor.org/rfc/rfc4488
    (ReferSub, REFER_SUB, b"Refer-Sub", b"refer-sub");
    /// The `Refer-To` header field ([RFC 3515]).
    ///
    /// [RFC 3515]: https://www.rfc-editor.org/rfc/rfc3515
    (ReferTo, REFER_TO, b"Refer-To", b"refer-to", compact = b"r");
    /// The `Referred-By` header field ([RFC 3892]).
    ///
    /// [RFC 3892]: https://www.rfc-editor.org/rfc/rfc3892
    (ReferredBy, REFERRED_BY, b"Referred-By", b"referred-by", compact = b"b");
    /// The `Reject-Contact` header field ([RFC 3841]).
    ///
    /// [RFC 3841]: https://www.rfc-editor.org/rfc/rfc3841
    (RejectContact, REJECT_CONTACT, b"Reject-Contact", b"reject-contact", compact = b"j");
    /// The `Relayed-Charge` header field ([3GPP TS 24.229 v12.14.0]).
    ///
    /// [3GPP TS 24.229 v12.14.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (RelayedCharge, RELAYED_CHARGE, b"Relayed-Charge", b"relayed-charge");
    /// The `Replaces` header field ([RFC 3891]).
    ///
    /// [RFC 3891]: https://www.rfc-editor.org/rfc/rfc3891
    (Replaces, REPLACES, b"Replaces", b"replaces");
    /// The `Reply-To` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ReplyTo, REPLY_TO, b"Reply-To", b"reply-to");
    /// The `Request-Disposition` header field ([RFC 3841]).
    ///
    /// [RFC 3841]: https://www.rfc-editor.org/rfc/rfc3841
    (RequestDisposition, REQUEST_DISPOSITION, b"Request-Disposition", b"request-disposition", compact = b"d");
    /// The `Require` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Require, REQUIRE, b"Require", b"require");
    /// The `Resource-Priority` header field ([RFC 4412]).
    ///
    /// [RFC 4412]: https://www.rfc-editor.org/rfc/rfc4412
    (ResourcePriority, RESOURCE_PRIORITY, b"Resource-Priority", b"resource-priority");
    /// The `Resource-Share` header field ([3GPP TS 24.229 v13.7.0]).
    ///
    /// [3GPP TS 24.229 v13.7.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (ResourceShare, RESOURCE_SHARE, b"Resource-Share", b"resource-share");
    /// The `Response-Key` header field from RFC 2543, removed by [RFC 3261].
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (ResponseKey, RESPONSE_KEY, b"Response-Key", b"response-key");
    /// The `Response-Source` header field ([3GPP TS 24.229 v15.11.0]).
    ///
    /// [3GPP TS 24.229 v15.11.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (ResponseSource, RESPONSE_SOURCE, b"Response-Source", b"response-source");
    /// The `Restoration-Info` header field ([3GPP TS 24.229 v12.14.0]).
    ///
    /// [3GPP TS 24.229 v12.14.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (RestorationInfo, RESTORATION_INFO, b"Restoration-Info", b"restoration-info");
    /// The `Retry-After` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (RetryAfter, RETRY_AFTER, b"Retry-After", b"retry-after");
    /// The `Route` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Route, ROUTE, b"Route", b"route");
    /// The `RSeq` header field ([RFC 3262]).
    ///
    /// [RFC 3262]: https://www.rfc-editor.org/rfc/rfc3262
    (Rseq, RSEQ, b"RSeq", b"rseq");
    /// The `Security-Client` header field ([RFC 3329]).
    ///
    /// [RFC 3329]: https://www.rfc-editor.org/rfc/rfc3329
    (SecurityClient, SECURITY_CLIENT, b"Security-Client", b"security-client");
    /// The `Security-Server` header field ([RFC 3329]).
    ///
    /// [RFC 3329]: https://www.rfc-editor.org/rfc/rfc3329
    (SecurityServer, SECURITY_SERVER, b"Security-Server", b"security-server");
    /// The `Security-Verify` header field ([RFC 3329]).
    ///
    /// [RFC 3329]: https://www.rfc-editor.org/rfc/rfc3329
    (SecurityVerify, SECURITY_VERIFY, b"Security-Verify", b"security-verify");
    /// The `Server` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Server, SERVER, b"Server", b"server");
    /// The `Service-Interact-Info` header field ([3GPP TS 24.229 v13.18.0]).
    ///
    /// [3GPP TS 24.229 v13.18.0]: https://www.3gpp.org/ftp/Specs/archive/24_series/24.229/
    (ServiceInteractInfo, SERVICE_INTERACT_INFO, b"Service-Interact-Info", b"service-interact-info");
    /// The `Service-Route` header field ([RFC 3608]).
    ///
    /// [RFC 3608]: https://www.rfc-editor.org/rfc/rfc3608
    (ServiceRoute, SERVICE_ROUTE, b"Service-Route", b"service-route");
    /// The `Session-Expires` header field ([RFC 4028]).
    ///
    /// [RFC 4028]: https://www.rfc-editor.org/rfc/rfc4028
    (SessionExpires, SESSION_EXPIRES, b"Session-Expires", b"session-expires", compact = b"x");
    /// The `Session-ID` header field ([RFC 7989]).
    ///
    /// [RFC 7989]: https://www.rfc-editor.org/rfc/rfc7989
    (SessionId, SESSION_ID, b"Session-ID", b"session-id");
    /// The `SIP-ETag` header field ([RFC 3903]).
    ///
    /// [RFC 3903]: https://www.rfc-editor.org/rfc/rfc3903
    (SipEtag, SIP_ETAG, b"SIP-ETag", b"sip-etag");
    /// The `SIP-If-Match` header field ([RFC 3903]).
    ///
    /// [RFC 3903]: https://www.rfc-editor.org/rfc/rfc3903
    (SipIfMatch, SIP_IF_MATCH, b"SIP-If-Match", b"sip-if-match");
    /// The `Subject` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Subject, SUBJECT, b"Subject", b"subject", compact = b"s");
    /// The `Subscription-State` header field ([RFC 6665]).
    ///
    /// [RFC 6665]: https://www.rfc-editor.org/rfc/rfc6665
    (SubscriptionState, SUBSCRIPTION_STATE, b"Subscription-State", b"subscription-state");
    /// The `Supported` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Supported, SUPPORTED, b"Supported", b"supported", compact = b"k");
    /// The `Suppress-If-Match` header field ([RFC 5839]).
    ///
    /// [RFC 5839]: https://www.rfc-editor.org/rfc/rfc5839
    (SuppressIfMatch, SUPPRESS_IF_MATCH, b"Suppress-If-Match", b"suppress-if-match");
    /// The `Target-Dialog` header field ([RFC 4538]).
    ///
    /// [RFC 4538]: https://www.rfc-editor.org/rfc/rfc4538
    (TargetDialog, TARGET_DIALOG, b"Target-Dialog", b"target-dialog");
    /// The `Timestamp` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Timestamp, TIMESTAMP, b"Timestamp", b"timestamp");
    /// The `To` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (To, TO, b"To", b"to", compact = b"t");
    /// The `Trigger-Consent` header field ([RFC 5360]).
    ///
    /// [RFC 5360]: https://www.rfc-editor.org/rfc/rfc5360
    (TriggerConsent, TRIGGER_CONSENT, b"Trigger-Consent", b"trigger-consent");
    /// The `Unsupported` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Unsupported, UNSUPPORTED, b"Unsupported", b"unsupported");
    /// The `User-Agent` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (UserAgent, USER_AGENT, b"User-Agent", b"user-agent");
    /// The `User-to-User` header field ([RFC 7433]).
    ///
    /// [RFC 7433]: https://www.rfc-editor.org/rfc/rfc7433
    (UserToUser, USER_TO_USER, b"User-to-User", b"user-to-user");
    /// The `Via` header field ([RFC 3261] and [RFC 7118]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    /// [RFC 7118]: https://www.rfc-editor.org/rfc/rfc7118
    (Via, VIA, b"Via", b"via", compact = b"v");
    /// The `Warning` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (Warning, WARNING, b"Warning", b"warning");
    /// The `WWW-Authenticate` header field ([RFC 3261]).
    ///
    /// [RFC 3261]: https://www.rfc-editor.org/rfc/rfc3261
    (WwwAuthenticate, WWW_AUTHENTICATE, b"WWW-Authenticate", b"www-authenticate");
}

impl HeaderName {
    /// Creates a new `HeaderName` from a static string.
    ///
    /// This constructor is intended for compile-time constants. Standard SIP
    /// header names and compact forms are recognized without allocation.
    ///
    /// Custom header names must already be lowercase-normalized. Unlike
    /// [`HeaderName::from_bytes`], this constructor does not allocate in order
    /// to lowercase custom names at runtime.
    ///
    /// # Panics
    ///
    /// Panics if `src` is not a valid SIP header field name, or if it is a
    /// custom header name that is not already lowercase-normalized.
    pub const fn from_static(src: &'static str) -> HeaderName {
        let bytes = src.as_bytes();

        if check::header_name_const(bytes).is_err() {
            panic!("invalid SIP header field name");
        }

        if let Some(standard) =
            StandardHeader::from_bytes_case_insensitive(bytes)
        {
            return HeaderName(Repr::Standard(standard));
        }

        // A custom name is stored as given, so it must already be in the
        // lowercase form that `from_bytes` would produce.
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].to_ascii_lowercase() != bytes[i] {
                panic!(
                    "custom SIP header field names in from_static() must \
                     already be lowercase"
                );
            }
            i += 1;
        }

        HeaderName(Repr::Custom(Custom(ByteStr::from_static(src))))
    }

    /// Converts a byte slice to a `HeaderName`.
    ///
    /// Standard header names and compact forms are recognized
    /// case-insensitively. Custom header names are normalized to lowercase.
    pub fn from_bytes(src: &[u8]) -> Result<HeaderName, InvalidHeaderName> {
        // Every standard name and compact form is a valid `token`, so a match
        // needs no separate check. Most names in practice are standard.
        if let Some(standard) = StandardHeader::from_any_case(src) {
            return Ok(HeaderName(Repr::Standard(standard)));
        }

        let name =
            check::header_name(src).map_err(|_| InvalidHeaderName::new())?;
        Ok(HeaderName::custom(name))
    }

    /// Creates a `HeaderName` from a name that siparse parsed, without
    /// checking it again.
    pub(crate) fn from_parsed(name: &str) -> HeaderName {
        debug_assert!(check::header_name(name.as_bytes()).is_ok());

        match StandardHeader::from_any_case(name.as_bytes()) {
            Some(standard) => HeaderName(Repr::Standard(standard)),
            None => HeaderName::custom(name),
        }
    }

    /// Returns a custom name for a `token`, lowercased.
    fn custom(token: &str) -> HeaderName {
        HeaderName(Repr::Custom(Custom(ByteStr::from(
            token.to_ascii_lowercase(),
        ))))
    }

    /// Returns the canonical SIP header field name.
    ///
    /// Standard headers are rendered in their long form. Custom names are
    /// rendered in normalized lowercase.
    pub fn as_str(&self) -> &str {
        match self.0 {
            Repr::Standard(standard) => standard.as_str(),
            Repr::Custom(ref custom) => custom.as_str(),
        }
    }

    /// Returns the compact form for this header field, if one exists.
    pub fn compact_form(&self) -> Option<&'static str> {
        match self.0 {
            Repr::Standard(standard) => standard.compact_form(),
            Repr::Custom(_) => None,
        }
    }

    /// Returns whether `from_bytes` would read `src` as this name, without
    /// building one.
    ///
    /// A custom name is a lowercase token that no standard name or compact
    /// form matches, so a string that equals it ignoring case reads back as
    /// the same custom name. A standard name can be spelled only as its long
    /// or compact form.
    fn eq_str(&self, src: &str) -> bool {
        match self.0 {
            Repr::Standard(standard) => {
                src.eq_ignore_ascii_case(standard.as_str())
                    || standard.compact_form().is_some_and(|compact| {
                        src.eq_ignore_ascii_case(compact)
                    })
            }
            Repr::Custom(ref custom) => {
                src.eq_ignore_ascii_case(custom.as_str())
            }
        }
    }
}

impl fmt::Debug for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl fmt::Display for HeaderName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl PartialEq<str> for HeaderName {
    fn eq(&self, other: &str) -> bool {
        self.eq_str(other)
    }
}

impl PartialEq<&str> for HeaderName {
    fn eq(&self, other: &&str) -> bool {
        self.eq_str(other)
    }
}

impl PartialEq<HeaderName> for str {
    fn eq(&self, other: &HeaderName) -> bool {
        other.eq_str(self)
    }
}

impl PartialEq<HeaderName> for &str {
    fn eq(&self, other: &HeaderName) -> bool {
        other.eq_str(self)
    }
}

impl AsRef<str> for HeaderName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl From<&HeaderName> for HeaderName {
    fn from(name: &HeaderName) -> HeaderName {
        name.clone()
    }
}

impl TryFrom<&[u8]> for HeaderName {
    type Error = InvalidHeaderName;

    fn try_from(src: &[u8]) -> Result<HeaderName, InvalidHeaderName> {
        HeaderName::from_bytes(src)
    }
}

impl TryFrom<&str> for HeaderName {
    type Error = InvalidHeaderName;

    fn try_from(src: &str) -> Result<HeaderName, InvalidHeaderName> {
        HeaderName::from_bytes(src.as_bytes())
    }
}

impl FromStr for HeaderName {
    type Err = InvalidHeaderName;

    fn from_str(src: &str) -> Result<HeaderName, InvalidHeaderName> {
        HeaderName::try_from(src)
    }
}

impl StandardHeader {
    /// Finds the standard header that `src` names, in any letter case.
    ///
    /// This lowercases on the stack and then takes the single jump table in
    /// `from_bytes`, which is faster than comparing each name in turn as
    /// `from_bytes_case_insensitive` does for `const` contexts.
    fn from_any_case(src: &[u8]) -> Option<StandardHeader> {
        if src.len() > SCRATCH_BUF_SIZE {
            return None;
        }
        // Copy and lowercase in one loop. `copy_from_slice` followed by
        // `make_ascii_lowercase` made whole-message parsing a few percent
        // slower in the benchmarks, since names are short and the copy became
        // a `memcpy` call.
        let mut buf = [0u8; SCRATCH_BUF_SIZE];
        let lowered = &mut buf[..src.len()];
        for (dst, &b) in lowered.iter_mut().zip(src) {
            *dst = b.to_ascii_lowercase();
        }
        StandardHeader::from_bytes(lowered)
    }
}

// Stack scratch buffer size for lowercasing. It must hold the longest
// standard header name, currently `p-charging-function-addresses` at 29 bytes,
// which `standard_headers!` checks at compile time. Longer names cannot be
// standard.
const SCRATCH_BUF_SIZE: usize = 64;

const fn eq_lowercase_bytes(src: &[u8], expected: &[u8]) -> bool {
    if src.len() != expected.len() {
        return false;
    }

    let mut i = 0;
    while i < src.len() {
        if src[i].to_ascii_lowercase() != expected[i] {
            return false;
        }
        i += 1;
    }

    true
}

#[cfg(test)]
mod tests {
    use std::str::{self, FromStr};

    use super::*;

    #[test]
    fn standard_headers_parse_long_and_compact_forms() {
        for test in TEST_HEADERS {
            let parsed =
                HeaderName::from_bytes(test.canonical.as_bytes()).unwrap();

            assert_eq!(parsed, test.header);
            assert_eq!(parsed.as_str(), test.canonical);
            assert_eq!(parsed.compact_form(), test.compact);
            assert_eq!(parsed.to_string(), test.canonical);
            assert_eq!(format!("{parsed:?}"), test.canonical);

            if let Some(compact) = test.compact {
                assert_eq!(
                    HeaderName::from_bytes(compact.as_bytes()).unwrap(),
                    test.header
                );
            }
        }
    }

    #[test]
    fn standard_names_are_case_insensitive() {
        for test in TEST_HEADERS {
            assert_eq!(
                HeaderName::from_bytes(test.lower.as_bytes()).unwrap(),
                test.header
            );

            let mixed = test
                .canonical
                .chars()
                .enumerate()
                .map(|(i, ch)| {
                    if ch.is_ascii_alphabetic() && i % 2 == 0 {
                        ch.to_ascii_lowercase()
                    } else {
                        ch
                    }
                })
                .collect::<String>();

            assert_eq!(
                HeaderName::from_bytes(mixed.as_bytes()).unwrap(),
                test.header
            );

            if let Some(compact) = test.compact {
                let upper = compact.to_ascii_uppercase();
                assert_eq!(
                    HeaderName::from_bytes(upper.as_bytes()).unwrap(),
                    test.header
                );
            }
        }
    }

    #[test]
    fn custom_names_are_normalized_to_lowercase() {
        let name = HeaderName::from_bytes(b"X-CuStOm-Header").unwrap();
        assert_eq!(name.as_str(), "x-custom-header");
        assert_eq!(name, HeaderName::from_bytes(b"x-custom-header").unwrap());
        assert_eq!(name.compact_form(), None);
    }

    #[test]
    fn custom_names_use_custom_repr() {
        let short = HeaderName::from_bytes(b"X-Test").unwrap();
        assert!(matches!(short.0, Repr::Custom(_)));
        assert_eq!(short.as_str(), "x-test");

        let long_bytes = vec![b'X'; 80];
        let long = HeaderName::from_bytes(&long_bytes).unwrap();
        assert!(matches!(long.0, Repr::Custom(_)));
        assert_eq!(long.as_str(), str::from_utf8(&[b'x'; 80]).unwrap());
    }

    #[test]
    fn from_static_accepts_standard_and_lowercase_custom_names() {
        assert_eq!(HeaderName::from_static("Call-ID"), super::konst::CALL_ID);
        assert_eq!(HeaderName::from_static("i"), super::konst::CALL_ID);

        let custom = HeaderName::from_static("x-custom-header");
        assert_eq!(custom.as_str(), "x-custom-header");
        assert!(matches!(custom.0, Repr::Custom(_)));
    }

    #[test]
    fn from_static_accepts_long_custom_names() {
        // Longer than every standard name, so no fixed-size scratch buffer
        // can hold it.
        let src = "x-a-custom-header-name-longer-than-any-standard-one";
        assert_eq!(HeaderName::from_static(src).as_str(), src);
    }

    #[test]
    #[should_panic(
        expected = "custom SIP header field names in from_static() must \
            already be lowercase"
    )]
    fn from_static_rejects_non_lowercase_custom_names() {
        let _ = HeaderName::from_static("X-Custom-Header");
    }

    #[test]
    #[should_panic(expected = "invalid SIP header field name")]
    fn from_static_rejects_invalid_names() {
        let _ = HeaderName::from_static("Call ID");
    }

    #[test]
    fn rejects_invalid_header_names() {
        assert!(HeaderName::from_bytes(b"").is_err());
        assert!(HeaderName::from_bytes(b"Call ID").is_err());
        assert!(HeaderName::from_bytes(b"Call-ID:").is_err());
        assert!(HeaderName::from_bytes(b"Call/ID").is_err());
        assert!(HeaderName::from_bytes(&[0xff]).is_err());
    }

    #[test]
    fn parsing_apis_are_consistent() {
        let a = HeaderName::from_bytes(b"Call-ID").unwrap();
        let b = HeaderName::try_from("Call-ID").unwrap();
        let c = HeaderName::from_str("Call-ID").unwrap();

        assert_eq!(a, b);
        assert_eq!(b, c);
    }

    #[test]
    fn standard_names_equal_their_spellings_in_any_case() {
        for test in TEST_HEADERS {
            let header = &test.header;
            let upper = test.canonical.to_ascii_uppercase();

            assert_eq!(*header, test.canonical);
            assert_eq!(*header, test.lower);
            assert_eq!(*header, *upper);
            assert_eq!(test.canonical, *header);
            assert_eq!(*upper, *header);

            if let Some(compact) = test.compact {
                assert_eq!(*header, compact);
                assert_eq!(*header, *compact.to_ascii_uppercase());
            }

            assert_ne!(*header, format!("{}:", test.canonical).as_str());
            assert_ne!(*header, &test.canonical[1..]);
        }
    }

    #[test]
    fn standard_names_differ_from_other_names() {
        assert_ne!(super::konst::VIA, "Call-ID");
        assert_ne!(super::konst::VIA, "i");
        assert_ne!(super::konst::CALL_ID, "v");
        assert_ne!(super::konst::WARNING, "w");
        assert_ne!(super::konst::VIA, "x-via");
    }

    #[test]
    fn custom_names_equal_strings_ignoring_case() {
        let name = HeaderName::from_bytes(b"X-Account-Id").unwrap();

        assert_eq!(name, "x-account-id");
        assert_eq!(name, "X-ACCOUNT-ID");
        assert_eq!("X-Account-Id", name);
        assert_ne!(name, "x-account");
        assert_ne!(name, "x-account-id ");
        assert_ne!(name, "");
    }

    #[test]
    fn str_equality_matches_from_bytes() {
        // A string equals a name exactly when `from_bytes` reads it as that
        // name. The pool mixes standard names, with and without a compact
        // form, and custom ones. Random strings rarely name any of them, so
        // the fixed spellings after the random run cover the matches.
        fn property(src: String, index: usize) -> bool {
            let pool = [
                super::konst::VIA,
                super::konst::CALL_ID,
                super::konst::WARNING,
                HeaderName::from_static("x-a"),
                HeaderName::from_static("x-account-id"),
            ];
            let name = &pool[index % pool.len()];
            let parsed = HeaderName::from_bytes(src.as_bytes()).ok();

            let consistent =
                (*name == *src) == (parsed.as_ref() == Some(name));
            let symmetric = (*src == *name) == (*name == *src);
            let parsed_equal = parsed.is_none_or(|parsed| parsed == *src);
            consistent && symmetric && parsed_equal
        }

        quickcheck::QuickCheck::new()
            .tests(2000)
            .quickcheck(property as fn(String, usize) -> bool);

        for src in ["v", "V", "via", "VIA", "Via", "i", "x-A", "X-ACCOUNT-ID"]
        {
            for index in 0..5 {
                assert!(property(src.to_owned(), index), "{src} at {index}");
            }
        }
    }

    #[test]
    fn invalid_header_name_error_text() {
        let err = HeaderName::from_bytes(b"Call ID").unwrap_err();
        assert_eq!(err.to_string(), "invalid SIP header name");
        assert_eq!(format!("{err:?}"), "InvalidHeaderName");
    }
}
