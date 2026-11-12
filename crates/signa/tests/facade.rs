//! The facade re-exports signa-core's items rather than copies, so the two
//! crates' paths name the same types and code written against the paths of
//! signa 0.3 compiles unchanged. With the `ua` feature it re-exports
//! signa-ua the same way.

use std::any::TypeId;

use bytes::Bytes;

/// Whether two paths name one type. A copied type would have its own id.
fn same<A: 'static, B: 'static>() -> bool {
    TypeId::of::<A>() == TypeId::of::<B>()
}

// A value built through one crate's path is accepted where the other's is
// named, with no conversion.
#[test]
fn facade_request_response_type_identity() {
    fn into_core(
        request: signa::Request<Bytes>,
    ) -> signa_core::Request<Bytes> {
        request
    }
    fn into_facade(
        response: signa_core::Response<Bytes>,
    ) -> signa::Response<Bytes> {
        response
    }

    let request = signa::Request::builder()
        .method("OPTIONS")
        .uri("sip:bob@example.com")
        .header("CSeq", "1 OPTIONS")
        .body(Bytes::new())
        .unwrap();
    let response = signa_core::Response::reply_to(&request)
        .status(200)
        .body(Bytes::new())
        .unwrap();

    assert_eq!(into_core(request).method(), signa::Method::OPTIONS);
    assert_eq!(into_facade(response).status(), signa_core::StatusCode::OK);

    assert!(same::<signa::Message<Bytes>, signa_core::Message<Bytes>>());
    assert!(same::<signa::HeaderMap, signa_core::HeaderMap>());
    assert!(same::<signa::Uri, signa_core::Uri>());
    assert!(same::<signa::Extensions, signa_core::Extensions>());
    assert!(
        same::<signa::message::BuildError, signa_core::message::BuildError>()
    );
    assert!(
        same::<signa::transaction::Timers, signa_core::transaction::Timers>()
    );
    assert!(same::<signa::transport::Flow, signa_core::transport::Flow>());
}

// The imports of signa 0.3's README and examples, through the facade. Each
// name is checked against signa-core's, so a re-export that went missing or
// pointed elsewhere fails here.
#[test]
fn facade_existing_endpoint_imports_compile() {
    use signa::{
        endpoint::{
            BindError, Builder, CancelError, CancelOutcome, ClientControl,
            ClientTransaction, Endpoint, Error, Incoming, IncomingEvent,
            ReplyRoute, Responder, Responses, ServerEvent, ServerEvents,
            ServerRequest, ShutdownOutcome, SubmitError, Target, ViaMode,
            WorkGuard,
        },
        message::header::{CALL_ID, FROM, TO, Tag},
        transaction::Timers,
        transport::{Flow, Transport, WriteLimits},
    };

    assert!(same::<Endpoint, signa_core::endpoint::Endpoint>());
    assert!(same::<Builder, signa_core::endpoint::Builder>());
    assert!(same::<Incoming, signa_core::endpoint::Incoming>());
    assert!(same::<IncomingEvent, signa_core::endpoint::IncomingEvent>());
    assert!(same::<ServerRequest, signa_core::endpoint::ServerRequest>());
    assert!(same::<Responder, signa_core::endpoint::Responder>());
    assert!(same::<ServerEvent, signa_core::endpoint::ServerEvent>());
    assert!(same::<ServerEvents, signa_core::endpoint::ServerEvents>());
    assert!(same::<ClientControl, signa_core::endpoint::ClientControl>());
    assert!(
        same::<ClientTransaction, signa_core::endpoint::ClientTransaction>()
    );
    assert!(same::<Responses, signa_core::endpoint::Responses>());
    assert!(same::<ReplyRoute, signa_core::endpoint::ReplyRoute>());
    assert!(same::<Target, signa_core::endpoint::Target>());
    assert!(same::<ViaMode, signa_core::endpoint::ViaMode>());
    assert!(same::<WorkGuard, signa_core::endpoint::WorkGuard>());
    assert!(same::<ShutdownOutcome, signa_core::endpoint::ShutdownOutcome>());
    assert!(same::<CancelOutcome, signa_core::endpoint::CancelOutcome>());
    assert!(same::<Error, signa_core::endpoint::Error>());
    assert!(same::<BindError, signa_core::endpoint::BindError>());
    assert!(same::<CancelError, signa_core::endpoint::CancelError>());
    assert!(same::<SubmitError, signa_core::endpoint::SubmitError>());
    assert!(same::<Tag, signa_core::message::header::Tag>());
    assert!(same::<Timers, signa_core::transaction::Timers>());
    assert!(same::<Transport, signa_core::transport::Transport>());
    assert!(same::<Flow, signa_core::transport::Flow>());
    assert!(same::<WriteLimits, signa_core::transport::WriteLimits>());
    assert_eq!(CALL_ID, signa_core::message::header::CALL_ID);
    assert_eq!(FROM, signa_core::message::header::FROM);
    assert_eq!(TO, signa_core::message::header::TO);
}

// `signa::ua` is signa-ua itself, so the checks of its items below guard the
// form of the re-export, not each item. What matters more is that a UA
// attaches to an endpoint built through the facade, since both crates name
// signa-core's endpoint.
#[cfg(feature = "ua")]
#[tokio::test]
async fn facade_ua_type_identity() {
    use signa::{
        endpoint::Endpoint,
        ua::{
            AttachError, Config, Description, Error, Event, IncomingInvite,
            InvitePlan, ReinvitePlan, Session, ShutdownMode, ShutdownOutcome,
            StaticResolver, Ua, UaDriver, UaEvents, UaHandle, attach,
        },
    };

    assert!(same::<Ua, signa_ua::Ua>());
    assert!(same::<UaHandle, signa_ua::UaHandle>());
    assert!(same::<UaEvents, signa_ua::UaEvents>());
    assert!(same::<UaDriver, signa_ua::UaDriver>());
    assert!(same::<Config, signa_ua::Config>());
    assert!(same::<Event, signa_ua::Event>());
    assert!(same::<IncomingInvite, signa_ua::IncomingInvite>());
    assert!(same::<InvitePlan, signa_ua::InvitePlan>());
    assert!(same::<ReinvitePlan, signa_ua::ReinvitePlan>());
    assert!(same::<Session, signa_ua::Session>());
    assert!(same::<Description, signa_ua::Description>());
    assert!(same::<StaticResolver, signa_ua::StaticResolver>());
    assert!(same::<Error, signa_ua::Error>());
    assert!(same::<AttachError, signa_ua::AttachError>());
    assert!(same::<ShutdownMode, signa_ua::ShutdownMode>());
    assert!(same::<ShutdownOutcome, signa_ua::ShutdownOutcome>());

    let (endpoint, incoming) = Endpoint::builder()
        .udp("127.0.0.1:0".parse().unwrap())
        .bind()
        .unwrap();
    let config = Config::new("sip:ua@127.0.0.1").unwrap();
    let ua = attach(endpoint, incoming, config).unwrap();
    let driver = tokio::spawn(ua.driver);
    // A zero timeout drains a UA with nothing to do, rather than expiring.
    let report = ua
        .handle
        .shutdown(ShutdownMode::DrainExisting, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(report.outcome, ShutdownOutcome::Drained);
    driver.await.unwrap();
}
