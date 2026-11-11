/*!
The UA's runtime through its public API.

Each test drives a UA attached to a loopback endpoint and plays the other
side by hand, as a raw UDP or TCP peer or as another UA, so that what goes on
the wire is what the test checks. The modules follow the sections of
`docs/signa-ua-rfc-test-map.md`, and `support` holds what more than one of
them uses. `tower` is an external Tower adapter for the UA's decisions, with
its tests. `interop` holds the ignored tests that `scripts/interop/run` runs
against SIPp, an independent implementation.
*/

mod cancel_bye;
mod interop;
mod limits;
mod reinvite;
mod routing;
mod runtime;
mod shutdown;
mod support;
mod tower;
mod uac;
mod uas;
