# RFC and contract test map

This maps each requirement signa takes on, and each decision of its API, to
the tests that show it. A section link names the rule a test checks. It is not
a claim that signa implements the whole section, and nothing here claims
conformance to an RFC as a whole. Rows whose basis is signa policy or design
are decisions of this crate, not RFC rules.

Test names are the function names, and the file says where to find them.

The crate documentation's "Supported RFC scope" section sums these rows up by
RFC as supported, partial, the TU's, or not supported. Each item it lists as
supported or partial has a row here, and its omissions are in "Deliberate
omissions" below.

## Reading the table

Type is where the evidence runs. Paths are in `crates/signa-core/` unless
they start with `examples/`:

* machine: a transaction state machine driven with a fake clock, in
  `src/transaction/`.
* driver: the endpoint's driver run by hand, mostly on a paused clock, in
  `src/endpoint/driver.rs` and `src/endpoint/server.rs`.
* loopback: endpoints and raw peers over real loopback sockets, in
  `src/endpoint/mod.rs` and `src/transport/`.
* external: a separate test crate that sees only the public API, in `tests/`.
* unit: a test of one module's functions, inline in that module.
* example: a program in `examples/` that checks its own outcome. CI runs each
  one with RFC 3261's default timers.

Status:

* covered: the behavior is tested on the transports and receptions listed.
* partial: tested, with the limit stated.
* omitted: deliberately not in 0.3.0. The crate documentation's "Deliberate
  omissions" section says why.

Unless a row says otherwise, the transport is UDP and TCP and the reception is
stateful.

[3261]: https://www.rfc-editor.org/rfc/rfc3261.html
[6026]: https://www.rfc-editor.org/rfc/rfc6026.html
[4320]: https://www.rfc-editor.org/rfc/rfc4320.html
[3581]: https://www.rfc-editor.org/rfc/rfc3581.html

## Messages (RFC 3261 sections 7 and 18.3)

Unless a row says otherwise, these are unit tests in `src/message/mod.rs`.

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Parsing | [3261 §7](https://www.rfc-editor.org/rfc/rfc3261.html#section-7) | A complete request or response parses with siparse and shares the input. An incomplete head, what siparse rejects, and a status outside 100 to 699 are errors. | `parses_a_request`, `parses_a_response`, `parses_either_kind_as_a_message`, `shares_the_input_instead_of_copying`, `rejects_an_incomplete_head`, `reports_what_siparse_rejected`, `rejects_status_codes_outside_the_sip_classes` | unit | - | covered |
| Body length of one message | [3261 §18.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.3) | Without Content-Length the body is the rest of the datagram. Content-Length cuts off trailing bytes. A shorter body, a non-numeric value, and repeated values that disagree are errors. | `body_without_content_length_is_the_rest`, `content_length_cuts_off_trailing_bytes`, `rejects_a_body_shorter_than_content_length`, `content_length_must_be_digits`, `repeated_content_length_must_agree` | unit | - | covered |
| Encoding | [3261 §7](https://www.rfc-editor.org/rfc/rfc3261.html#section-7), [§20.14](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.14) | Content-Length comes from the body, a missing reason phrase gets the standard one, and a received message encodes back to itself. | `encodes_a_request`, `encodes_a_response_with_its_canonical_reason`, `content_length_always_matches_the_body`, `round_trips_a_received_message` | unit | - | covered |
| Extension methods | [3261 §17](https://www.rfc-editor.org/rfc/rfc3261.html#section-17) | An unknown method is an extension method. It runs as a non-INVITE transaction on both sides, arrives at a stateless endpoint, and goes out through `send_request`. | `non_canonical_case_becomes_extension`, `inline_and_allocated_extension` (`message/start_line/method.rs`), `an_extension_method_runs_as_a_non_invite_transaction`, `stateless_requests_of_every_method_arrive_without_transactions` (`endpoint/mod.rs`), `send_request_takes_any_method_without_a_transaction` | unit, loopback | UDP | covered |

## Transactions and timers (RFC 3261 sections 17 and 18, RFC 6026, RFC 4320)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| INVITE client retransmission | [3261 §17.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.2) | Timer A doubles without a T2 cap. B ends Calling, not Proceeding. A stops on a provisional. | `client_retransmits_invite_without_a_t2_cap`, `client_b_wins_over_a_and_reliable_calling_still_times_out`, `proceeding_stops_a_and_has_no_timer_b` (`transaction/invite/client.rs`), `invite_proceeding_has_no_timer_b_and_d_keeps_the_ack_32_seconds` (`driver.rs`) | machine, driver | A on UDP only | covered |
| INVITE client finals | [3261 §17.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.2), [6026 §8.4](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4) | Every final class from Calling and Proceeding. A 2xx enters Accepted, a non-2xx Completed. | `every_final_class_transitions_from_calling_and_proceeding` | machine | both | covered |
| Non-2xx ACK | [3261 §17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.3) | The transaction builds the ACK from the INVITE's routing and the final's To, caches it for duplicate finals, and delivers the final once. Timer D is at least 32 s on UDP and 0 on TCP. | `non_success_ack_uses_request_routing_and_response_to`, `client_d_resends_the_cached_ack_and_never_redelivers_final`, `configurable_d_is_independent_of_t1`, `invite_client_acknowledges_a_non_2xx_on_both_transports` (`mod.rs`), `invite_proceeding_has_no_timer_b_and_d_keeps_the_ack_32_seconds` | machine, driver, loopback | both | covered |
| INVITE client Accepted | [6026 §8.4](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4) | Every 2xx, retransmitted or forked, goes to the TU until Timer M. M is not restarted and fires before a 2xx due at its instant. | `accepted_delivers_every_success_without_restarting_m`, `invite_m_is_not_restarted_and_fires_before_a_2xx_at_its_instant`, `invite_client_delivers_forked_2xx_until_timer_m_for_the_tu_to_ack` | machine, driver, loopback | both | covered |
| INVITE client transport errors | [3261 §17.1.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.2), [3261 §18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2) | A transport error ends Calling, Proceeding and Completed. A final on a new TCP connection is still taken when a listener is advertised. | `transport_errors_end_calling_proceeding_and_completed`, `a_tcp_invite_acks_a_final_from_a_new_connection_at_its_target`, `a_tcp_invite_without_a_listener_fails_when_its_connection_closes` | machine, loopback | TCP for the connection cases | covered |
| INVITE server provisional and non-2xx | [3261 §17.2.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.1) | Proceeding resends the latest provisional for a retransmission. G caps at T2, H times out and reports `AckTimeout`. An ACK starts I, and a repeated one does not extend it. TCP has no G. | `server_proceeding_retransmits_the_latest_provisional`, `server_g_caps_at_t2_and_h_times_out`, `reliable_server_waits_for_ack_or_h_without_g`, `non_success_ack_starts_i_and_repeated_ack_does_not_extend_it`, `invite_server_sends_100_and_absorbs_the_non_2xx_ack`, `invite_server_reports_a_missing_ack_at_timer_h` | machine, loopback | both | covered |
| INVITE server Accepted | [6026 §8.7](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7) | Accepted takes more 2xx without restarting L, absorbs INVITE retransmissions without sending, and hands each ACK to the TU. | `accepted_server_absorbs_invites_and_passes_ack_without_restarting_l`, `invite_l_is_not_restarted_and_fires_before_a_retransmission`, `invite_server_takes_forked_2xx_and_hands_acks_to_the_tu` | machine, driver, loopback | both | covered |
| INVITE server transport failure | [6026 §8.8](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.8) | A transport error is reported and does not end the INVITE server. | `server_transport_failure_preserves_each_live_state`, `invite_server_keeps_accepted_after_a_transport_failure` | machine, loopback | both | covered |
| Server response admission | [3261 §17.2.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.1), [6026 §8.7](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7) | No 1xx or non-2xx after a final, only 2xx in Accepted, with a reason for each refusal. | `server_rejects_responses_outside_the_current_state`, `check_response_reports_why_a_response_is_refused`, `response_rejections_preserve_the_live_machine` | machine, driver | both | covered |
| Non-INVITE client | [3261 §17.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.2) | E until F, E moves to T2 after a provisional, F wins a tie, K after the final, no retransmission and K of 0 on TCP. | `retransmits_on_timer_e_until_timer_f`, `timer_f_wins_when_both_are_due`, `a_provisional_response_moves_retransmissions_to_t2`, `the_final_response_ends_it_after_timer_k`, `a_reliable_transport_never_retransmits_and_ends_with_the_response`, `a_reliable_transport_still_times_out`, `a_transport_error_ends_it`, `timer_f_ends_a_request_nobody_answers` | machine, loopback | both | covered |
| Non-INVITE server | [3261 §17.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.2) | The final is resent for retransmissions until J, and the transaction ends with the final on TCP. | `the_final_response_is_resent_until_timer_j`, `a_reliable_transport_ends_with_the_final_response`, `retransmissions_are_absorbed_by_the_server_transaction`, `examples/options` | machine, loopback, example | both | covered |
| RFC 4320 100 and 408 | [4320 §4](https://www.rfc-editor.org/rfc/rfc4320.html#section-4) | The driver sends a 100 when due on UDP. A TU 100 before that is `TooEarly` on UDP and allowed on TCP. Other provisionals and 408 are refused. | `sends_a_100_itself_when_nothing_was_sent_in_time`, `a_response_in_time_cancels_the_100`, `early_udp_100_rejection_keeps_the_automatic_deadline`, `reliable_100_is_allowed_immediately_and_admission_is_non_mutating`, `a_due_100_from_the_user_is_sent_and_other_provisionals_are_not`, `a_408_is_dropped_and_ends_it`, `a_slow_service_gets_a_100_sent_for_it`, `examples/options` | machine, loopback, example | both | covered |
| No late stateful non-INVITE forwarding | [4320 §4](https://www.rfc-editor.org/rfc/rfc4320.html#section-4) | A response after the client transaction ended is stray and discarded. | `a_response_nobody_listens_for_is_dropped`, `only_a_stateless_endpoint_delivers_stray_responses` | loopback | UDP | covered |
| Timers | [3261 §17.1.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.1.1), [table 4](https://www.rfc-editor.org/rfc/rfc3261.html#page-265) | Defaults, derived intervals, no overflow, positive bases, UDP D at least 32 s. | `defaults_and_derived_intervals`, `invalid_values_cannot_make_a_timer_set`, `configurable_d_is_independent_of_t1` | unit, machine | - | covered |
| Timers before input at the same instant | signa policy | Due timers run before input that arrives at their instant. | `invite_m_is_not_restarted_and_fires_before_a_2xx_at_its_instant`, `invite_l_is_not_restarted_and_fires_before_a_retransmission`, `timer_f_wins_when_both_are_due` | driver, machine | both | covered |
| Server matching | [3261 §17.2.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3) | A key from branch, sent-by and method matches retransmissions and tells transactions apart. The cookie is case-insensitive. A request without it gets no key. | `server_keys_match_retransmissions_and_tell_transactions_apart`, `the_cookie_is_case_insensitive`, `requests_without_an_rfc_3261_branch_have_no_key`, `requests_without_a_cookie_are_handed_up_each_time` | unit, loopback | both | covered |
| Client matching | [3261 §17.1.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.3) | A response matches by branch and CSeq method. A response with another sent-by is discarded. | `client_keys_match_a_response_to_its_request`, `responses_without_a_branch_or_cseq_have_no_key`, `a_response_from_another_sent_by_is_discarded` | unit, loopback | both | covered |
| Stray responses in stateful reception | [6026 §8.9](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.9) | Responses matching no client transaction, including a 2xx after M, are discarded. | `only_a_stateless_endpoint_delivers_stray_responses`, `invite_client_delivers_forked_2xx_until_timer_m_for_the_tu_to_ack` | loopback | UDP | covered |
| RFC 2543 fallback matching | [3261 §17.2.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-17.2.3) | Not implemented. Such requests are `Untracked`. | `requests_without_a_cookie_are_handed_up_each_time`, `untracked_reception_has_no_transaction_or_drop_fallback` | loopback, driver | both | omitted |

## CANCEL (RFC 3261 section 9)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| CANCEL construction | [3261 §9.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1) | Request-URI, From, To, Call-ID, CSeq number, Route and top Via of the INVITE, to its next hop. No Require. | `cancel_copies_the_invite_identity_routing_and_top_via`, `cancel_waits_for_a_provisional_and_runs_its_own_transaction` | machine, loopback | UDP, TCP | covered |
| No CANCEL before a provisional | [3261 §9.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1) | The intent waits for the first provisional, and a final first makes it `NotNeeded`. | `cancel_waits_for_a_provisional_and_runs_its_own_transaction`, `invite_client_acknowledges_a_non_2xx_on_both_transports` | loopback | both | covered |
| One cancellation intent | signa policy | A second call is `AlreadyRequested`. A dropped `cancel` future still cancels once. | `a_dropped_cancel_future_still_cancels_once` | loopback | UDP | covered |
| Separate CANCEL transaction | [3261 §9.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1) | The CANCEL's responses do not end the INVITE's stream. | `cancel_waits_for_a_provisional_and_runs_its_own_transaction`, `examples/invite-uac`, `examples/fork-proxy` | loopback, example | UDP | covered |
| Cancellation deadline | [3261 §9.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1) | 64 T1 after the CANCEL without a final, the INVITE ends with `is_cancel_timeout`. | `the_cancel_deadline_runs_64_t1_from_the_cancel`, `the_cancel_deadline_ends_an_unanswered_invite` | driver, loopback | UDP | covered |
| 2xx racing CANCEL | [3261 §9.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.1), [13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | The 2xx reaches the TU, which acknowledges it. | `a_2xx_racing_a_cancel_still_reaches_the_tu`, `examples/invite-uac` (case 3) | loopback, example | UDP | covered |
| CANCEL matching | [3261 §9.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2) | By branch and sent-by. Two peers with the same branch get different targets. A retransmitted CANCEL gets its cached 200 after the target ended. | `a_cancel_targets_its_request_by_branch_and_sent_by` (`key.rs`), `a_cancel_reaches_the_tu_with_its_target_and_transaction` | unit, loopback | UDP | covered |
| CANCEL of a non-INVITE | [3261 §9.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2) | Delivered with its target, which it does not affect. | `a_cancel_of_a_non_invite_is_not_an_invite_cancellation` | loopback | UDP | covered |
| Unmatched CANCEL | [3261 §9.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2), [16.10](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.10) | No transaction and no automatic 481. The TU answers through the route. | `an_unmatched_cancel_waits_for_the_tu` | loopback | UDP | covered |
| UAS answer to CANCEL | [3261 §9.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-9.2) | The TU answers 200, and 487 to a pending INVITE. | `examples/invite-uas`, `examples/fork-proxy`, `a_cancel_is_answered_while_the_request_service_is_not_ready` (`tests/tower_fixture.rs`) | example, external | UDP | covered (TU behavior) |
| Dropping handles does not cancel | signa policy | Dropping `ClientControl` or `Responses` neither sends CANCEL nor stops the machine. | `dropped_invite_handles_neither_cancel_nor_stop_the_machine` | loopback | UDP | covered |

## ACK and the 2xx (RFC 3261 sections 13.2.2.4 and 13.3.1.4, RFC 6026 section 8)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| ACK never gets a response | [3261 §17](https://www.rfc-editor.org/rfc/rfc3261.html#section-17) | On every path, overload and shutdown included. | `acks_never_get_a_response`, `acks_reach_the_tu_during_shutdown_without_a_response`, `control_capacity_discards_acks_beyond_it`, `invalid_identity_and_ack_are_rejected_before_enqueue`, `stateless_routes_answer_requests_but_not_acks` | loopback, unit | both receptions | covered |
| 2xx ACK goes to the TU | [6026 §8.7](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7), [3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4) | An ACK matching Accepted or nothing arrives as `IncomingEvent::Ack`. | `invite_server_takes_forked_2xx_and_hands_acks_to_the_tu`, `acks_never_get_a_response` | loopback | UDP | covered |
| UAC ACK for each 2xx | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | The TU sends an ACK for every 2xx, retransmissions and forks included, with `send_request` and no client transaction. | `invite_client_delivers_forked_2xx_until_timer_m_for_the_tu_to_ack`, `examples/invite-uac` (case 1) | loopback, example | UDP | covered (TU behavior) |
| UAS 2xx retransmission | [3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4), [6026 §8.1](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.1) | The TU retransmits through the reply route from T1, doubling to T2, until the ACK or 64 T1, over TCP as well. signa does not. | `a_uas_retransmits_its_2xx_under_a_guard_until_the_ack`, `examples/invite-uas` (calls 1 and 2, which checks the count against the schedule) | loopback, example | UDP, TCP | covered (TU behavior) |
| ACK wait registered before the 2xx | design | The TU records its waiter before submitting the 2xx. | `examples/invite-uas`, `wrappers_see_every_submission_and_no_protocol_output` (`tests/tower_fixture.rs`) | example, external | UDP | covered (TU behavior) |
| Multiple 2xx through a responder | [6026 §8.7](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7) | Further 2xx with other To tags are accepted in Accepted. To is not locked to the first tag. | `invite_server_takes_forked_2xx_and_hands_acks_to_the_tu`, `examples/fork-proxy` (call 1), `wrappers_see_every_submission_and_no_protocol_output` | loopback, example, external | UDP | covered |

## Proxies (RFC 3261 section 16, RFC 6026 sections 7.3 and 8.3)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Stateless forwarding | [3261 §16.11](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11) | No transaction, no absorbed retransmission, no 100/500/503. Every method arrives. | `stateless_requests_of_every_method_arrive_without_transactions`, `stateless_routes_answer_requests_but_not_acks`, `a_stateless_proxy_relays_between_real_endpoints` | loopback | UDP stateless | covered |
| Stable branch for INVITE, CANCEL and non-2xx ACK | [3261 §16.11](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.11) | The caller's branch tops the received Via rows. The example's branch keeps the downstream UAS's matching intact. | `a_caller_branch_tops_the_received_via_rows`, `a_retransmission_through_a_stateless_proxy_reaches_one_transaction`, `examples/stateless-proxy` | loopback, example | UDP stateless | covered |
| Response forwarding by Via | [3261 §18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2), [3581 §4](https://www.rfc-editor.org/rfc/rfc3581.html#section-4) | `forward_response` sends by the remaining top Via, `received` with `rport`, IPv6, above 1300 bytes, and refuses what it cannot route. | `forward_response_routes_by_the_remaining_top_via`, `forward_response_routes_to_an_ipv6_sent_by`, `forward_response_refuses_what_it_cannot_route`, `a_forwarded_response_goes_where_its_remaining_top_via_says`, `a_forwarded_response_signa_cannot_route_is_refused` | loopback, unit | UDP stateless | covered |
| Stateless TCP | design | Refused at bind. | `stateless_reception_binds_udp_only` | loopback | - | omitted |
| Stateful proxy: no 100 forwarded, provisionals and every 2xx forwarded, best response | [3261 §16.7](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.7) | TU policy. The example shows it with signa's transactions. | `examples/fork-proxy` | example | UDP | covered (TU behavior) |
| Stateful proxy: CANCEL of branches | [3261 §16.10](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.10) | The proxy answers the CANCEL and cancels each pending branch. | `examples/fork-proxy` (call 2) | example | UDP | covered (TU behavior) |
| Late responses need live state | [6026 §7.3](https://www.rfc-editor.org/rfc/rfc6026.html#section-7.3), [§8.3](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.3) | `respond` refuses after the final non-2xx, and everything after L. A route does not give permission. | `server_rejects_responses_outside_the_current_state`, `a_stateful_response_after_timer_l_is_refused`, `examples/fork-proxy` (a 183 after the 2xx is refused and dropped) | machine, loopback, example | both | covered |
| Unmatched CANCEL forwarded statelessly | [3261 §16.10](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.10) | Needs a separate stateless endpoint in 0.3.0. | none | - | - | omitted (mixed reception) |
| Request validation, Route, Record-Route, target sets, Timer C | [3261 §16.3 to 16.6](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.3), [16.8](https://www.rfc-editor.org/rfc/rfc3261.html#section-16.8) | TU policy. The examples state what they leave out. | none in signa | - | - | omitted (TU) |

## Transport and response routing (RFC 3261 section 18, RFC 3581)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| received and rport | [3261 §18.2.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.1), [3581 §4](https://www.rfc-editor.org/rfc/rfc3581.html#section-4) | `received` is added with every filled-in `rport`, and a sender's own `received` is replaced. | `received_and_rport_are_filled_in`, `rport_and_a_sender_s_received_always_get_the_source_address`, `marking_the_top_via_preserves_later_values` | loopback, unit | UDP, TCP | covered |
| Response destination | [3261 §18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2) | UDP replies go from the receiving local address to the Via/rport destination. TCP uses the original connection, then falls back to sent-by. | `udp_route_preserves_local_address_and_rport_and_can_outlive_other_handles`, `udp_without_rport_uses_sent_by_port`, `tcp_uses_original_writer_then_falls_back_after_closure`, `a_response_opens_a_new_connection_when_the_request_s_has_closed`, `reply_ports_follow_transport_and_rport_without_trusting_received` | loopback, unit | both | covered |
| Two connections with one sent-by | [3261 §18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2) | Each gets its own response. The route keeps the connection, not the Via. | `two_tcp_connections_with_one_sent_by_get_their_own_responses` (`tests/reply_routing.rs`) | external | TCP | covered |
| UDP response above 1300 bytes | [3261 §18.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1), [18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2) | Stays on UDP. The 1300-byte limit is for requests. | `a_udp_response_above_1300_bytes_stays_on_udp` (`tests/reply_routing.rs`), `forward_response_routes_by_the_remaining_top_via` | external, loopback | UDP | covered |
| Large UDP requests | [3261 §18.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1) | A request above 1300 bytes with its Via is refused, not moved to TCP. | `large_requests_do_not_go_over_udp`, `send_request_refuses_before_sending` | loopback | UDP | covered |
| Stream framing | [3261 §18.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.3) | Content-Length framing, fragments, pipelining, bad lengths close the connection. | `transport/framing.rs` tests, `a_fragmented_request_is_put_together`, `a_bad_message_closes_the_connection` | unit, loopback | TCP | covered |
| Keepalive | [5626 §4.4.1](https://www.rfc-editor.org/rfc/rfc5626.html#section-4.4.1) | A double CRLF gets a single CRLF. | `a_ping_is_answered_with_a_pong`, `server_answers_pings_and_waits_for_half_of_one` | loopback, unit | TCP | partial: no flow keepalive policy |
| Multicast, maddr | [3261 §18.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.2.2) | Refused or dropped explicitly. | `via_maddr_requests_are_dropped_without_multicast_support`, `client_tu_rejects_multicast_before_admission` | driver, loopback | UDP | omitted (explicit error) |

## SIPS and routing responsibility

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| `sips:` Request-URI | [3261 §8.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.2) | `start` and `send_request` refuse it in any letter case. | `plaintext_transports_cannot_submit_sips_request_uris`, `client_tu_refuses_a_sips_request_uri_before_admission`, `a_sips_request_uri_is_refused_in_any_case` | unit, loopback | both | partial: the Request-URI is the only SIPS check, see the next row |
| Route-derived TLS needs | [5630 §5.1.1](https://www.rfc-editor.org/rfc/rfc5630.html#section-5.1.1) | The caller's. signa sends Route and target as given. | `sips_routes_are_left_to_the_caller`, `client_tu_sends_to_the_target_with_request_uri_and_route_as_given` | unit, loopback | both | covered (as a boundary) |
| TLS, RFC 3263 discovery | design | Not in 0.3.0. | none | - | - | omitted |

## TU API contracts (signa policy)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Reception is fixed and explicit | design | Each reception refuses the other's operations. Stateless is UDP-only. | `stateless_reception_binds_udp_only`, `each_reception_refuses_the_other_s_operations` | loopback | both receptions | covered |
| Owned envelopes, Send handles | design | Envelopes destructure, handles split, operations are `Send`, and `ResponseSubmission` is `Unpin`. | `public_operations_are_send_and_envelopes_are_owned`, `submissions_are_send_and_unpin` (`tests/tower_fixture.rs`) | driver, external | - | covered |
| Commit points | design | Dropping before enqueue has no effect. After enqueue the operation runs. | `cancellation_before_enqueue_has_no_effect_and_after_enqueue_keeps_the_write`, `client_tu_start_and_receive_cancellation_preserve_committed_work`, `queued_submissions_keep_their_count_after_waiters_drop`, `stateless_sends_commit_at_enqueue`, `shared_reply_bytes_remain_charged_after_the_future_is_dropped` | driver, loopback | both | covered |
| Responder drop | design | An unanswered responder drop sends a 500 with a stable tag, ordered after queued submissions. | `unanswered_drop_reuses_the_provisional_to_tag`, `a_dropped_invite_responder_sends_a_500_with_the_provisional_tag`, `cancelled_waiter_and_responder_drop_cannot_race_a_queued_final`, `a_panicking_application_releases_work_through_responder_drop`, `a_tower_timeout_drops_the_handler_but_cancels_nothing` (`tests/tower_fixture.rs`) | driver, loopback, external | both | covered |
| Stale IDs | design | A reused slot cannot be reached through an old handle. | `a_reused_numeric_slot_cannot_redirect_a_tu_capability`, `a_stale_cancel_handle_cannot_reach_a_reused_slot`, `timer_j_returns_server_capacity_and_old_ids_do_not_touch_reused_slots`, `a_removed_id_finds_nothing_even_when_its_slot_is_reused` | driver, unit | - | covered |
| Response stream overflow | design | Queued responses stay, then one `DeliveryOverflow`. The machine goes on. | `overflow_preserves_queued_responses_and_reserved_terminal_error`, `client_tu_overflow_does_not_end_the_machine_or_free_its_slot`, `invite_client_overflow_keeps_acknowledging` | unit, loopback | UDP | covered |
| Server observation | design | Failures before termination, coalesced with a count, termination never lost, late write failures after it. | `accepted_io_failure_precedes_termination_and_retains_operation_id`, `failure_overflow_does_not_consume_terminal_capacity`, `local_write_failure_remains_observable_after_machine_termination`, `teardown_reports_an_unknown_write_outcome_as_endpoint_close` | driver | both | covered |
| Resource bounds | design | Tables, unanswered work, event bytes, routes, writes, connects, timer history and control capacity are bounded through their lifetime. | `work_lasts_beyond_recv_and_returns_at_accepted_final`, `a_retained_route_has_its_own_lifetime_bound`, `saturated_response_retention_rejects_without_changing_state`, `completed_servers_refuse_new_transactions_but_answer_retransmissions`, `route_churn_is_bounded_and_response_entries_have_reserved_room`, `arbitrary_deadline_changes_preserve_live_timers_and_bound_history`, `an_invite_reserves_its_cancel_or_nothing`, `stateless_queues_are_bounded_in_count_and_count_drops`, `stateless_queues_and_routes_are_bounded_in_bytes` | driver, unit, loopback | both | covered |
| Overload | design, [3261 §21.5.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-21.5.4) | A new request beyond admission gets a stateless 503. ACK and CANCEL go on in control capacity. | `overload_gets_a_stateless_503`, `ack_and_cancel_progress_while_ordinary_admission_is_full`, `protocol_work_progresses_with_admission_full_during_a_shutdown` | loopback | UDP | partial: the stateless 503 has no reproducible To tag yet |
| Adapter dispatch keeps control live | design | ACK and CANCEL progress while handlers wait for an ACK or readiness is Pending. Handlers and buffered calls are bounded. Readiness and call on one non-`Clone` instance. | `acks_progress_while_every_handler_waits_for_one`, `a_cancel_is_answered_while_the_request_service_is_not_ready`, `buffered_calls_are_bounded_and_overflow_gets_a_503` (`tests/tower_fixture.rs`) | external | UDP | covered |
| Response middleware | design | Wrappers see each TU 1xx and every 2xx, keep watching after the first final, and see neither the automatic 100 nor retransmissions. Acceptance is not delivery. | `wrappers_see_every_submission_and_no_protocol_output` (`tests/tower_fixture.rs`) | external | UDP | covered |
| Handler end is not transaction end | design | A handler's future can finish long before its transaction. | `handler_end_comes_before_transaction_end` (`tests/tower_fixture.rs`), `examples/fork-proxy` | external, example | UDP | covered |

## Shutdown and work guards (signa policy)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Drain waits for Accepted | [6026 §8.4](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.4), [§8.7](https://www.rfc-editor.org/rfc/rfc6026.html#section-8.7) | The drain waits for L and M, and for D, I, J and K. | `a_graceful_shutdown_waits_for_timer_l`, `a_graceful_shutdown_waits_for_timer_m`, `a_shutdown_waits_for_timer_l_and_runs_it_before_a_deadline_at_l`, `an_invite_is_cancelled_and_acknowledged_during_a_shutdown`, every example | loopback, driver, example | both | covered |
| Work guards | design | A guard holds the drain until it drops. Guards are counted without a task each. | `a_uas_retransmits_its_2xx_under_a_guard_until_the_ack`, `work_guards_hold_a_drain_until_the_last_one_drops`, `the_last_guard_wakes_the_driver_without_a_command`, `examples/invite-uas` | loopback, driver, example | both | covered |
| Drained or DeadlineExpired | design | The earliest deadline ends a drain. What is left sees closed errors. | `the_earliest_deadline_ends_a_drain_held_by_a_guard`, `a_deadline_before_l_and_m_closes_the_observers`, `a_zero_timeout_drains_only_an_idle_endpoint`, `examples/invite-uas` (call 3) | loopback, example | both | covered |
| Teardown past the deadline | design | Tasks that end after the deadline without dropping output leave the outcome Drained. A writer aborted with output makes it DeadlineExpired. The future waits for every task either way. | `a_teardown_past_the_deadline_with_nothing_left_is_a_drain` (`driver.rs`), `abort_of_a_writer_with_nothing_left_discards_nothing`, `abort_stops_a_stalled_writer_and_fails_its_receipts` (`tcp.rs`), `the_deadline_aborts_a_stalled_tcp_writer` | driver, unit, loopback | TCP | covered |
| Routes and clones do not hold a drain | design | Only guards, machines and writes do. | `routes_and_clones_do_not_hold_a_drain_and_tcp_closes`, `unread_stateless_events_do_not_hold_a_drain` | loopback | both | covered |
| Protocol work during the drain | design | ACK, matched CANCEL, responders, reply routes and `send_request` keep working. New requests get 503. | `protocol_work_progresses_with_admission_full_during_a_shutdown`, `reply_routes_keep_sending_while_existing_work_drains`, `a_stateless_shutdown_keeps_committed_sends` | loopback | both | covered |

## Deliberate omissions

These are left out of 0.3.0 on purpose. They are not missing tests:

* Dialog and call state, 2xx ACK construction from route sets, UAS 2xx
  retransmission helpers, proxy Timer C and fork selection. The examples show
  them as TU code.
* PRACK (RFC 3262), session timers, authentication and media.
* Mixed stateful and stateless reception, and TCP stateless forwarding.
* RFC 2543 fallback matching, RFC 3263 discovery and failover, multicast, TLS
  and other transports.

## Measurements

Retained transaction state is measured by `scripts/tables`, with
`-m options|invite|reject` for what each transaction is and `-o` to keep the
TU's handles. Latency is measured by the Criterion benchmarks under
`endpoint/` in `bench/`. Neither is a correctness test, and both depend on the
machine they run on.
