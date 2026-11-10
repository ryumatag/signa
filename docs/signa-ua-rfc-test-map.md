# signa-ua RFC and contract test map

This maps each requirement signa-ua takes on, and each decision of its design,
to the tests that show it. signa-core's map is [rfc-test-map.md]. A section
link names the rule a test checks. It is not a claim that signa-ua implements
the whole section, and nothing here claims conformance to an RFC as a whole.
Rows whose basis is design or signa-ua policy are decisions of this crate, not
RFC rules.

signa-ua has an early public API, the runtime, which drives the private state
model on a signa-core endpoint. Many rows below are not implemented yet.

Test names are the function names, and the file says where to find them.

[rfc-test-map.md]: rfc-test-map.md

## Reading the table

Type is where the evidence runs. Paths are in `crates/signa-ua/`:

* model: the state model driven by inputs, with a fake clock and
  deterministic randomness, in `src/model.rs`.
* unit: a test of one module's functions, inline in that module.
* build: the compiler checks it on every build.
* loopback: a UA through its public API, against raw UDP peers on loopback,
  in `tests/ua.rs`.

Status:

* covered: the behavior is tested on the transports listed.
* partial: tested, with the limit stated.
* not implemented: nothing tests it yet.

The Scope column names transports. The model tests use none, so they show a
rule of state, not of a wire exchange.

## Invariants

These hold across the whole UA core, whatever the message.

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Transactions are the core's | [6026 §7](https://www.rfc-editor.org/rfc/rfc6026.html#section-7), design | The UA keeps no transaction state or timer A to M, and acts on what the core reports. The model has no such timer. | none | - | - | not implemented |
| One writer | design | Only the driver changes UA state, through the model. Handles hold no state, and the application never holds a responder or client transaction. | `observer_drop_does_not_drop_responder_or_client_control`, `single_incoming_owner` | loopback | UDP | covered |
| Dialog identity | [3261 §12](https://www.rfc-editor.org/rfc/rfc3261.html#section-12) | A dialog is its Call-ID with a local and a remote tag, never the Call-ID alone. Each side names the tags from itself, and swapped tags are another dialog. | `each_side_names_the_tags_and_uris_from_itself` (`dialog.rs`), `a_tagged_request_finds_its_dialog`, `an_unknown_ack_changes_nothing` | unit, model | - | partial: the model only, not on the wire |
| A copy of a 2xx is not a new session | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | A 2xx with the dialog and INVITE CSeq of one seen before gets the ACK again and no new usage, also after the usage ended. | `usage_termination_does_not_destroy_needed_replay` | model | - | partial: the model only, not on the wire |
| Every 2xx gets its ACK | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | Each new 2xx the UA can hold leaves an ACK to send. | `usage_termination_does_not_destroy_needed_replay` | model | - | partial: a branch beyond the limits gets no ACK yet |
| A sent ACK does not change | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4), design | The ACK of a 2xx is fixed when first sent and reused for its copies. | none | - | - | not implemented |
| UAS 2xx retransmission | [3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4), [6026 §7.1](https://www.rfc-editor.org/rfc/rfc6026.html#section-7.1) | The 2xx is retransmitted on UDP and TCP until its ACK or deadline. | none | - | - | not implemented |
| CANCEL success is not INVITE failure | [3261 §9](https://www.rfc-editor.org/rfc/rfc3261.html#section-9) | A 200 to CANCEL ends neither the INVITE nor the session. | none | - | - | not implemented |
| One final per UAS exchange | design | An exchange takes one final. A competing accept gets `AlreadyFinalized` and sends nothing. | `one_final_at_a_time` (`invite.rs`), `a_losing_or_stale_decision_has_no_wire_effect` | unit, model | - | partial: no CANCEL or timeout race yet |
| Local CSeq | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1) | One counter per dialog, with ACK and CANCEL on their INVITE's number. | `ack_and_cancel_do_not_allocate_new_dialog_cseq`, `confirmed_transition_preserves_sequence_history` (`dialog.rs`) | unit | - | partial: the model only, not on the wire |
| Target refresh apart from negotiation | [6141 §3.3 to 3.5](https://www.rfc-editor.org/rfc/rfc6141.html#section-3.3) | A failed re-INVITE does not roll the target back with the session. | none | - | - | not implemented |
| One offer at a time | [3264 §4](https://www.rfc-editor.org/rfc/rfc3264.html#section-4) | A dialog with an offer outstanding refuses another offer, in either direction. | `offers_and_answers_alternate`, `a_second_offer_waits_for_the_first_answer`, `an_answer_needs_an_offer_from_the_other_side` (`negotiation.rs`) | unit | - | partial: state only, not tied to messages yet |
| Dropping is not CANCEL or BYE | design | Dropping an operation, session, attempt or the events sends nothing and withdraws nothing. An undecided INVITE dropped gets a 500, by signa-ua policy. | `accepted_command_survives_waiter_drop`, `waiting_operation_drop_does_not_withdraw_accepted_command`, `observer_drop_does_not_drop_responder_or_client_control`, `an_undecided_invite_gets_a_500_and_a_rejected_one_its_status` | model, loopback | UDP | covered |
| Protocol work goes on when the application stalls | design | Neither a full event queue nor a slow resolution stops the driver. Each send and resolution runs as a job of its own. | `slow_resolver_does_not_block_other_dialog_ack`, `terminal_outcome_survives_notification_overflow` | loopback | UDP | partial: no timers yet |
| Everything held is bounded | design | Each table has a limit. A full table refuses new work and hands it back, and the slots a 2xx needs are reserved before it goes out. | `a_full_table_hands_the_value_back`, `a_reservation_keeps_its_slot` (`slot.rs`), `no_2xx_without_room_for_its_session`, `unsent_busy_command_preserves_decision_authority`, `an_unwatched_outcome_is_kept_for_the_retention_time` (`operation.rs`) | unit, model | - | partial: counts only, no byte budgets or timer limits yet |
| Terminal outcomes are not telemetry | design | An outcome is set once and reaches its operation apart from notifications. A notification that does not fit is counted and reported. | `the_first_outcome_sticks` (`operation.rs`), `accepted_command_survives_waiter_drop`, `terminal_outcome_survives_notification_overflow` | unit, model, loopback | UDP | covered |
| Nothing is sent after shutdown | design | Once shutdown completes, no UA task or timer sends. | none | - | - | not implemented |
| `Drained` claims local work only | design | `Drained` says local work ended, not that the peer got anything. | none | - | - | not implemented |
| Only the core's public API | design | signa-ua uses no private item of signa-core, and does not turn on its `__bench` feature. | the crate boundary, and `crates/signa-ua/Cargo.toml` | build | - | covered |
| Protocol rules apart from policy | design | Each row of this map names an RFC rule or a local decision as its basis. | this map | - | - | partial: no rows for wire behavior yet |

## Dialogs and routing (RFC 3261 sections 8.1.2, 12 and 13.2.2.4)

Unless a row says otherwise, these are unit tests in `src/dialog.rs`,
`src/routing.rs` and `src/protocol/`, and model tests in `src/model.rs`.

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Header elements | [3261 §25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1), [3261 §20](https://www.rfc-editor.org/rfc/rfc3261.html#section-20) | Contact, Route and Record-Route split into addresses by the grammar, so a comma in a quoted display name or parameter, or in angle brackets, does not split them. URI parameters stay with the URI, rows and comma lists are one list, folds are whitespace, and IPv6 references survive. | `quoted_comma_does_not_split_address`, `uri_parameters_stay_with_the_uri`, `an_addr_spec_ends_at_its_parameters`, `ipv6_references_survive`, `display_names_come_in_both_forms`, `folds_are_whitespace`, `rejects_what_is_not_a_list_of_addresses` | unit | - | covered |
| From, To, Call-ID and CSeq | [3261 §25.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-25.1), [3261 §20.8](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.8), [3261 §20.16](https://www.rfc-editor.org/rfc/rfc3261.html#section-20.16) | Each appears once. The Call-ID is kept byte for byte, a tag inside a URI is not the header tag, and a repeated or valueless tag is malformed. | `call_ids_are_kept_as_written`, `parties_carry_their_uri_and_tag`, `a_tag_inside_the_uri_is_not_the_header_tag`, `an_ambiguous_tag_is_malformed`, `cseq_has_a_number_and_a_method` | unit | - | covered |
| Contact of a dialog | [3261 §8.1.1.8](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.8), [3261 §12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1) | A request or response that forms a dialog has exactly one SIP or SIPS Contact URI. An INVITE without one gets a 400 before the application sees it. | `contact_holds_one_uri`, `a_dialog_needs_one_sip_contact`, `an_invite_without_contact_is_refused` | unit, model | - | covered |
| Dialog state of each side | [3261 §12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1), [3261 §12.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.2) | A UAS and a UAC take the URIs, tags, target and CSeq numbers from their own side. A peer without a tag has a null remote tag. | `each_side_names_the_tags_and_uris_from_itself`, `a_peer_without_a_tag_has_a_null_remote_tag` | unit | - | covered |
| Route set order | [3261 §12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1), [3261 §12.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.2) | A UAS keeps the Record-Route order and a UAC reverses it, both with every URI parameter, across rows and comma lists. Only bracketed SIP or SIPS URIs are taken. | `uac_reverses_record_route_uas_preserves_order`, `rows_and_lists_both_add_routes`, `record_route_needs_bracketed_sip_uris` | unit | - | covered |
| Route set length | signa-ua policy | A route set longer than the limit is refused, with a 500 for an INVITE. | `route_sets_are_bounded`, `a_long_route_set_is_refused` | unit | - | covered |
| Loose routing | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1) | The remote target is the Request-URI, and the route set is the Route. Without a route set there is no Route. | `loose_router_keeps_remote_target_as_request_uri`, `an_empty_route_set_sends_to_the_remote_target`, `requests_carry_the_dialog_state` | unit | - | covered |
| Strict routing | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1), [3261 §19.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-19.1.1) | The first route becomes the Request-URI without the parts Table 1 disallows there, and the remote target goes last in Route. | `strict_router_moves_remote_target_to_route_tail`, `the_request_uri_drops_what_it_does_not_allow` | unit | - | covered |
| Requests in a dialog | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1), [3261 §8.1.1.6](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.6) | To, From, Call-ID, CSeq, Max-Forwards and Route come from the dialog, with To and From normalized to the URI and tag. | `requests_carry_the_dialog_state` | unit | - | covered |
| Confirming an early dialog | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4), [6141 §4.9](https://www.rfc-editor.org/rfc/rfc6141.html#section-4.9) | A 2xx recomputes the route set and replaces the target, and the CSeq numbers stay. A failed confirmation changes nothing. | `confirmed_transition_preserves_sequence_history`, `a_failed_confirmation_changes_nothing`, `an_unreliable_provisional_does_not_refresh_the_target` | unit, model | - | covered |
| Unreliable provisional responses | [6141 §4.7](https://www.rfc-editor.org/rfc/rfc6141.html#section-4.7), [§4.9](https://www.rfc-editor.org/rfc/rfc6141.html#section-4.9) | A 101 to 199 with a To tag forms an early dialog. A later one refreshes neither target nor route set. | `an_unreliable_provisional_does_not_refresh_the_target` | model | - | covered |
| Forked 2xx | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | A 2xx with a new tag forms a confirmed dialog of its own. | `a_fork_forms_a_dialog_of_its_own` | model | - | partial: a branch that does not fit gets no ACK or BYE yet |
| Target refresh | [3261 §12.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2), [6141 §4.7](https://www.rfc-editor.org/rfc/rfc6141.html#section-4.7) | A refresh replaces the remote target and leaves the route set. A Contact that is not SIP or SIPS leaves the old target. | `target_refresh_keeps_the_route_set` (`routing.rs`), `a_contact_refresh_keeps_the_route_set` (`dialog.rs`) | unit | - | partial: no re-INVITE yet |
| Remote CSeq | [3261 §12.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.2) | A gap is accepted and a lower number rejected. An equal number from a new transaction is rejected too, by signa-ua policy. | `cseq_gap_is_accepted_lower_value_is_rejected` | unit | - | covered |
| Local CSeq | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1), [3261 §8.1.1.5](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.1.5) | ACK and CANCEL take the INVITE's number. The first number of a UAS is below 2^16, and no number reaches 2^31. | `ack_and_cancel_do_not_allocate_new_dialog_cseq`, `a_uas_picks_its_first_number_below_2_16`, `cseq_stops_below_2_31` | unit | - | covered |
| Tagged request without a dialog | [3261 §12.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.2) | A request with a To tag that matches no dialog gets a 481. It is not a new call. | `unknown_tagged_request_is_not_new_initial_invite`, `a_tagged_request_finds_its_dialog` | model | - | covered |
| Next hop | [3261 §8.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.2), [3263 §4](https://www.rfc-editor.org/rfc/rfc3263.html#section-4), [§4.1](https://www.rfc-editor.org/rfc/rfc3263.html#section-4.1) | The first Route value, or the Request-URI after a strict router or without a route set, is resolved. `maddr` stands for the host, `transport` picks UDP or TCP, and the default is UDP on port 5060. A host name resolves only from the table given. | `literals_resolve_with_their_transport_and_port`, `an_unmapped_hostname_is_not_resolved` | unit | - | partial: no DNS, so RFC 3263 is not implemented |
| Large requests | [3261 §18.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-18.1.1) | A request over 1300 bytes leaves UDP for TCP. | `a_large_request_leaves_udp` | unit | - | covered |
| SIPS | [3261 §26.2.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-26.2.2), [3261 §8.1.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.1.2), [5630 §5.1.1](https://www.rfc-editor.org/rfc/rfc5630.html#section-5.1.1) | A SIPS Request-URI or next hop needs a secured first hop, and is never sent over plain UDP or TCP. | `sips_requirement_never_falls_back_to_plaintext` | unit | - | covered: there is no TLS, so it is always refused |

## Runtime (design)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| One receiver | design | The UA takes the endpoint's only receiver, and refuses a stateless endpoint. | `single_incoming_owner` | loopback | - | covered |
| Admission | design | A submission beyond the command queue or the operations gets `Busy` and its value back, and sends nothing. | `command_queue_full_returns_busy_without_state_mutation`, `an_invalid_rejection_hands_the_invite_back` | loopback | UDP | covered |
| Hung resolver | design | A resolution past its timeout counts as unresolved and frees its job, so finals and ACKs still get out. | `a_hung_resolver_gives_up_and_frees_its_job` | loopback | UDP | covered |
| Forced stop | design | Dropping the driver stops the UA and its endpoint at once. Operations in flight fail with `DriverStopped`, and the handle takes nothing more. | `driver_drop_is_forced_stop_not_graceful_shutdown` | loopback | UDP | covered |
| ACK before the commit | [3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4), design | An ACK that reaches the driver before the core's verdict on its 2xx is kept and applied after it. | `an_ack_before_the_commit_is_not_lost` | model | - | covered |
| Refusing an INVITE | [3261 §8.2.6.2](https://www.rfc-editor.org/rfc/rfc3261.html#section-8.2.6.2), [§21.5.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-21.5.4), signa-ua policy | An INVITE the UA has no room for gets a 503, one that cannot form a dialog a 400, each with a To tag. | `an_invite_without_contact_is_refused`, `no_randomness_refuses_the_invite` | model | - | partial: the 503 is not tested on the wire |
| The UAS 2xx | [3261 §12.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1.1) | The 2xx copies the request's Record-Route and carries the UA's Contact. | `waiting_operation_drop_does_not_withdraw_accepted_command` | loopback | UDP | partial: no session description yet |
| The ACK of a 2xx | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | The UAC sends the ACK of each 2xx to the dialog's next hop, numbered as the INVITE. | `observer_drop_does_not_drop_responder_or_client_control`, `an_ack_is_built_from_its_dialog` | loopback, model | UDP | partial: no answer in the ACK yet |
| Failed INVITE | [3261 §12.3](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.3) | A non-2xx final ends the attempt's early dialogs, and a 2xx from another fork still forms a dialog. | `a_failure_ends_the_early_dialogs_of_its_attempt` | model | - | covered |

## State model contracts (design)

| Requirement | Basis | Expected behavior | Evidence | Type | Scope | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Stale keys | design | A key whose record was removed finds nothing, also after its slot is reused. A slot whose generation runs out is not reused. | `stale_generation_cannot_mutate_reused_slot`, `a_slot_whose_generation_runs_out_is_retired` (`slot.rs`), `a_losing_or_stale_decision_has_no_wire_effect` | unit, model | - | covered |
| Confirmed is not acknowledged | [3261 §12.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.1), [§13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4) | A 2xx confirms the dialog. The ACK is still awaited and the offer in the 2xx still open, until the ACK arrives. | `dialog_confirmed_is_not_ack_received_or_media_ready` | model | - | covered |
| Replay outlives the usage | [6026 §7.2](https://www.rfc-editor.org/rfc/rfc6026.html#section-7.2), design | Ending a usage keeps what copies of its 2xx need, until the core stops collecting responses. | `usage_termination_does_not_destroy_needed_replay`, `retention_follows_the_duplicates_not_the_usage`, `a_live_usage_does_not_keep_a_finished_context` (`retention.rs`) | model, unit | - | covered |
| Admission returns what it refuses | design | A refused command comes back whole, with the authority to decide its INVITE, and changes nothing. | `unsent_busy_command_preserves_decision_authority` | model | - | covered |
| Admission is the commit point | design | A dropped waiter neither withdraws the command nor loses its outcome before the retention time. | `accepted_command_survives_waiter_drop`, `an_unwatched_outcome_is_kept_for_the_retention_time` | model, unit | - | covered |
| Progress stages | design | An operation's stage only moves forward, from admitted to committed, written and answered. | `stages_only_move_forward` (`operation.rs`) | unit | - | covered |
| Errors state their wire effect | design | Only a response from the peer proves delivery. A refused or stale command sends nothing. | `only_a_response_proves_delivery` (`error.rs`) | unit | - | covered |
| Unknown ACK | design | An ACK that matches no 2xx changes nothing and gets no response. | `an_unknown_ack_changes_nothing` | model | - | partial: no matching by parsed headers yet |
| `dialog` does not refer to `invite` | [5057 §3](https://www.rfc-editor.org/rfc/rfc5057.html#section-3), design | Dialog state can serve other usages. | `dialog_does_not_refer_to_invite` (`lib.rs`) | unit | - | covered |
| Injected time and randomness | design | Tags come from the injected source. Retention follows the injected clock. | `tags_come_from_the_injected_randomness`, `accepted_command_survives_waiter_drop` | model | - | covered |
