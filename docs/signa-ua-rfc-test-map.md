# signa-ua RFC and contract test map

This maps each requirement signa-ua takes on, and each decision of its design,
to the tests that show it. signa-core's map is [rfc-test-map.md]. A section
link names the rule a test checks. It is not a claim that signa-ua implements
the whole section, and nothing here claims conformance to an RFC as a whole.
Rows whose basis is design or signa-ua policy are decisions of this crate, not
RFC rules.

signa-ua has no public API yet. What exists is the private state model, and
most rows below are not implemented.

Test names are the function names, and the file says where to find them.

[rfc-test-map.md]: rfc-test-map.md

## Reading the table

Type is where the evidence runs. Paths are in `crates/signa-ua/`:

* model: the state model driven by inputs, with a fake clock and
  deterministic randomness, in `src/model.rs`.
* unit: a test of one module's functions, inline in that module.
* build: the compiler checks it on every build.

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
| One writer | design | Only the model changes UA state. Handles hold no mutable state. | none | - | - | not implemented |
| Dialog identity | [3261 §12](https://www.rfc-editor.org/rfc/rfc3261.html#section-12) | A dialog is its Call-ID with a local and a remote tag, never the Call-ID alone. Swapped tags are another dialog. | `the_tags_keep_their_sides` (`dialog.rs`), `an_unknown_ack_changes_nothing` | unit, model | - | partial: no header parsing yet |
| A copy of a 2xx is not a new session | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | A 2xx with the dialog and INVITE CSeq of one seen before gets the ACK again and no new usage, also after the usage ended. | `usage_termination_does_not_destroy_needed_replay` | model | - | partial: the model only, not on the wire |
| Every 2xx gets its ACK | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4) | Each new 2xx the UA can hold leaves an ACK to send. | `usage_termination_does_not_destroy_needed_replay` | model | - | partial: a branch beyond the limits gets no ACK yet |
| A sent ACK does not change | [3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.2.2.4), design | The ACK of a 2xx is fixed when first sent and reused for its copies. | none | - | - | not implemented |
| UAS 2xx retransmission | [3261 §13.3.1.4](https://www.rfc-editor.org/rfc/rfc3261.html#section-13.3.1.4), [6026 §7.1](https://www.rfc-editor.org/rfc/rfc6026.html#section-7.1) | The 2xx is retransmitted on UDP and TCP until its ACK or deadline. | none | - | - | not implemented |
| CANCEL success is not INVITE failure | [3261 §9](https://www.rfc-editor.org/rfc/rfc3261.html#section-9) | A 200 to CANCEL ends neither the INVITE nor the session. | none | - | - | not implemented |
| One final per UAS exchange | design | An exchange takes one final. A competing accept gets `AlreadyFinalized` and sends nothing. | `one_final_at_a_time` (`invite.rs`), `a_losing_or_stale_decision_has_no_wire_effect` | unit, model | - | partial: no CANCEL or timeout race yet |
| Local CSeq | [3261 §12.2.1.1](https://www.rfc-editor.org/rfc/rfc3261.html#section-12.2.1.1) | One counter per dialog, with ACK and CANCEL on their INVITE's number. | none | - | - | not implemented |
| Target refresh apart from negotiation | [6141 §3.3 to 3.5](https://www.rfc-editor.org/rfc/rfc6141.html#section-3.3) | A failed re-INVITE does not roll the target back with the session. | none | - | - | not implemented |
| One offer at a time | [3264 §4](https://www.rfc-editor.org/rfc/rfc3264.html#section-4) | A dialog with an offer outstanding refuses another offer, in either direction. | `offers_and_answers_alternate`, `a_second_offer_waits_for_the_first_answer`, `an_answer_needs_an_offer_from_the_other_side` (`negotiation.rs`) | unit | - | partial: state only, not tied to messages yet |
| Dropping is not CANCEL or BYE | design | Dropping a waiter or handle sends nothing and withdraws nothing. | `accepted_command_survives_waiter_drop` | model | - | partial: operation waiters only, no public handles yet |
| Protocol work goes on when the application stalls | design | A full application queue stops neither core events nor timers. | none | - | - | not implemented |
| Everything held is bounded | design | Each table has a limit. A full table refuses new work and hands it back, and the slots a 2xx needs are reserved before it goes out. | `a_full_table_hands_the_value_back`, `a_reservation_keeps_its_slot` (`slot.rs`), `no_2xx_without_room_for_its_session`, `unsent_busy_command_preserves_decision_authority`, `an_unwatched_outcome_is_kept_for_the_retention_time` (`operation.rs`) | unit, model | - | partial: counts only, no byte budgets or timer limits yet |
| Terminal outcomes are not telemetry | design | An outcome is set once and kept in the operation's record, apart from notifications. | `the_first_outcome_sticks` (`operation.rs`), `accepted_command_survives_waiter_drop` | unit, model | - | partial: no notification queue yet |
| Nothing is sent after shutdown | design | Once shutdown completes, no UA task or timer sends. | none | - | - | not implemented |
| `Drained` claims local work only | design | `Drained` says local work ended, not that the peer got anything. | none | - | - | not implemented |
| Only the core's public API | design | signa-ua uses no private item of signa-core, and does not turn on its `__bench` feature. | the crate boundary, and `crates/signa-ua/Cargo.toml` | build | - | covered |
| Protocol rules apart from policy | design | Each row of this map names an RFC rule or a local decision as its basis. | this map | - | - | partial: no rows for wire behavior yet |

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
