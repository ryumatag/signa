# Memory retention in completed SIP transactions

I improved this in [#38], but I thought it was worth writing down what was
happening, what I changed, and what the measurements actually tell me.

The problem was that a transaction could finish its useful work and still keep
much more memory alive than it needed. Some state has to survive the final
response because SIP still has retransmissions to deal with. But that doesn't
mean everything used to process the original message has to survive with it.

This is about the non-INVITE transactions implemented here, such as `OPTIONS`.
INVITE transactions have different state machines and aren't covered by this
change.

[#38]: https://github.com/ryumatag/signa/pull/38

### Why a completed transaction still exists

Over UDP, receiving or sending the final response doesn't immediately remove
the transaction.

A non-INVITE server transaction stays in `Completed` for Timer J so it can
answer a retransmitted request with the same final response. A non-INVITE
client transaction stays in `Completed` for Timer K so it can absorb
retransmitted final responses without handing them to the application again.

With the defaults in [`Timers`], Timer J is 64 × T1, or 32 seconds, and Timer K
is T4, or 5 seconds. Over a reliable transport, these state machines terminate
immediately after the final response. That follows the non-INVITE transaction
behavior in [RFC 3261, sections 17.1.2 and 17.2.2].

So the number of requests currently waiting for a response isn't the same as
the number of transactions still in memory. Even with only 16 requests in
flight, completed transactions can accumulate much faster than their timers
expire.

I needed to keep the transaction identity and whatever state retransmissions
still require. The extra memory came from keeping other data alive for that
same lifetime.

[Timers]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/transaction/mod.rs#L44
[RFC 3261, sections 17.1.2 and 17.2.2]: https://www.rfc-editor.org/rfc/rfc3261.html#section-17.1.2

### How a small slice kept a large receive allocation alive

The UDP reader deliberately shares receive allocations across datagrams. In
[`src/transport/udp/mod.rs`], `MAX_DATAGRAM` is `u16::MAX`, and `CHUNK` is four
times that. That's 262,140 bytes, roughly 256 KiB.

After a receive, the reader returns the datagram with:

```rust
let datagram = buf.split_to(received.len).freeze();
```

Consecutive datagrams can share the same backing allocation. That avoids
allocating a separate buffer for every small SIP message.

The parser continues that sharing. [`parse::headers`] builds header values
through `HeaderValue::from_parsed`, which uses `src.slice_ref(...)` in
[`src/header/value.rs`].

That means a header containing only a few dozen bytes can still hold a
reference to the allocation that received the datagram. Dropping the message
doesn't free that allocation if a header value or transaction key still shares
it.

And it isn't one 256 KiB allocation per transaction. Several datagrams can
share one chunk, and any surviving slice can keep that chunk alive. The
allocation can only be released or reused once the remaining owners allow it.

Rust was keeping valid, reachable data alive exactly as requested. The
ownership lasted longer than the data was useful.

I found four places to change.

[`src/transport/udp/mod.rs`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/transport/udp/mod.rs
[`parse::headers`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/parse.rs#L196
[`src/header/value.rs`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/header/value.rs

#### 1. Give `ServerKey` its own small backing allocation

Before #38, `ServerKey` kept the top `Via` branch and sent-by host as slices
of the request's header value. The key lived in the server transaction table,
so those small slices could keep a receive chunk alive throughout Timer J.

In [`ServerKey::new`], I now concatenate the branch and host into one owned
byte buffer:

```rust
let text = Bytes::from([branch, via.host].concat());
```

The key stores that buffer and the branch length. Its accessors split the
buffer back into the branch and host.

This adds a copy and a small allocation when constructing a server key. In
return, the key's backing storage contains the text it actually needs,
independently of the request's receive allocation. Cloning the key shares that
small buffer.

The matching rules stay the same. Equality still checks the branch, port,
method, and ASCII case-insensitive host. The hash still covers the branch and
method.

There is also a focused test, `a_server_key_does_not_hold_the_message_buffer`,
which checks that the branch and host pointers are outside the original `Via`
value's range. That verifies the storage separation. It doesn't measure how
much process memory the change saves.

[`ServerKey::new`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/transaction/key.rs#L56

#### 2. Drop the server's copied request headers after the final response

Fixing the key alone wasn't enough.

`ServerTransaction` also kept the request headers needed to construct a
response. [`reply_headers`] clones the rows for `Via`, `From`, `To`, `Call-ID`,
and `CSeq`.

Those are five header names, rather than necessarily five rows. A request can
have more than one `Via` row, and the function preserves the matching rows.
Cloning a value also preserves its shared backing bytes, so these headers could
retain the request's receive chunk too.

The server needs them while a response is still being constructed. It uses them
for its automatic `100 Trying`, and the driver can use them to build a fallback
`500` if the service doesn't provide a usable response.

After the final response, the server already has the encoded response it needs
for retransmissions. It doesn't need the original request header map to build
it again.

In [`ServerTransaction`], I changed the stored headers to `Option<HeaderMap>`
and clear them when the final response is handled. The code also clears them
when a `408` terminates the transaction without being sent, and on a transport
error.

This changes the internal API. `headers()` now returns `Option<&HeaderMap>` and
returns `None` after the final response. The driver handles that explicitly
when considering a fallback response.

The encoded final response still remains in the UDP server's `Completed` state
until Timer J. That's the data required to answer retransmitted requests.

[`reply_headers`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/response.rs#L161
[`ServerTransaction`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/transaction/server.rs#L42

#### 3. Keep the encoded client request in the states that use it

The client had a separate retention problem. It stored the encoded request
directly in `ClientTransaction`, so the request stayed alive until the
transaction itself was dropped.

The request is needed for retransmissions in `Trying` and `Proceeding`. Once
the final response arrives, those retransmissions stop. Timer K exists to
absorb duplicate responses, so retaining the encoded request through Timer K
served no purpose.

I moved the request into the `Trying` and `Proceeding` variants of
[`client::State`]. `Completed` contains only its Timer K deadline.

[`client::State`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/transaction/client.rs#L60

Moving between `Trying` and `Proceeding` carries the request forward. Moving to
`Completed` or `Terminated` drops the old state's ownership of it.

This also releases the request on timeout and transport-error paths. Other
owners, such as a pending send, can still hold the same bytes, but the
transaction no longer retains them after it stops needing them.

This part is distinct from the receive-chunk problem. It removes an unnecessary
encoded outgoing request from every completed client transaction.

#### 4. Put the table's key in the timer heap

The last path was easy to miss because it lived outside the transaction state
machines.

When a response arrives, `ClientKey::from_response` makes a lookup key whose
branch is a slice of the received `Via`. That is useful for finding the
transaction without copying the branch.

Previously, `settle_client` could move that lookup key into the timer heap when
scheduling Timer K. Even after the application dropped the response, the heap
entry could keep its receive allocation alive.

The client table already had an equal key with different backing storage. The
endpoint creates that key from the outgoing request's locally generated `Via`,
which has a small allocation of its own.

I changed [`settle_client`] and [`settle_server`] to use `get_key_value` and
clone the key stored in the table when scheduling a timer.

That distinction matters. Two keys can compare equal while keeping completely
different allocations alive. Cloning the response-derived lookup key would
preserve the retention problem. Cloning the stored key gives the heap the
backing storage intended to live with the transaction.

I left `ClientKey` itself as a shared slice. The endpoint's stored client key
is already backed by a small locally built `Via`, and the received lookup key
can be dropped after the lookup. Copying every client lookup key would add work
without being necessary for this fix.

[`settle_client`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/endpoint/driver.rs#L569
[`settle_server`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/src/endpoint/driver.rs#L550

### What I measured

I used the temporary [`examples/tables.rs`] example to make completed
transactions accumulate.

It runs two UDP endpoints in one process on a current-thread Tokio runtime. One
endpoint answers each `OPTIONS` with `200 OK`. Sixteen client tasks each send
requests sequentially, giving a maximum of 16 requests awaiting responses at
once.

The example uses the default RFC timer values and raises the client transaction
limit so the run can retain a large number of completed transactions.

For the 200,000-round-trip comparison, I recorded:

| Measurement | Before | After |
| --- | ---: | ---: |
| Maximum RSS | 881 MB | 517 MB |
| Approximately 256 KiB blocks reported by `heap -s` | 289 | 2 |
| Elapsed time divided by completed round trips | 11.2 µs | 10.0 µs |

At those timings, the request loop took roughly 2.2 seconds before the change
and 2.0 seconds after it. That is shorter than both Timer K and Timer J, which
is why completed transactions could still be present on both sides when the
request loop finished.

The timing here is total elapsed time divided by the number of round trips.
With 16 requests in flight, it shouldn't be read as the latency of an
individual request.

Maximum RSS fell by 364 MB, about 41%. The large-block count also fell sharply,
which is consistent with removing the references that pinned receive chunks.

Those two observations don't provide a complete memory breakdown. The
difference of 287 blocks at 256 KiB each is about 71.75 MiB, so that block
count alone doesn't explain the whole RSS change. The measurements also cover
different things: maximum RSS is a process high-water mark, while `heap -s`
reports the heap at the time it is sampled. The dropped request buffers, header
storage, allocator behavior, and other live allocations can also matter. I
don't have enough information here to assign an exact share of the RSS
reduction to each change.

The example optionally waits for 20 seconds so the process can be inspected
with `heap`. The endpoint keeps running during that wait, so timer expiry
continues too. In particular, a late sample can be taken after the client
transactions have expired. That makes the sampling point part of the
experiment.

[`examples/tables.rs`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/examples/tables.rs

### The cost of copying the server key

The [`transaction/non_invite/server_key` benchmark] went from 34.5 ns to 51.1
ns, an increase of 16.6 ns per key construction.

That is a real local cost. The benchmark includes constructing the key and its
equality check, so I treat the difference as the observed cost of the changed
path rather than an isolated measurement of the copy instruction.

I accepted that cost to give long-lived server keys appropriately sized backing
storage.

I also compared the existing endpoint round-trip benchmarks against `main` on
the same laptop:

| Benchmark | Before | After |
| --- | ---: | ---: |
| UDP loopback round trip | 36.4 µs | 35.9 µs |
| TCP loopback round trip | 27.6 µs | 27.5 µs |

I treat those as essentially unchanged. The point estimates don't show a
meaningful regression, but they aren't enough to claim a statistically
established speedup.

These benchmarks answer a different question from the accumulation example.
[`bench/src/endpoint.rs`] deliberately uses shorter timers to keep the tables
at a steadier size during repeated measurements. The accumulation example keeps
the default timers so the memory retained by completed transactions becomes
visible.

The lower elapsed time in the accumulation run is useful to record, but all
four changes were applied together. It doesn't tell me which change caused that
timing difference.

[`transaction/non_invite/server_key` benchmark]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/bench/src/transaction.rs
[`bench/src/endpoint.rs`]: https://github.com/ryumatag/signa/blob/2e9dd251e7d79f1993dc8c4f289494bdc70e757a/bench/src/endpoint.rs

### Why I kept the timer heap

The driver uses a `BinaryHeap` of deadlines. When a transaction's deadline
changes, it adds another entry. Old entries remain until they are popped, and
the transaction checks its current state and deadline when the driver processes
them.

I kept that design.

For the accumulation example, I recorded:

| Round trips | Elapsed time per round trip |
| --- | ---: |
| 50,000 | 10.2 µs |
| 200,000 | 9.9 µs |
| 600,000 | 10.5 µs |

I didn't see a clear growth in average time that justified replacing the heap
as part of this change.

That doesn't show that heap operations are free, or that every transaction
remains resident at every scale. The 600,000-round-trip run takes about 6.3
seconds at the reported rate, so early client transactions can already pass
Timer K during that run. These are measurements of the workload as it runs,
including timer processing.

The remaining table and entry layout is a separate optimization to investigate.
Completed server transactions also still need their encoded final responses. I
wouldn't describe the remaining 517 MB as entirely waste, or attribute it all
to table layout without a more detailed profile.

The main thing I wanted to preserve from this work is the ownership boundary.
Sharing receive bytes is useful while parsing and processing a message. Once a
small piece of that message enters a transaction table or timer heap, the
lifetime changes.

In this case, copying a small server key, dropping data at the relevant state
transition, and choosing the right existing key for timer entries removed
substantial retention while keeping the required SIP behavior.
