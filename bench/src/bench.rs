use criterion::{Bencher, Criterion, Throughput};

mod encode;
mod endpoint;
mod frame;
mod header_map;
mod header_name;
mod header_value;
mod message;
mod method;
mod reason;
mod transaction;
mod transport;
mod uri;
mod via;

// I `assert_eq!` on every benchmark iteration. For the argument behind
// this choice, see the linked jiff issue comment.
// https://github.com/BurntSushi/jiff/issues/38#issuecomment-2250207870

criterion::criterion_group! {
    name = benches;
    config = criterion::Criterion::default()
        .configure_from_args()
        .sample_size(200)
        .warm_up_time(std::time::Duration::from_secs(1))
        .measurement_time(std::time::Duration::from_secs(3));
    targets =
        // Whole messages. Judge changes by these.
        message::parse,
        encode::encode,
        // The stream decoder and the protocol layer's header parsers, through
        // the `__bench` feature.
        frame::stream,
        via::parse,
        header_map::prepend,
        transaction::non_invite,
        transaction::invite,
        // Loopback round trips through the transports, on a current-thread
        // runtime. These include the syscalls.
        transport::udp,
        transport::tcp,
        // The same round trips between two endpoints, which adds the
        // transactions, the service, and the message layer on both sides.
        endpoint::round_trip,
        // One value at a time. These cover the checks that will move to
        // siparse, so they show what the switch changes for each type.
        header_name::from_bytes,
        header_value::from_shared,
        method::from_bytes,
        reason::from_bytes,
        uri::from_bytes,
}

criterion::criterion_main!(benches);

/// Defines a Criterion benchmark for the given function.
///
/// `throughput_bytes` counts the bytes of the input being converted. For
/// whole-message benchmarks, that is the whole message.
///
/// This helper keeps Criterion settings in one place.
///
/// Borrowing this style from the `jiff-bench` crate.
fn benchmark(
    c: &mut Criterion,
    id: impl AsRef<str>,
    throughput_bytes: u64,
    f: impl FnMut(&mut Bencher<'_>),
) {
    // Criterion exposes throughput on `BenchmarkGroup`, not on the bare
    // `bench_function`. I split the slashed id into a group prefix and a
    // function name. For an id like `parse/request/typical`, the group
    // becomes `parse` and the function becomes `request/typical`. Criterion
    // concatenates the two back to `parse/request/typical` for display.
    let id = id.as_ref();
    let (group, fn_id) = id.split_once('/').unwrap_or(("bench", id));
    c.benchmark_group(group)
        .throughput(Throughput::Bytes(throughput_bytes))
        .bench_function(fn_id, f);
}
