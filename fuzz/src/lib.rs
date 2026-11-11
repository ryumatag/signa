/*!
Fuzz targets for signa-ua, through the entry points of its unstable
`__fuzz` feature.

`headers` runs one request through the readers of the headers the UA
interprets and through the model's classification. `messages` feeds a
series of requests to the state model, with an application that decides
each INVITE by a byte of the input, and checks that a termination leaves
the model at rest. Its input is records of a byte of choice, two bytes of
length and a request, which the seeds in `corpus/messages` show. The
rustdoc of `signa_ua::fuzz::messages` says what each bit of the choice
does: how the application decides, whether the runtime's jobs fail, and
how much time passes.

A run writes the inputs it finds to a scratch directory, so that the
tracked seeds stay small:

```text
mkdir -p tmp/fuzz-headers tmp/fuzz-messages
cargo +nightly fuzz run headers \
    tmp/fuzz-headers fuzz/corpus/headers -- \
    -max_total_time=300 -max_len=4096
cargo +nightly fuzz run messages \
    tmp/fuzz-messages fuzz/corpus/messages -- \
    -max_total_time=300 -max_len=8192
```
*/
