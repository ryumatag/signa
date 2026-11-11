#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| signa_ua::fuzz::messages(input));
