//! Unit-style tests for neton's pure parsers and the piped-stdin merge contract.
//!
//! These exercise the library's public pure functions directly (no server) and
//! focus on edge / hostile inputs that were not already covered by the inline
//! `#[cfg(test)]` suites: whitespace tolerance, range boundaries, numeric
//! overflow and JSON type confusion. They live in `tests/` so the added coverage
//! ships as an isolated, add-only test directory.

use neton::cli::{MergeStdin, PingArgs, ProbeArgs};
use neton::dispatch::{dispatch, DispatchError};
use neton::scan::{parse_cidr, parse_port_spec};
use serde_json::json;

#[test]
fn port_spec_tolerates_outer_whitespace_and_dedupes_ranges() {
    // Whole entries are trimmed; a range's own bounds must not contain spaces
    // (the parser does not trim inside "from-to").
    assert_eq!(
        parse_port_spec(" 80 , 443-445 ").unwrap(),
        vec![80, 443, 444, 445]
    );
    // A degenerate range whose bounds are equal is a single port.
    assert_eq!(parse_port_spec("443-443").unwrap(), vec![443]);
    // Empty segments (double comma) are filtered, not a hard error.
    assert_eq!(parse_port_spec("1,,2").unwrap(), vec![1, 2]);
    // A space inside the range bounds is rejected, not silently tolerated.
    assert!(parse_port_spec("443 - 445").is_err());
}

#[test]
fn port_spec_rejects_numeric_overflow_and_injection_strings() {
    assert!(parse_port_spec("65536").is_err(), "65536 is beyond u16::MAX");
    assert!(parse_port_spec("80; rm -rf /").is_err(), "shell payload must not parse");
    assert!(
        parse_port_spec("../../etc/passwd").is_err(),
        "path-traversal string must not parse"
    );
    assert!(parse_port_spec("-").is_err(), "bare dash is not a range");
}

#[test]
fn cidr_trims_input_and_rejects_bad_prefix() {
    assert_eq!(
        parse_cidr("  10.0.0.0/8  ").unwrap(),
        ("10.0.0.0".parse().unwrap(), 8)
    );
    assert!(parse_cidr("10.0.0.0/abc").is_err(), "non-numeric prefix");
    assert!(parse_cidr("10.0.0.0/").is_err(), "empty prefix");
}

#[test]
fn probe_stdin_merge_rejects_array_of_non_strings() {
    let mut args = ProbeArgs::default();
    assert!(
        args.merge_stdin(&json!({ "targets": ["ok:1", 2] })).is_err(),
        "numeric array item must be a type error, not coerced"
    );
}

#[test]
fn ping_stdin_merge_rejects_string_when_u16_expected() {
    let mut args = PingArgs::default();
    assert!(
        args.merge_stdin(&json!({ "port": "443" })).is_err(),
        "a string port must not be silently accepted"
    );
}

#[test]
fn dispatch_rejects_negative_and_oversized_numbers() {
    // A negative number has no u64 representation.
    let err = dispatch(&json!({ "action": "ping", "host": "x", "port": -1 })).unwrap_err();
    assert!(
        matches!(err, DispatchError::BadParams(_)),
        "negative port must be a BadParams, never a panic"
    );
    // 2^32 overflows u32 for the pid filter.
    let err = dispatch(&json!({ "action": "ports", "pid": 4294967296u64 })).unwrap_err();
    assert!(matches!(err, DispatchError::BadParams(_)));
}

#[test]
fn dispatch_rejects_wrong_typed_params() {
    let err = dispatch(&json!({ "action": "probe", "targets": 12345 })).unwrap_err();
    assert!(matches!(err, DispatchError::BadParams(_)));
    let err = dispatch(&json!({ "action": "ports", "pid": "9000" })).unwrap_err();
    assert!(matches!(err, DispatchError::BadParams(_)));
}
