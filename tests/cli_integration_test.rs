//! Integration tests for the ejson2env CLI.

use std::io::Write;
use std::process::{Command, Stdio};

const TEST_KEY_VALUE: &str = "2ed65dd6a16eab833cc4d2a860baa60042da34a58ac43855e8554ca87a5e557d";

fn run_ejson2env(args: &[&str], stdin_input: Option<&str>) -> (String, String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ejson2env"));
    cmd.args(args);

    if stdin_input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("Failed to spawn command");

    if let Some(input) = stdin_input {
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(input.as_bytes())
                .expect("Failed to write to stdin");
        }
    }

    let output = child.wait_with_output().expect("Failed to wait on child");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let success = output.status.success();

    (stdout, stderr, success)
}

// Tests for --trim-underscore-prefix (strips only first underscore)

#[test]
fn test_trim_underscore_prefix_option() {
    let (stdout, _stderr, success) = run_ejson2env(
        &[
            "--key-from-stdin",
            "--trim-underscore-prefix",
            "testdata/test-leading-underscore-env-key.ejson",
        ],
        Some(TEST_KEY_VALUE),
    );

    assert!(success, "Command should succeed");
    assert!(
        stdout.contains("export test_key='test value'"),
        "Should trim underscore prefix: {}",
        stdout
    );
    assert!(
        !stdout.contains("_test_key"),
        "Should not contain original key with underscore: {}",
        stdout
    );
}

#[test]
fn test_trim_underscore_prefix_with_quiet() {
    let (stdout, _stderr, success) = run_ejson2env(
        &[
            "--key-from-stdin",
            "--trim-underscore-prefix",
            "-q",
            "testdata/test-leading-underscore-env-key.ejson",
        ],
        Some(TEST_KEY_VALUE),
    );

    assert!(success, "Command should succeed");
    assert!(
        stdout.contains("test_key='test value'"),
        "Should output without export prefix: {}",
        stdout
    );
    assert!(
        !stdout.contains("export"),
        "Should not contain export: {}",
        stdout
    );
}

// Test without any trim flag

#[test]
fn test_without_trim_underscore_preserves_underscore() {
    let (stdout, _stderr, success) = run_ejson2env(
        &[
            "--key-from-stdin",
            "testdata/test-leading-underscore-env-key.ejson",
        ],
        Some(TEST_KEY_VALUE),
    );

    assert!(success, "Command should succeed");
    assert!(
        stdout.contains("export _test_key='test value'"),
        "Should preserve underscore when flag not provided: {}",
        stdout
    );
}

// Tests demonstrating --trim-underscore-prefix strips only the first underscore
// using keys with multiple leading underscores

#[test]
fn test_trim_underscore_prefix_strips_only_first_underscore() {
    // --trim-underscore-prefix should only strip the FIRST underscore
    // __double_underscore_key -> _double_underscore_key
    // ___triple_underscore_key -> __triple_underscore_key
    let (stdout, _stderr, success) = run_ejson2env(
        &[
            "--key-from-stdin",
            "--trim-underscore-prefix",
            "testdata/test-multiple-leading-underscores.ejson",
        ],
        Some(TEST_KEY_VALUE),
    );

    assert!(success, "Command should succeed");
    // __double -> _double (only first _ removed)
    assert!(
        stdout.contains("_double_underscore_key='double value'"),
        "Should have single underscore for double: {}",
        stdout
    );
    assert!(
        !stdout.contains("export double_underscore_key="),
        "Should NOT strip all underscores: {}",
        stdout
    );
    // ___triple -> __triple (only first _ removed)
    assert!(
        stdout.contains("__triple_underscore_key='triple value'"),
        "Should have double underscore for triple: {}",
        stdout
    );
    assert!(
        !stdout.contains("export triple_underscore_key="),
        "Should NOT strip all underscores from triple: {}",
        stdout
    );
}
