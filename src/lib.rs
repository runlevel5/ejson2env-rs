//! ejson2env - Export environment variables from EJSON, EYAML, and ETOML files.
//!
//! This crate provides utilities for decrypting EJSON/EYAML/ETOML files and exporting
//! the secrets as shell environment variables.
//!
//! Supported file formats:
//! - `.ejson`, `.json` - JSON format
//! - `.eyaml`, `.eyml`, `.yaml`, `.yml` - YAML format
//! - `.etoml`, `.toml` - TOML format

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::Path;

use serde_json::Value as JsonValue;
use serde_norway::Value as YamlValue;
use thiserror::Error;
use toml::Value as TomlValue;
use zeroize::{Zeroize, Zeroizing};

// Re-export FileFormat from ejson for use by dependent crates
pub use ejson::format::FileFormat;

// Re-export Zeroizing for use by dependent crates
pub use zeroize::Zeroizing as SecretString;

/// A map of environment variable names to their secret values.
///
/// Security: This struct automatically zeroizes all secret values when dropped,
/// preventing sensitive data from lingering in memory. Each key and value string
/// is individually zeroized before the map is cleared.
pub struct SecretEnvMap {
    /// The underlying map of environment variable names to values.
    /// Both keys (env var names) and values (secrets) are zeroized on drop.
    inner: BTreeMap<String, String>,
}

impl SecretEnvMap {
    /// Creates a new empty SecretEnvMap.
    pub fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    /// Inserts a key-value pair into the map.
    pub fn insert(&mut self, key: String, value: String) {
        self.inner.insert(key, value);
    }

    /// Returns a reference to the value corresponding to the key.
    pub fn get(&self, key: &str) -> Option<&String> {
        self.inner.get(key)
    }

    /// Returns true if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the number of elements in the map.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns an iterator over the key-value pairs.
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, String> {
        self.inner.iter()
    }
}

impl Default for SecretEnvMap {
    fn default() -> Self {
        Self::new()
    }
}

impl Zeroize for SecretEnvMap {
    fn zeroize(&mut self) {
        // Zeroize each key and value individually before clearing the map
        // We need to take ownership to zeroize, so we drain and zeroize each entry
        for (mut key, mut value) in std::mem::take(&mut self.inner) {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for SecretEnvMap {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for SecretEnvMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretEnvMap")
            .field("len", &self.inner.len())
            .field("keys", &self.inner.keys().collect::<Vec<_>>())
            .field("values", &"[REDACTED]")
            .finish()
    }
}

impl<'a> IntoIterator for &'a SecretEnvMap {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::btree_map::Iter<'a, String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.iter()
    }
}

/// Validates that a string is a valid environment variable identifier.
/// Must start with letter or underscore, followed by letters, digits, or underscores.
#[inline]
fn is_valid_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Errors that can occur during ejson2env operations.
#[derive(Error, Debug)]
pub enum Ejson2EnvError {
    #[error("environment is not set in ejson/eyaml/etoml")]
    NoEnv,

    #[error("environment is not a map[string]interface{{}}")]
    EnvNotMap,

    #[error("invalid identifier as key in environment: {0:?}")]
    InvalidIdentifier(String),

    #[error("could not load ejson/eyaml/etoml file: {0}")]
    LoadError(String),

    #[error("could not load environment from file: {0}")]
    EnvLoadError(String),

    #[error("invalid file path: {0}")]
    InvalidPath(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("yaml error: {0}")]
    Yaml(#[from] serde_norway::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("ejson error: {0}")]
    Ejson(#[from] ejson::EjsonError),

    #[error("unsupported file format: {0}")]
    UnsupportedFormat(#[from] ejson::format::FormatError),
}

/// Type alias for export functions.
pub type ExportFunction = fn(&mut dyn Write, &SecretEnvMap);

/// Returns true if the error is due to the environment being missing or invalid.
pub fn is_env_error(err: &Ejson2EnvError) -> bool {
    matches!(err, Ejson2EnvError::NoEnv | Ejson2EnvError::EnvNotMap)
}

/// Decrypted secrets that can be either JSON, YAML, or TOML.
///
/// Security: This enum implements a custom Drop that attempts to clear sensitive
/// data from memory. Note that the underlying serde types don't implement Zeroize,
/// so this is a best-effort approach - the sensitive data is dropped and the memory
/// will be overwritten, but not cryptographically zeroized.
pub enum DecryptedSecrets {
    Json(JsonValue),
    Yaml(YamlValue),
    Toml(TomlValue),
}

impl std::fmt::Debug for DecryptedSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecryptedSecrets::Json(_) => f.debug_tuple("Json").field(&"[REDACTED]").finish(),
            DecryptedSecrets::Yaml(_) => f.debug_tuple("Yaml").field(&"[REDACTED]").finish(),
            DecryptedSecrets::Toml(_) => f.debug_tuple("Toml").field(&"[REDACTED]").finish(),
        }
    }
}

/// Validates that a path does not contain path traversal sequences.
/// Returns the canonicalized path if valid.
fn validate_path(path: &str) -> Result<std::path::PathBuf, Ejson2EnvError> {
    let path_obj = Path::new(path);

    // Check for path traversal sequences in the raw path
    if path.contains("..") {
        return Err(Ejson2EnvError::InvalidPath(
            "path contains traversal sequences".to_string(),
        ));
    }

    // Attempt to canonicalize the path to resolve symlinks and validate existence
    path_obj
        .canonicalize()
        .map_err(|e| Ejson2EnvError::InvalidPath(format!("cannot resolve path: {}", e)))
}

/// Reads and decrypts secrets from an EJSON, EYAML, or ETOML file.
fn read_secrets(
    filename: &str,
    keydir: &str,
    private_key: &str,
    trim_underscore_prefix: bool,
) -> Result<DecryptedSecrets, Ejson2EnvError> {
    // Validate the filename path to prevent path traversal
    let canonical_path = validate_path(filename)?;

    let decrypted =
        ejson::decrypt_file(&canonical_path, keydir, private_key, trim_underscore_prefix)?;
    let format = FileFormat::from_path(filename)?;

    match format {
        FileFormat::Json => {
            let secrets: JsonValue = serde_json::from_slice(&decrypted)?;
            Ok(DecryptedSecrets::Json(secrets))
        }
        FileFormat::Yaml => {
            let secrets: YamlValue = serde_norway::from_slice(&decrypted)?;
            Ok(DecryptedSecrets::Yaml(secrets))
        }
        FileFormat::Toml => {
            let decrypted_str = std::str::from_utf8(&decrypted)
                .map_err(|e| Ejson2EnvError::LoadError(format!("invalid UTF-8: {}", e)))?;
            let secrets: TomlValue = toml::from_str(decrypted_str)?;
            Ok(DecryptedSecrets::Toml(secrets))
        }
    }
}

/// Extracts environment values from decrypted JSON secrets.
///
/// Returns a SecretEnvMap of environment variable names to their values.
/// Only string values are exported; non-string values are silently ignored.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn extract_env_json(secrets: &JsonValue) -> Result<SecretEnvMap, Ejson2EnvError> {
    let raw_env = secrets.get("environment").ok_or(Ejson2EnvError::NoEnv)?;

    let env_map = raw_env.as_object().ok_or(Ejson2EnvError::EnvNotMap)?;

    let mut env_secrets = SecretEnvMap::new();

    for (key, raw_value) in env_map {
        // Reject keys that would be invalid environment variable identifiers
        if !is_valid_identifier(key) {
            return Err(Ejson2EnvError::InvalidIdentifier(key.clone()));
        }

        // Only export values that are strings
        if let Some(value) = raw_value.as_str() {
            env_secrets.insert(key.clone(), value.to_string());
        }
    }

    Ok(env_secrets)
}

/// Extracts environment values from decrypted YAML secrets.
///
/// Returns a SecretEnvMap of environment variable names to their values.
/// Only string values are exported; non-string values are silently ignored.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn extract_env_yaml(secrets: &YamlValue) -> Result<SecretEnvMap, Ejson2EnvError> {
    let raw_env = secrets.get("environment").ok_or(Ejson2EnvError::NoEnv)?;

    let env_map = raw_env.as_mapping().ok_or(Ejson2EnvError::EnvNotMap)?;

    let mut env_secrets = SecretEnvMap::new();

    for (key, raw_value) in env_map {
        // Get the key as a string
        let key_str = key
            .as_str()
            .ok_or_else(|| Ejson2EnvError::InvalidIdentifier(format!("{:?}", key)))?;

        // Reject keys that would be invalid environment variable identifiers
        if !is_valid_identifier(key_str) {
            return Err(Ejson2EnvError::InvalidIdentifier(key_str.to_string()));
        }

        // Only export values that are strings
        if let Some(value) = raw_value.as_str() {
            env_secrets.insert(key_str.to_string(), value.to_string());
        }
    }

    Ok(env_secrets)
}

/// Extracts environment values from decrypted TOML secrets.
///
/// Returns a SecretEnvMap of environment variable names to their values.
/// Only string values are exported; non-string values are silently ignored.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn extract_env_toml(secrets: &TomlValue) -> Result<SecretEnvMap, Ejson2EnvError> {
    let raw_env = secrets.get("environment").ok_or(Ejson2EnvError::NoEnv)?;

    let env_map = raw_env.as_table().ok_or(Ejson2EnvError::EnvNotMap)?;

    let mut env_secrets = SecretEnvMap::new();

    for (key, raw_value) in env_map {
        // Reject keys that would be invalid environment variable identifiers
        if !is_valid_identifier(key) {
            return Err(Ejson2EnvError::InvalidIdentifier(key.clone()));
        }

        // Only export values that are strings
        if let Some(value) = raw_value.as_str() {
            env_secrets.insert(key.clone(), value.to_string());
        }
    }

    Ok(env_secrets)
}

/// Extracts environment values from decrypted secrets (JSON, YAML, or TOML).
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn extract_env_from_secrets(
    secrets: &DecryptedSecrets,
) -> Result<SecretEnvMap, Ejson2EnvError> {
    match secrets {
        DecryptedSecrets::Json(json) => extract_env_json(json),
        DecryptedSecrets::Yaml(yaml) => extract_env_yaml(yaml),
        DecryptedSecrets::Toml(toml) => extract_env_toml(toml),
    }
}

/// Reads secrets from file and extracts environment variables.
///
/// Security: The returned SecretEnvMap will automatically zeroize all values when dropped.
pub fn read_and_extract_env(
    filename: &str,
    keydir: &str,
    private_key: &str,
    trim_underscore_prefix: bool,
) -> Result<SecretEnvMap, Ejson2EnvError> {
    let secrets = read_secrets(filename, keydir, private_key, trim_underscore_prefix)?;
    extract_env_from_secrets(&secrets)
}

/// Reads, extracts, and exports environment variables.
///
/// If the environment key is missing or invalid, it's not considered a fatal error
/// and an empty export will be produced.
///
/// Security: All secret values are automatically zeroized when dropped.
pub fn read_and_export_env<W: Write>(
    filename: &str,
    keydir: &str,
    private_key: &str,
    trim_underscore_prefix: bool,
    export_func: ExportFunction,
    output: &mut W,
) -> Result<(), Ejson2EnvError> {
    let env_values =
        match read_and_extract_env(filename, keydir, private_key, trim_underscore_prefix) {
            Ok(values) => values,
            Err(e) if is_env_error(&e) => SecretEnvMap::new(),
            Err(e) => return Err(Ejson2EnvError::EnvLoadError(e.to_string())),
        };

    export_func(output, &env_values);
    Ok(())
}

/// Validates that a key is safe for use in shell export statements.
/// Keys must start with a letter or underscore, followed by letters, digits, or underscores.
fn valid_key(k: &str) -> bool {
    is_valid_identifier(k)
}

/// Filters control characters from a value, preserving newlines.
fn filtered_value(v: &str) -> (String, bool) {
    let mut had_control_chars = false;
    let filtered: String = v
        .chars()
        .filter(|&c| {
            if c.is_control() && c != '\n' {
                had_control_chars = true;
                false
            } else {
                true
            }
        })
        .collect();
    (filtered, had_control_chars)
}

/// Shell-escapes a value for safe use in shell commands.
/// This mimics Go's shellescape.Quote behavior which always uses single quotes
/// and escapes single quotes by ending the quoted string, adding an escaped
/// single quote, then starting a new quoted string.
fn shell_quote(s: &str) -> String {
    // Go's shellescape.Quote behavior:
    // - Always wraps in single quotes
    // - Escapes single quotes as: 'text'"'"'more'
    //   which means: end single quote, add escaped single quote, start new single quote
    let mut result = String::with_capacity(s.len() + 2);
    result.push('\'');
    for c in s.chars() {
        if c == '\'' {
            // End the current single-quoted string, add an escaped single quote,
            // then start a new single-quoted string
            result.push_str("'\"'\"'");
        } else {
            result.push(c);
        }
    }
    result.push('\'');
    result
}

/// Internal export function that writes environment variables with a prefix.
fn export(w: &mut dyn Write, prefix: &str, values: &SecretEnvMap) {
    // SecretEnvMap uses BTreeMap internally, so iteration is sorted by key
    for (k, v) in values {
        if !valid_key(k) {
            eprintln!("ejson2env blocked invalid key");
            continue;
        }

        let (filtered, had_control_chars) = filtered_value(v);
        if had_control_chars {
            eprintln!("ejson2env trimmed control characters from value");
        }

        let quoted = shell_quote(&filtered);
        let _ = writeln!(w, "{}{}={}", prefix, k, quoted);
    }
}

/// Exports environment variables with "export " prefix.
///
/// Output format: `export KEY='value'`
pub fn export_env(w: &mut dyn Write, values: &SecretEnvMap) {
    export(w, "export ", values);
}

/// Exports environment variables without "export " prefix.
///
/// Output format: `KEY='value'`
pub fn export_quiet(w: &mut dyn Write, values: &SecretEnvMap) {
    export(w, "", values);
}

/// Reads a private key from stdin, trimming whitespace.
/// The returned string is wrapped in `Zeroizing` to ensure it is securely
/// wiped from memory when dropped.
pub fn read_key_from_stdin() -> Result<Zeroizing<String>, io::Error> {
    let mut buffer = Zeroizing::new(String::new());
    io::stdin().read_to_string(&mut buffer)?;
    let trimmed = Zeroizing::new(buffer.trim().to_string());
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY_VALUE: &str = "2ed65dd6a16eab833cc4d2a860baa60042da34a58ac43855e8554ca87a5e557d";

    fn test_ejson_path(name: &str) -> String {
        format!("testdata/{}", name)
    }

    #[test]
    fn test_is_valid_identifier() {
        // Should match
        assert!(is_valid_identifier("ALL_CAPS123"));
        assert!(is_valid_identifier("lowercase"));
        assert!(is_valid_identifier("a"));
        assert!(is_valid_identifier("_leading_underscore"));

        // Should not match
        assert!(!is_valid_identifier("1_leading_digit"));
        assert!(!is_valid_identifier("contains whitespace"));
        assert!(!is_valid_identifier("contains-dash"));
        assert!(!is_valid_identifier("contains_special_character;"));
    }

    #[test]
    fn test_valid_key() {
        assert!(valid_key("valid_key"));
        assert!(valid_key("KEY123"));
        assert!(valid_key("a"));
        assert!(!valid_key("")); // Empty key
        assert!(!valid_key("key-with-dash")); // Dashes not allowed
        assert!(!valid_key("key with space"));
        assert!(!valid_key("key;semicolon"));
        assert!(!valid_key("key\nnewline"));
    }

    #[test]
    fn test_filtered_value() {
        let (filtered, had_control) = filtered_value("normal value");
        assert_eq!(filtered, "normal value");
        assert!(!had_control);

        let (filtered, had_control) = filtered_value("value\nwith\nnewlines");
        assert_eq!(filtered, "value\nwith\nnewlines");
        assert!(!had_control);

        let (filtered, had_control) = filtered_value("\x08value with control");
        assert_eq!(filtered, "value with control");
        assert!(had_control);
    }

    #[test]
    fn test_extract_env_json_no_env() {
        let secrets: JsonValue = serde_json::json!({
            "_public_key": "abc123"
        });
        let result = extract_env_json(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
    }

    #[test]
    fn test_extract_env_json_not_map() {
        let secrets: JsonValue = serde_json::json!({
            "_public_key": "abc123",
            "environment": "not a map"
        });
        let result = extract_env_json(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
    }

    #[test]
    fn test_extract_env_json_invalid_key() {
        let secrets: JsonValue = serde_json::json!({
            "_public_key": "abc123",
            "environment": {
                "invalid key": "value"
            }
        });
        let result = extract_env_json(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_extract_env_json_valid() {
        let secrets: JsonValue = serde_json::json!({
            "_public_key": "abc123",
            "environment": {
                "test_key": "test_value",
                "_underscore_key": "underscore_value"
            }
        });
        let result = extract_env_json(&secrets).unwrap();
        assert_eq!(result.get("test_key"), Some(&"test_value".to_string()));
        assert_eq!(
            result.get("_underscore_key"),
            Some(&"underscore_value".to_string())
        );
    }

    #[test]
    fn test_export_env() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_env(&mut output, &values);
        assert_eq!(String::from_utf8(output).unwrap(), "export key='value'\n");
    }

    #[test]
    fn test_export_quiet() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value".to_string());

        export_quiet(&mut output, &values);
        assert_eq!(String::from_utf8(output).unwrap(), "key='value'\n");
    }

    #[test]
    fn test_path_validation_rejects_traversal() {
        // Path traversal should be rejected
        let result = validate_path("../../../etc/passwd");
        assert!(matches!(result, Err(Ejson2EnvError::InvalidPath(_))));

        let result = validate_path("foo/../bar/../../../etc/passwd");
        assert!(matches!(result, Err(Ejson2EnvError::InvalidPath(_))));
    }

    #[test]
    fn test_path_validation_accepts_valid_paths() {
        // Valid existing paths should be accepted
        let result = validate_path("testdata/test-expected-usage.ejson");
        assert!(result.is_ok());
    }

    #[test]
    fn test_export_escaping() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert(
            "test".to_string(),
            "test value'; echo dangerous; echo 'done".to_string(),
        );

        export_env(&mut output, &values);
        let result = String::from_utf8(output).unwrap();
        // The value should be properly escaped
        // The expected output should match Go's shellescape.Quote behavior
        let expected = "export test='test value'\"'\"'; echo dangerous; echo '\"'\"'done'\n";
        assert_eq!(result, expected);
    }

    #[test]
    fn test_command_injection_in_key() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key; touch pwned.txt".to_string(), "value".to_string());

        export_env(&mut output, &values);
        // Invalid key should be blocked
        assert!(String::from_utf8(output).unwrap().is_empty());
    }

    #[test]
    fn test_empty_key_blocked() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("".to_string(), "value".to_string());

        export_env(&mut output, &values);
        // Empty key should be blocked
        assert!(String::from_utf8(output).unwrap().is_empty());
    }

    #[test]
    fn test_dash_in_key_blocked() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key-with-dash".to_string(), "value".to_string());

        export_env(&mut output, &values);
        // Key with dash should be blocked (not valid for POSIX shell variables)
        assert!(String::from_utf8(output).unwrap().is_empty());
    }

    #[test]
    fn test_newline_in_value() {
        let mut output = Vec::new();
        let mut values = SecretEnvMap::new();
        values.insert("key".to_string(), "value\nnewline".to_string());

        export_env(&mut output, &values);
        let result = String::from_utf8(output).unwrap();
        // Newlines in values should be preserved and properly escaped
        assert!(result.contains("newline"));
    }

    #[test]
    fn test_is_env_error() {
        assert!(is_env_error(&Ejson2EnvError::NoEnv));
        assert!(is_env_error(&Ejson2EnvError::EnvNotMap));
        assert!(!is_env_error(&Ejson2EnvError::InvalidIdentifier(
            "test".to_string()
        )));
    }

    #[test]
    fn test_load_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-expected-usage.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_load_no_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-public-key-only.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_bad_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-environment-string-not-object.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_underscore_env_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-leading-underscore-env-key.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("_test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_read_and_export_env() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
            export_env,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "export test_key='test value'\n");
    }

    #[test]
    fn test_read_and_export_env_quiet() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.ejson"),
            "./key",
            TEST_KEY_VALUE,
            false,
            export_quiet,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "test_key='test value'\n");
    }

    #[test]
    fn test_read_and_export_env_bad_file() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            "bad.ejson",
            "./key",
            TEST_KEY_VALUE,
            false,
            export_env,
            &mut output,
        );

        assert!(result.is_err());
    }

    // EYAML tests
    #[test]
    fn test_extract_env_yaml_no_env() {
        let secrets: YamlValue = serde_norway::from_str(
            r#"
            _public_key: "abc123"
            "#,
        )
        .unwrap();
        let result = extract_env_yaml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
    }

    #[test]
    fn test_extract_env_yaml_not_map() {
        let secrets: YamlValue = serde_norway::from_str(
            r#"
            _public_key: "abc123"
            environment: "not a map"
            "#,
        )
        .unwrap();
        let result = extract_env_yaml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
    }

    #[test]
    fn test_extract_env_yaml_invalid_key() {
        let secrets: YamlValue = serde_norway::from_str(
            r#"
            _public_key: "abc123"
            environment:
              "invalid key": "value"
            "#,
        )
        .unwrap();
        let result = extract_env_yaml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_extract_env_yaml_valid() {
        let secrets: YamlValue = serde_norway::from_str(
            r#"
            _public_key: "abc123"
            environment:
              test_key: "test_value"
              _underscore_key: "underscore_value"
            "#,
        )
        .unwrap();
        let result = extract_env_yaml(&secrets).unwrap();
        assert_eq!(result.get("test_key"), Some(&"test_value".to_string()));
        assert_eq!(
            result.get("_underscore_key"),
            Some(&"underscore_value".to_string())
        );
    }

    #[test]
    fn test_load_eyaml_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-expected-usage.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_load_eyaml_no_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-public-key-only.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_eyaml_bad_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-environment-string-not-object.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_eyaml_underscore_env_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-leading-underscore-env-key.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("_test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_read_and_export_eyaml_env() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
            export_env,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "export test_key='test value'\n");
    }

    #[test]
    fn test_read_and_export_eyaml_env_quiet() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.eyaml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
            export_quiet,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "test_key='test value'\n");
    }

    #[test]
    fn test_file_format_detection() {
        // Valid formats
        assert_eq!(
            FileFormat::from_path("secrets.ejson").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("secrets.json").unwrap(),
            FileFormat::Json
        );
        assert_eq!(
            FileFormat::from_path("secrets.eyaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("secrets.eyml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("secrets.yaml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("secrets.yml").unwrap(),
            FileFormat::Yaml
        );
        assert_eq!(
            FileFormat::from_path("secrets.etoml").unwrap(),
            FileFormat::Toml
        );
        assert_eq!(
            FileFormat::from_path("secrets.toml").unwrap(),
            FileFormat::Toml
        );

        // Invalid formats should return error
        assert!(FileFormat::from_path("secrets.txt").is_err());
        assert!(FileFormat::from_path("secrets").is_err());
    }

    // ETOML tests
    #[test]
    fn test_extract_env_toml_no_env() {
        let secrets: TomlValue = toml::from_str(
            r#"
            _public_key = "abc123"
            "#,
        )
        .unwrap();
        let result = extract_env_toml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
    }

    #[test]
    fn test_extract_env_toml_not_map() {
        let secrets: TomlValue = toml::from_str(
            r#"
            _public_key = "abc123"
            environment = "not a map"
            "#,
        )
        .unwrap();
        let result = extract_env_toml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
    }

    #[test]
    fn test_extract_env_toml_invalid_key() {
        let secrets: TomlValue = toml::from_str(
            r#"
            _public_key = "abc123"
            [environment]
            "invalid key" = "value"
            "#,
        )
        .unwrap();
        let result = extract_env_toml(&secrets);
        assert!(matches!(result, Err(Ejson2EnvError::InvalidIdentifier(_))));
    }

    #[test]
    fn test_extract_env_toml_valid() {
        let secrets: TomlValue = toml::from_str(
            r#"
            _public_key = "abc123"
            [environment]
            test_key = "test_value"
            _underscore_key = "underscore_value"
            "#,
        )
        .unwrap();
        let result = extract_env_toml(&secrets).unwrap();
        assert_eq!(result.get("test_key"), Some(&"test_value".to_string()));
        assert_eq!(
            result.get("_underscore_key"),
            Some(&"underscore_value".to_string())
        );
    }

    #[test]
    fn test_load_etoml_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-expected-usage.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_load_etoml_no_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-public-key-only.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::NoEnv)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_etoml_bad_env_secrets() {
        let result = read_and_extract_env(
            &test_ejson_path("test-environment-string-not-object.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        );

        assert!(matches!(result, Err(Ejson2EnvError::EnvNotMap)));
        if let Err(ref e) = result {
            assert!(is_env_error(e));
        }
    }

    #[test]
    fn test_load_etoml_underscore_env_secrets() {
        let env_values = read_and_extract_env(
            &test_ejson_path("test-leading-underscore-env-key.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
        )
        .expect("Failed to load secrets");

        assert_eq!(env_values.get("_test_key"), Some(&"test value".to_string()));
    }

    #[test]
    fn test_read_and_export_etoml_env() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
            export_env,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "export test_key='test value'\n");
    }

    #[test]
    fn test_read_and_export_etoml_env_quiet() {
        let mut output = Vec::new();

        let result = read_and_export_env(
            &test_ejson_path("test-expected-usage.etoml"),
            "/opt/ejson/keys",
            TEST_KEY_VALUE,
            false,
            export_quiet,
            &mut output,
        );

        assert!(result.is_ok());
        let output_str = String::from_utf8(output).unwrap();
        assert_eq!(output_str, "test_key='test value'\n");
    }

    #[test]
    fn test_secret_env_map_debug_redacts_values() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("API_KEY".to_string(), "super_secret_key_123".to_string());
        secrets.insert("DB_PASSWORD".to_string(), "password123".to_string());

        let debug_output = format!("{:?}", secrets);

        // Should show keys but not values
        assert!(debug_output.contains("API_KEY"));
        assert!(debug_output.contains("DB_PASSWORD"));
        assert!(debug_output.contains("[REDACTED]"));
        // Should NOT contain the actual secret values
        assert!(!debug_output.contains("super_secret_key_123"));
        assert!(!debug_output.contains("password123"));
    }

    #[test]
    fn test_decrypted_secrets_debug_redacts_content() {
        let json_secrets = DecryptedSecrets::Json(serde_json::json!({
            "environment": {
                "SECRET": "my_secret_value"
            }
        }));

        let debug_output = format!("{:?}", json_secrets);

        // Should show type but not content
        assert!(debug_output.contains("Json"));
        assert!(debug_output.contains("[REDACTED]"));
        // Should NOT contain the actual secret
        assert!(!debug_output.contains("my_secret_value"));
    }

    #[test]
    fn test_secret_env_map_zeroize() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("KEY".to_string(), "secret_value".to_string());

        // Verify the map has content before zeroize
        assert_eq!(secrets.len(), 1);
        assert!(secrets.get("KEY").is_some());

        // Zeroize the map
        secrets.zeroize();

        // After zeroize, the map should be empty
        assert!(secrets.is_empty());
        assert_eq!(secrets.len(), 0);
    }

    #[test]
    fn test_secret_env_map_into_iterator() {
        let mut secrets = SecretEnvMap::new();
        secrets.insert("ZEBRA".to_string(), "value_z".to_string());
        secrets.insert("ALPHA".to_string(), "value_a".to_string());
        secrets.insert("MIKE".to_string(), "value_m".to_string());

        // Test that we can iterate using for-in syntax (IntoIterator trait)
        let collected: Vec<_> = (&secrets).into_iter().collect();
        assert_eq!(collected.len(), 3);

        // Verify iteration order is sorted by key (BTreeMap behavior)
        let keys: Vec<_> = collected.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, vec!["ALPHA", "MIKE", "ZEBRA"]);

        // Verify values are correctly associated
        let pairs: Vec<_> = collected
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("ALPHA", "value_a"),
                ("MIKE", "value_m"),
                ("ZEBRA", "value_z")
            ]
        );

        // Test idiomatic for-in loop
        let mut count = 0;
        for (k, v) in &secrets {
            assert!(!k.is_empty());
            assert!(!v.is_empty());
            count += 1;
        }
        assert_eq!(count, 3);
    }
}
