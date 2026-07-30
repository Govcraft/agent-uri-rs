//! End-to-end tests driving the real binary.
//!
//! Two invariants are asserted throughout, because they are the ones a user
//! notices when they break:
//!
//! - **A failure never writes to stdout.** A pipeline that captures stdout must
//!   never mistake a diagnostic for data.
//! - **`--json` stdout always parses.** Machine output is never contaminated by
//!   prose, warnings, or colour.
//!
//! Nothing here touches the real XDG config directory: every test that exercises
//! the default key path redirects `XDG_CONFIG_HOME` into a temporary directory.

use std::path::Path;
use std::process::Output;
use std::time::Duration;

use agent_uri::AgentUri;
use agent_uri_attestation::{AttestationClaims, Issuer, SigningKey};
use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

const URI: &str = "agent://acme.com/workflow/approval/rule_01h455vb4pex5vsknk084sn02q";
const OTHER_URI: &str = "agent://acme.com/chat/bot_01h455vb4pex5vsknk084sn02q";

/// The binary under test, with the real XDG path redirected somewhere harmless.
fn agent_uri(home: &TempDir) -> Command {
    let mut command = Command::cargo_bin("agent-uri").expect("binary builds");
    command.env("XDG_CONFIG_HOME", home.path());
    command.env_remove("NO_COLOR");
    command
}

/// Stdout as text.
fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("stdout is utf-8")
}

/// Stderr as text.
fn stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("stderr is utf-8")
}

/// The exit code, which every test cares about.
fn code(output: &Output) -> i32 {
    output.status.code().expect("process exited normally")
}

/// Parses stdout as JSON, failing loudly if prose leaked into it.
fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|e| panic!("stdout is not valid JSON ({e}): {:?}", stdout(output)))
}

/// Generates a key at `path` and returns its public half.
fn generate_key(home: &TempDir, path: &Path) -> String {
    let output = agent_uri(home)
        .args(["--json", "key", "generate", "--out"])
        .arg(path)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0, "key generate failed: {}", stderr(&output));
    json(&output)["public_key"]
        .as_str()
        .expect("a public key")
        .to_string()
}

/// Mints a token through the CLI, returning only what landed on stdout.
/// A stand-in for the agent's own public key.
///
/// Any valid Ed25519 public key does; the CLI never signs with it. Holding it
/// constant keeps these tests about the token rather than the key.
const AGENT_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn issue(home: &TempDir, key: &Path, uri: &str, capability: &str) -> String {
    let output = agent_uri(home)
        .args(["attest", "issue", "--key"])
        .arg(key)
        .args([
            "--agent",
            uri,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            capability,
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0, "issue failed: {}", stderr(&output));
    stdout(&output).trim().to_string()
}

// ---------------------------------------------------------------- the ceremony

#[test]
fn the_full_ceremony_round_trips() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");

    // generate -> register the public key -> issue -> verify
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .args(["--agent", URI, "--capability", "workflow/approval"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains(URI));
    assert!(stderr(&output).contains("VERIFIED"));
}

#[test]
fn key_public_derives_the_same_key_that_generate_reported() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let reported = generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["key", "public", "--key"])
        .arg(&key)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);
    // Bare on stdout, so it composes into a registry file.
    assert_eq!(stdout(&output).trim(), reported);
    assert_eq!(reported.len(), 64);
    assert!(reported.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn a_key_generated_at_the_default_path_lands_under_xdg_config_home() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["key", "generate"])
        .output()
        .expect("runs");
    assert_eq!(code(&output), 0, "{}", stderr(&output));

    let expected = home.path().join("agent-uri/keys/issuer.key");
    assert!(expected.exists(), "key should be at {}", expected.display());
    assert!(stdout(&output).contains(&expected.display().to_string()));
}

// --------------------------------------------------------------- key hygiene

#[cfg(unix)]
#[test]
fn a_key_file_is_written_0600_inside_a_0700_directory() {
    use std::os::unix::fs::PermissionsExt;

    let home = TempDir::new().unwrap();
    agent_uri(&home)
        .args(["key", "generate"])
        .output()
        .expect("runs");

    let key = home.path().join("agent-uri/keys/issuer.key");
    let key_mode = key.metadata().unwrap().permissions().mode() & 0o777;
    let dir_mode = key
        .parent()
        .unwrap()
        .metadata()
        .unwrap()
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(key_mode, 0o600, "key mode was {key_mode:o}");
    assert_eq!(dir_mode, 0o700, "key directory mode was {dir_mode:o}");
}

#[cfg(unix)]
#[test]
fn a_key_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = agent_uri(&home)
        .args(["key", "public", "--key"])
        .arg(&key)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 3);
    assert!(
        stdout(&output).is_empty(),
        "a refusal must not write to stdout"
    );
    assert!(stderr(&output).contains("readable by others"));
    assert!(
        stderr(&output).contains("chmod 600"),
        "must say how to fix it"
    );
}

#[test]
fn generate_refuses_to_clobber_an_existing_key() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let original = generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["key", "generate", "--out"])
        .arg(&key)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 3);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("--force"));

    // The original key is intact.
    let still_there = agent_uri(&home)
        .args(["key", "public", "--key"])
        .arg(&key)
        .output()
        .expect("runs");
    assert_eq!(stdout(&still_there).trim(), original);
}

#[test]
fn force_replaces_an_existing_key() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let original = generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["--json", "key", "generate", "--force", "--out"])
        .arg(&key)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);
    assert_ne!(json(&output)["public_key"].as_str().unwrap(), original);
}

#[test]
fn generate_never_prints_the_private_key_by_default() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");

    let output = agent_uri(&home)
        .args(["key", "generate", "--out"])
        .arg(&key)
        .output()
        .expect("runs");

    let secret = std::fs::read_to_string(&key).unwrap();
    let secret = secret.trim();

    assert!(
        !stdout(&output).contains(secret),
        "the private key must never reach stdout"
    );
    assert!(
        !stderr(&output).contains(secret),
        "the private key must never reach stderr"
    );
}

#[test]
fn generate_with_stdout_prints_only_the_private_key_and_writes_no_file() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["key", "generate", "--stdout"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);

    // Exactly the key, so it pipes verbatim into a secret store.
    let secret = stdout(&output).trim().to_string();
    assert_eq!(secret.len(), 64);
    assert!(secret.chars().all(|c| c.is_ascii_hexdigit()));

    // The warning is loud, and it is on stderr where a pipe will not eat it.
    assert!(stderr(&output).contains("PRIVATE KEY ON STDOUT"));
    assert!(!home.path().join("agent-uri/keys/issuer.key").exists());
}

#[test]
fn a_missing_key_is_an_io_error_not_a_refusal() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["key", "public", "--key", "/nonexistent/nope.key"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 3);
    assert!(stdout(&output).is_empty());
    assert!(
        stderr(&output).contains("key generate"),
        "must say how to fix it"
    );
}

// ------------------------------------------------------------------- issuing

#[test]
fn issue_puts_the_token_and_nothing_else_on_stdout() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval",
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);

    // This is the `| pbcopy` contract: one line, the token, nothing else.
    let out = stdout(&output);
    assert_eq!(out.lines().count(), 1);
    assert!(out.starts_with("v4.public."));

    // The summary exists, but it is prose, so it lives on stderr.
    let err = stderr(&output);
    assert!(err.contains("Issued an attestation"));
    assert!(err.contains("expires at"));
}

#[test]
fn issue_refuses_an_issuer_that_does_not_own_the_uris_authority() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
            "--issuer",
            "evil.com",
        ])
        .output()
        .expect("runs");

    // Minting this would produce a token no verifier could ever accept.
    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("evil.com"));
    assert!(stderr(&output).contains("acme.com"));
}

#[test]
fn issue_refuses_an_invalid_agent_uri() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            "http://example.com",
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "read",
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
}

#[test]
fn a_custom_ttl_is_honoured() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["--json", "attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
            "--ttl",
            "90d",
        ])
        .output()
        .expect("runs");

    let expires_in = json(&output)["claims"]["expires_in_seconds"]
        .as_i64()
        .unwrap();
    let ninety_days = 90 * 24 * 60 * 60;

    assert!(
        (ninety_days - 5..=ninety_days).contains(&expires_in),
        "expected ~90d, got {expires_in}s"
    );
}

#[test]
fn the_default_ttl_is_twenty_four_hours() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["--json", "attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
        ])
        .output()
        .expect("runs");

    let expires_in = json(&output)["claims"]["expires_in_seconds"]
        .as_i64()
        .unwrap();
    assert!(
        (86_395..=86_400).contains(&expires_in),
        "expected ~24h, got {expires_in}s"
    );
}

// --------------------------------------------------------------- verification

/// Mints a token that expired in the past, without making the test sleep.
fn expired_token(signing_key: &SigningKey) -> String {
    let issuer = Issuer::new("acme.com", signing_key.clone(), Duration::from_hours(1));

    let mut claims = AttestationClaims::builder()
        .agent_uri(URI)
        .agent_key(&SigningKey::generate().verifying_key())
        .issuer("acme.com")
        .add_capability("workflow/approval")
        .build()
        .expect("claims build");

    claims.iat = chrono::Utc::now() - chrono::Duration::days(4);
    claims.exp = chrono::Utc::now() - chrono::Duration::days(3);

    issuer.issue_claims(&claims).expect("signs")
}

/// Loads the signing key the CLI wrote, so tests can mint edge-case tokens with it.
fn load_key(path: &Path) -> SigningKey {
    let hex = std::fs::read_to_string(path).unwrap();
    let bytes: [u8; 32] = hex::decode(hex.trim()).unwrap().try_into().unwrap();
    SigningKey::from_bytes(&bytes).unwrap()
}

/// Corrupts a token's payload so that its decoded bytes definitely change.
///
/// Flipping the *last* base64 character is not enough: the final character can
/// carry "don't care" bits that decode to the same bytes, leaving the signature
/// intact and this test passing by accident. A character in the middle of the
/// payload always lands on a full 6-bit group.
fn tamper(token: &str) -> String {
    let mut parts: Vec<String> = token.split('.').map(String::from).collect();
    let payload = &mut parts[2];

    let midpoint = payload.len() / 2;
    let original = payload.as_bytes()[midpoint] as char;
    let replacement = if original == 'a' { 'b' } else { 'a' };
    payload.replace_range(midpoint..=midpoint, &replacement.to_string());

    parts.join(".")
}

#[test]
fn an_expired_token_is_refused_and_the_instant_is_named() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = expired_token(&load_key(&key));

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());

    // The library reports expiry without the instant; the tool recovers it.
    let err = stderr(&output);
    assert!(err.contains("expired at"), "got: {err}");
    assert!(err.contains("3 days ago"), "got: {err}");
}

#[test]
fn a_tampered_token_is_refused_as_a_signature_failure() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let tampered = tamper(&token);

    let output = agent_uri(&home)
        .args(["attest", "verify", &tampered, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());

    let err = stderr(&output);
    assert!(err.contains("signature"), "got: {err}");
    assert!(
        !err.contains("cipher error"),
        "must not leak the library's wording: {err}"
    );
}

#[test]
fn a_token_from_an_unsupplied_authority_names_the_missing_root() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);
    let other = home.path().join("other.key");
    let other_public = generate_key(&home, &other);

    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("partner.io={other_public}"))
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());

    let err = stderr(&output);
    assert!(
        err.contains("acme.com"),
        "must name the token's issuer: {err}"
    );
    assert!(
        err.contains("--trust-root acme.com="),
        "must say how to fix it: {err}"
    );
}

#[test]
fn a_capability_the_token_does_not_cover_is_refused() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval/read");

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .args(["--agent", URI, "--capability", "workflow/approval/write"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("does not cover"));
}

#[test]
fn capability_coverage_is_hierarchical() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);

    // Granting the identity path covers its children.
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .args(["--agent", URI, "--capability", "workflow/approval/read"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0, "{}", stderr(&output));
}

#[test]
fn a_token_for_another_subject_is_refused() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .args(["--agent", OTHER_URI])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("attests"));
}

#[test]
fn a_token_can_be_verified_from_stdin() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["attest", "verify", "-", "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .write_stdin(format!("{token}\n"))
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0, "{}", stderr(&output));
    assert!(stdout(&output).contains(URI));
}

// ---------------------------------------------------------------- inspection

#[test]
fn inspect_decodes_an_expired_token_and_says_it_is_unverified() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);
    let token = expired_token(&load_key(&key));

    let output = agent_uri(&home)
        .args(["attest", "inspect", &token])
        .output()
        .expect("runs");

    // Describing a token nobody trusts is the whole job, so this succeeds.
    assert_eq!(code(&output), 0);
    assert!(stdout(&output).contains(URI));

    let err = stderr(&output);
    assert!(
        err.contains("UNVERIFIED"),
        "the banner must be unmissable: {err}"
    );
    assert!(err.contains("expired"));
}

#[test]
fn inspect_needs_no_key_and_trusts_nothing() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["--json", "attest", "inspect", "-"])
        .write_stdin(token)
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);

    // A machine can assert on this, rather than on the absence of a field.
    let body = json(&output);
    assert_eq!(body["verified"], Value::Bool(false));
    assert_eq!(body["claims"]["issuer"], "acme.com");
    assert!(body["warning"].as_str().unwrap().contains("NOT"));
}

#[test]
fn inspect_refuses_a_token_that_is_not_a_token() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["attest", "inspect", "not-a-token"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
}

// ----------------------------------------------------------------------- uri

#[test]
fn uri_validate_prints_the_canonical_form() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["uri", "validate", URI])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);
    assert_eq!(
        stdout(&output).trim(),
        AgentUri::parse(URI).unwrap().canonical()
    );
    assert!(stderr(&output).contains("VALID"));
}

#[test]
fn uri_validate_refuses_a_bad_uri_with_a_diagnostic() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["uri", "validate", "agent://acme.com/no-agent-id"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(stdout(&output).is_empty());
    assert!(stderr(&output).contains("error:"));
    assert!(stderr(&output).contains("fix:"));
}

#[test]
fn uri_validate_json_breaks_out_the_parts() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["--json", "uri", "validate", URI])
        .output()
        .expect("runs");

    let body = json(&output);
    assert_eq!(body["valid"], Value::Bool(true));
    assert_eq!(body["trust_root"], "acme.com");
    assert_eq!(body["capability_path"], "workflow/approval");
    assert_eq!(body["agent_id"], "rule_01h455vb4pex5vsknk084sn02q");
}

// ---------------------------------------------------------------- exit codes

#[test]
fn a_missing_required_flag_is_a_usage_error() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["attest", "issue", "--agent", URI])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 2, "clap reports usage errors as 2");
}

#[test]
fn an_unparseable_ttl_is_a_usage_error_not_a_refusal() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
            "--ttl",
            "bogus",
        ])
        .output()
        .expect("runs");

    // A malformed knob is a usage error; bad content would be a refusal.
    assert_eq!(code(&output), 2);
    assert!(stdout(&output).is_empty());
}

#[test]
fn a_bare_number_ttl_is_rejected_rather_than_guessed() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
            "--ttl",
            "90",
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 2);
    assert!(
        stderr(&output).contains("unit"),
        "must explain the missing unit"
    );
}

#[test]
fn a_malformed_trust_root_pair_is_a_usage_error() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args([
            "attest",
            "verify",
            "v4.public.x",
            "--trust-root",
            "acme.com",
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 2);
    assert!(stderr(&output).contains("<root>=<public-key-hex>"));
}

// --------------------------------------------------------------- json output

#[test]
fn json_errors_are_json_on_stderr_and_stdout_stays_empty() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["--json", "uri", "validate", "not-a-uri"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 1);
    assert!(
        output.stdout.is_empty(),
        "machine output must not carry a diagnostic"
    );

    let error: Value = serde_json::from_slice(&output.stderr).expect("stderr is JSON");
    assert_eq!(error["error"]["kind"], "invalid_uri");
    assert_eq!(error["error"]["exit_code"], 1);
    assert!(
        error["error"]["remedy"]
            .as_str()
            .unwrap()
            .contains("agent://")
    );
}

#[test]
fn json_issue_wraps_the_token_with_its_claims() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["--json", "attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval",
            "--audience",
            "api.acme.com",
        ])
        .output()
        .expect("runs");

    let body = json(&output);
    assert!(body["token"].as_str().unwrap().starts_with("v4.public."));
    assert_eq!(body["claims"]["agent_uri"], URI);
    assert_eq!(body["claims"]["issuer"], "acme.com");
    assert_eq!(body["claims"]["capabilities"][0], "workflow/approval");
    assert_eq!(body["claims"]["audience"], "api.acme.com");
    assert_eq!(body["claims"]["expired"], Value::Bool(false));
}

#[test]
fn audience_restricted_token_requires_exact_cli_context() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);

    let issued = agent_uri(&home)
        .args(["--json", "attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval",
            "--audience",
            "api.acme.com",
        ])
        .output()
        .expect("runs");
    let token = json(&issued)["token"].as_str().unwrap().to_string();

    let without_context = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .output()
        .expect("runs");
    assert_eq!(code(&without_context), 1);
    assert!(stderr(&without_context).contains("audience"));

    let with_context = agent_uri(&home)
        .args(["attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .args(["--audience", "api.acme.com"])
        .output()
        .expect("runs");
    assert_eq!(code(&with_context), 0, "{}", stderr(&with_context));
}

#[test]
fn json_verify_reports_the_checks_it_performed() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    let public_key = generate_key(&home, &key);
    let token = issue(&home, &key, URI, "workflow/approval");

    let output = agent_uri(&home)
        .args(["--json", "attest", "verify", &token, "--trust-root"])
        .arg(format!("acme.com={public_key}"))
        .output()
        .expect("runs");

    let body = json(&output);
    assert_eq!(body["verified"], Value::Bool(true));
    assert_eq!(body["claims"]["agent_uri"], URI);

    let checks = body["checks"].as_array().unwrap();
    assert!(
        checks
            .iter()
            .any(|c| c.as_str().unwrap().contains("signature"))
    );
}

#[test]
fn json_mode_never_narrates_on_stderr() {
    let home = TempDir::new().unwrap();
    let key = home.path().join("acme.key");
    generate_key(&home, &key);

    let output = agent_uri(&home)
        .args(["--json", "attest", "issue", "--key"])
        .arg(&key)
        .args([
            "--agent",
            URI,
            "--agent-key",
            AGENT_KEY,
            "--capability",
            "workflow/approval/read",
        ])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 0);
    assert!(
        output.stderr.is_empty(),
        "a machine asked for data, not prose: {:?}",
        stderr(&output)
    );
}

#[test]
fn output_is_never_coloured_when_piped() {
    let home = TempDir::new().unwrap();

    // assert_cmd pipes both streams, so no TTY is present and colour must be off.
    let output = agent_uri(&home)
        .args(["uri", "validate", URI])
        .output()
        .expect("runs");

    assert!(
        !stderr(&output).contains('\x1b'),
        "colour must not reach a pipe"
    );
    assert!(!stdout(&output).contains('\x1b'));
}

// -------------------------------------------------------------- completions

#[test]
fn completions_are_generated_for_every_supported_shell() {
    let home = TempDir::new().unwrap();

    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let output = agent_uri(&home)
            .args(["completions", shell])
            .output()
            .expect("runs");

        assert_eq!(code(&output), 0, "{shell} completions failed");
        assert!(!output.stdout.is_empty(), "{shell} completions were empty");
        assert!(stdout(&output).contains("agent-uri"));
    }
}

#[test]
fn an_unknown_shell_is_a_usage_error() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home)
        .args(["completions", "tcsh"])
        .output()
        .expect("runs");

    assert_eq!(code(&output), 2);
}

#[test]
fn the_man_page_is_roff_on_stdout() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home).arg("man").output().expect("runs");

    assert_eq!(code(&output), 0);
    assert!(
        stdout(&output).contains(".TH"),
        "roff man pages start with .TH"
    );
    assert!(stdout(&output).contains("agent-uri"));
}

#[test]
fn help_reads_like_a_man_page() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home).arg("--help").output().expect("runs");
    let help = stdout(&output);

    assert_eq!(code(&output), 0);
    assert!(
        help.contains("agent://"),
        "the overview must introduce the scheme"
    );
    assert!(help.contains("key"));
    assert!(help.contains("attest"));
    assert!(help.contains("uri"));
}

#[test]
fn long_help_documents_the_exit_codes_and_every_subcommand_shows_examples() {
    let home = TempDir::new().unwrap();

    let output = agent_uri(&home).arg("--help").output().expect("runs");
    let help = stdout(&output);
    assert!(
        help.contains("Exit codes:"),
        "the contract must be documented"
    );
    assert!(help.contains("stdout carries data, stderr carries prose"));

    for command in [
        vec!["key", "generate"],
        vec!["key", "public"],
        vec!["attest", "issue"],
        vec!["attest", "verify"],
        vec!["attest", "inspect"],
        vec!["uri", "validate"],
    ] {
        let mut args = command.clone();
        args.push("--help");

        let output = agent_uri(&home).args(&args).output().expect("runs");
        let help = stdout(&output);

        assert_eq!(code(&output), 0, "{command:?} --help failed");
        assert!(
            help.contains("EXAMPLES:"),
            "{command:?} --help has no EXAMPLES section"
        );
    }
}
