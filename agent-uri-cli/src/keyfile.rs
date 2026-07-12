//! On-disk signing keys, and the hygiene rules around them.
//!
//! A key file holds exactly one thing: 64 lowercase hex characters, the 32-byte
//! Ed25519 seed. No envelope, no metadata. It is the most boring format that
//! could work, which means it survives being catted, piped, and pasted into a
//! secret store without a parser in the way.
//!
//! Two rules are enforced, both of them refusals rather than warnings:
//!
//! - A key is written at mode `0600`, inside a directory at `0700`.
//! - A key that is readable by group or other is **refused**, not loaded. A
//!   private key that the rest of the machine can read is not private, and
//!   quietly using it anyway would launder that fact.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use agent_uri_attestation::SigningKey;

use crate::error::CliError;

/// Number of hex characters in an encoded 32-byte key.
const HEX_LEN: usize = 64;

/// The default key filename inside the config directory.
const DEFAULT_KEY_NAME: &str = "issuer.key";

/// Permission bits that must not be set on a private key file: group and other.
#[cfg(unix)]
const FORBIDDEN_BITS: u32 = 0o077;

/// Rejects any file mode that grants group or other access.
///
/// Pure, so the whole permission policy is testable without touching a disk.
///
/// # Errors
///
/// Returns the offending permission bits (masked to `0o777`) when the mode
/// grants any access beyond the owner.
#[cfg(unix)]
pub const fn check_mode(mode: u32) -> Result<(), u32> {
    if mode & FORBIDDEN_BITS == 0 {
        Ok(())
    } else {
        Err(mode & 0o777)
    }
}

/// Encodes a signing key as 64 lowercase hex characters.
pub fn encode(key: &SigningKey) -> String {
    hex::encode(key.to_bytes())
}

/// Parses a signing key from its hex encoding.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when the text is not exactly 64 hex characters.
pub fn decode(text: &str, path: &Path) -> Result<SigningKey, CliError> {
    let trimmed = text.trim();

    if trimmed.len() != HEX_LEN {
        return Err(CliError::fault(
            "malformed_key",
            format!(
                "key file '{}' holds {} characters; an Ed25519 key is {HEX_LEN} hex characters",
                path.display(),
                trimmed.len()
            ),
            "regenerate the key with 'agent-uri key generate', or restore it from your secret store",
        ));
    }

    let bytes = hex::decode(trimmed).map_err(|source| {
        CliError::fault(
            "malformed_key",
            format!("key file '{}' is not valid hex: {source}", path.display()),
            "the file should hold 64 lowercase hex characters and nothing else",
        )
    })?;

    let seed: [u8; 32] = bytes.try_into().map_err(|_| {
        CliError::fault(
            "malformed_key",
            format!("key file '{}' does not hold a 32-byte key", path.display()),
            "regenerate the key with 'agent-uri key generate'",
        )
    })?;

    SigningKey::from_bytes(&seed).map_err(|source| {
        CliError::fault(
            "malformed_key",
            format!("key file '{}' is not a valid Ed25519 key: {source}", path.display()),
            "regenerate the key with 'agent-uri key generate'",
        )
    })
}

/// The default key path: `$XDG_CONFIG_HOME/agent-uri/keys/issuer.key`.
///
/// Falls back to `$HOME/.config` when `XDG_CONFIG_HOME` is unset, per the XDG
/// base directory specification.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when neither `XDG_CONFIG_HOME` nor `HOME` is set,
/// since there is then no defensible place to put a key.
pub fn default_path() -> Result<PathBuf, CliError> {
    let base = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(xdg)
    } else if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        PathBuf::from(home).join(".config")
    } else {
        return Err(CliError::fault(
            "no_config_dir",
            "cannot locate a config directory: neither XDG_CONFIG_HOME nor HOME is set",
            "set XDG_CONFIG_HOME, or pass an explicit path with --out",
        ));
    };

    Ok(base.join("agent-uri").join("keys").join(DEFAULT_KEY_NAME))
}

/// Loads a signing key, refusing one whose permissions leak it.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when the file is missing, unreadable, readable by
/// group or other, or does not hold a valid key.
pub fn load(path: &Path) -> Result<SigningKey, CliError> {
    let metadata = fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            CliError::fault(
                "key_not_found",
                format!("no key file at '{}'", path.display()),
                "generate one with 'agent-uri key generate', or point --key at an existing key",
            )
        } else {
            CliError::io(path, "read key file", &source)
        }
    })?;

    enforce_permissions(&metadata, path)?;

    let text = fs::read_to_string(path).map_err(|source| CliError::io(path, "read key file", &source))?;
    decode(&text, path)
}

/// Refuses a key file that group or other can read.
#[cfg(unix)]
fn enforce_permissions(metadata: &fs::Metadata, path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    check_mode(metadata.permissions().mode()).map_err(|mode| {
        CliError::fault(
            "insecure_key_permissions",
            format!(
                "key file '{}' is readable by others (mode {mode:04o}); refusing to use it",
                path.display()
            ),
            format!("restrict it with: chmod 600 {}", path.display()),
        )
    })
}

/// On non-unix targets file modes cannot be enforced, so there is nothing to check.
#[cfg(not(unix))]
fn enforce_permissions(_metadata: &fs::Metadata, _path: &Path) -> Result<(), CliError> {
    Ok(())
}

/// Writes a signing key to disk at mode 0600, creating parent directories at 0700.
///
/// Refuses to overwrite an existing file unless `force` is set.
///
/// # Errors
///
/// Returns [`CliError::Fault`] when the file exists and `force` is unset, or when
/// the directory or file cannot be created.
pub fn store(path: &Path, key: &SigningKey, force: bool) -> Result<(), CliError> {
    if path.exists() {
        if !force {
            return Err(CliError::fault(
                "key_exists",
                format!("a key already exists at '{}'", path.display()),
                "pass --force to replace it, or choose another path with --out; \
                 replacing a key invalidates every attestation it has issued",
            ));
        }
        fs::remove_file(path).map_err(|source| CliError::io(path, "replace key file", &source))?;
    }

    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        create_private_dir(parent)?;
    }

    let mut file = private_file(path)?;
    // Newline included so the file behaves under `cat`, `read`, and text editors.
    writeln!(file, "{}", encode(key)).map_err(|source| CliError::io(path, "write key file", &source))?;
    file.flush().map_err(|source| CliError::io(path, "write key file", &source))?;

    Ok(())
}

/// Creates a directory tree, restricting the leaf to owner-only access.
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(dir).map_err(|source| CliError::io(dir, "create key directory", &source))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|source| CliError::io(dir, "restrict key directory", &source))
}

/// Creates a directory tree. Non-unix targets cannot express owner-only modes.
#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> Result<(), CliError> {
    fs::create_dir_all(dir).map_err(|source| CliError::io(dir, "create key directory", &source))
}

/// Creates the key file with owner-only permissions from the moment it exists,
/// so it is never briefly world-readable under a permissive umask.
#[cfg(unix)]
fn private_file(path: &Path) -> Result<fs::File, CliError> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| CliError::io(path, "create key file", &source))
}

/// Creates the key file. Non-unix targets cannot express owner-only modes.
#[cfg(not(unix))]
fn private_file(path: &Path) -> Result<fs::File, CliError> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| CliError::io(path, "create key file", &source))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn owner_only_modes_are_accepted() {
        assert!(check_mode(0o600).is_ok());
        assert!(check_mode(0o400).is_ok());
        assert!(check_mode(0o700).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn group_or_other_access_is_refused() {
        assert_eq!(check_mode(0o640), Err(0o640));
        assert_eq!(check_mode(0o604), Err(0o604));
        assert_eq!(check_mode(0o644), Err(0o644));
        assert_eq!(check_mode(0o666), Err(0o666));
        assert_eq!(check_mode(0o777), Err(0o777));
    }

    #[cfg(unix)]
    #[test]
    fn check_mode_ignores_file_type_bits() {
        // st_mode carries the file type in its high bits; only the low 9 matter.
        assert!(check_mode(0o100_600).is_ok());
        assert_eq!(check_mode(0o100_644), Err(0o644));
    }

    #[test]
    fn encoding_is_sixty_four_lowercase_hex_characters() {
        let encoded = encode(&SigningKey::generate());

        assert_eq!(encoded.len(), HEX_LEN);
        assert!(encoded.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(encoded, encoded.to_lowercase());
    }

    #[test]
    fn encode_decode_round_trips() {
        let key = SigningKey::generate();
        let recovered = decode(&encode(&key), Path::new("/k")).unwrap();

        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn decode_tolerates_a_trailing_newline() {
        let key = SigningKey::generate();
        let recovered = decode(&format!("{}\n", encode(&key)), Path::new("/k")).unwrap();

        assert_eq!(key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn decode_rejects_the_wrong_length() {
        let error = decode("abcd", Path::new("/k")).unwrap_err();

        assert_eq!(error.diagnosis().kind, "malformed_key");
        assert_eq!(error.exit_code(), 3);
    }

    #[test]
    fn decode_rejects_non_hex() {
        let error = decode(&"z".repeat(HEX_LEN), Path::new("/k")).unwrap_err();
        assert_eq!(error.diagnosis().kind, "malformed_key");
    }
}
