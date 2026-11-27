//! Native file hashing and checksum verification for INFERNEX.
//!
//! This module deliberately provides hashing only. Authenticated encryption is
//! being designed separately and will not be implemented with homemade crypto.
//! File contents are read in fixed-size chunks, so memory use is independent of
//! the size of the input file.

use sha2::{Digest, Sha256, Sha512};
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Maximum amount of file data held in memory while hashing.
pub const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Hash algorithm supported by the native INFERNEX file-integrity module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
}

/// Parse a canonical hash algorithm name, ignoring ASCII letter case.
///
/// Accepted names are `sha256` and `sha512`. Aliases and unknown algorithms
/// are rejected so callers cannot silently select a different digest.
impl FromStr for HashAlgorithm {
    type Err = CryptoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.eq_ignore_ascii_case("sha256") {
            Ok(Self::Sha256)
        } else if value.eq_ignore_ascii_case("sha512") {
            Ok(Self::Sha512)
        } else {
            Err(CryptoError::UnsupportedAlgorithm {
                algorithm: value.to_owned(),
            })
        }
    }
}

impl HashAlgorithm {
    /// Number of hexadecimal characters in this algorithm's digest.
    pub const fn hex_len(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    /// Canonical lowercase algorithm name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Errors returned by file hashing and checksum verification.
#[derive(Debug)]
pub enum CryptoError {
    /// Opening or reading the requested file failed.
    Io {
        path: PathBuf,
        source: io::Error,
    },
    /// Reading a caller-provided stream failed.
    ReaderIo(io::Error),
    /// A supplied checksum has the wrong number of hexadecimal characters.
    InvalidDigestLength {
        algorithm: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
    /// A supplied checksum contains a non-ASCII-hexadecimal byte.
    InvalidHexCharacter { index: usize, byte: u8 },
    /// Hexadecimal input must contain an even number of characters.
    InvalidHexLength { actual: usize },
    /// A percent-encoded URL component contains an incomplete or invalid escape.
    InvalidPercentEncoding { index: usize },
    /// Base64 input has invalid length, alphabet, padding, or unused padding bits.
    InvalidBase64 { index: usize },
    /// A requested hash algorithm name is not supported.
    UnsupportedAlgorithm { algorithm: String },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "cannot read '{}': {source}", path.display())
            }
            Self::ReaderIo(source) => write!(f, "cannot read input stream: {source}"),
            Self::InvalidDigestLength {
                algorithm,
                expected,
                actual,
            } => write!(
                f,
                "invalid {algorithm} digest length: expected {expected} hexadecimal characters, got {actual}"
            ),
            Self::InvalidHexCharacter { index, byte } => write!(
                f,
                "invalid hexadecimal character at byte {index}: 0x{byte:02x}"
            ),
            Self::InvalidHexLength { actual } => write!(
                f,
                "invalid hexadecimal length: expected an even number of characters, got {actual}"
            ),
            Self::InvalidPercentEncoding { index } => write!(
                f,
                "invalid percent escape at byte {index}: expected two hexadecimal digits"
            ),
            Self::InvalidBase64 { index } => {
                write!(f, "invalid Base64 input at byte {index}")
            }
            Self::UnsupportedAlgorithm { algorithm } => {
                write!(f, "unsupported hash algorithm '{algorithm}' (expected sha256 or sha512)")
            }
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } | Self::ReaderIo(source) => Some(source),
            Self::InvalidDigestLength { .. }
            | Self::InvalidHexCharacter { .. }
            | Self::InvalidHexLength { .. }
            | Self::InvalidPercentEncoding { .. }
            | Self::InvalidBase64 { .. }
            | Self::UnsupportedAlgorithm { .. } => None,
        }
    }
}

/// Hash a file with SHA-256 or SHA-512 and return a lowercase hexadecimal digest.
///
/// Reads the file incrementally using a fixed 64 KiB buffer. The file is never
/// loaded into memory in its entirety.
pub fn hash_file<P: AsRef<Path>>(
    path: P,
    algorithm: HashAlgorithm,
) -> Result<String, CryptoError> {
    hash_file_raw(path, algorithm).map(|digest| encode_hex(&digest))
}

/// Hash a file and return the raw digest bytes.
///
/// SHA-256 returns 32 bytes and SHA-512 returns 64 bytes. The file is read
/// incrementally using the fixed 64 KiB buffer.
pub fn hash_file_raw<P: AsRef<Path>>(
    path: P,
    algorithm: HashAlgorithm,
) -> Result<Vec<u8>, CryptoError> {
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|source| CryptoError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    match algorithm {
        HashAlgorithm::Sha256 => hash_reader_with_digest::<Sha256, _>(&mut file).map_err(|source| {
            CryptoError::Io {
                path: path.to_path_buf(),
                source,
            }
        }),
        HashAlgorithm::Sha512 => hash_reader_with_digest::<Sha512, _>(&mut file).map_err(|source| {
            CryptoError::Io {
                path: path.to_path_buf(),
                source,
            }
        }),
    }
}

/// Hash an in-memory byte slice with SHA-256 or SHA-512 and return a lowercase hexadecimal digest.
///
/// Unlike [`hash_file`], this helper is infallible and does not perform file I/O.
pub fn hash_bytes(data: &[u8], algorithm: HashAlgorithm) -> String {
    encode_hex(&hash_bytes_raw(data, algorithm))
}

/// Hash an in-memory byte slice and return the raw digest bytes.
///
/// SHA-256 returns 32 bytes and SHA-512 returns 64 bytes. Use hash_bytes
/// when a lowercase hexadecimal representation is preferred.
pub fn hash_bytes_raw(data: &[u8], algorithm: HashAlgorithm) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
        HashAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
    }
}

/// Encode arbitrary bytes as lowercase hexadecimal text.
pub fn encode_hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(data.len().saturating_mul(2));
    for byte in data {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

/// Decode hexadecimal text into bytes.
///
/// Both uppercase and lowercase ASCII hexadecimal characters are accepted.
/// Odd-length input and non-hexadecimal characters are rejected.
pub fn decode_hex(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    let bytes = encoded.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(CryptoError::InvalidHexLength { actual: bytes.len() });
    }

    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for (pair_index, pair) in bytes.chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(CryptoError::InvalidHexCharacter {
            index: pair_index * 2,
            byte: pair[0],
        })?;
        let low = hex_nibble(pair[1]).ok_or(CryptoError::InvalidHexCharacter {
            index: pair_index * 2 + 1,
            byte: pair[1],
        })?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode a URL component using RFC 3986 unreserved characters.
///
/// ASCII letters, digits, '-', '.', '_', and '~' are left unchanged. Every
/// other input byte is encoded as an uppercase `%HH` escape. This function
/// encodes one component, not a complete URL, and does not apply form rules
/// such as converting spaces to '+'.
pub fn percent_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::with_capacity(data.len());

    for &byte in data {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[(byte >> 4) as usize]));
            encoded.push(char::from(HEX[(byte & 0x0f) as usize]));
        }
    }

    encoded
}

/// Decode percent escapes in one URL component into its original bytes.
///
/// Non-escaped bytes are copied unchanged. A '+' remains '+', because this is
/// RFC 3986 component decoding rather than application/x-www-form-urlencoded
/// decoding. Invalid or incomplete escapes return the byte index of '%'.
pub fn percent_decode(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    let input = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;

    while index < input.len() {
        if input[index] != b'%' {
            decoded.push(input[index]);
            index += 1;
            continue;
        }

        if index + 2 >= input.len() {
            return Err(CryptoError::InvalidPercentEncoding { index });
        }

        let high = hex_nibble(input[index + 1])
            .ok_or(CryptoError::InvalidPercentEncoding { index })?;
        let low = hex_nibble(input[index + 2])
            .ok_or(CryptoError::InvalidPercentEncoding { index })?;

        decoded.push((high << 4) | low);
        index += 3;
    }

    Ok(decoded)
}

/// Encode arbitrary bytes using the standard RFC 4648 Base64 alphabet.
///
/// Output uses the standard '+' and '/' alphabet and canonical '=' padding.
/// This is an encoding utility, not encryption.
pub fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let capacity = data.len().saturating_add(2) / 3 * 4;
    let mut encoded = String::with_capacity(capacity);

    for chunk in data.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();

        encoded.push(char::from(ALPHABET[(first >> 2) as usize]));
        encoded.push(char::from(
            ALPHABET[(((first & 0x03) << 4) | second.unwrap_or(0) >> 4) as usize],
        ));

        match (second, third) {
            (Some(second), Some(third)) => {
                encoded.push(char::from(
                    ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize],
                ));
                encoded.push(char::from(ALPHABET[(third & 0x3f) as usize]));
            }
            (Some(second), None) => {
                encoded.push(char::from(ALPHABET[((second & 0x0f) << 2) as usize]));
                encoded.push('=');
            }
            (None, None) => {
                encoded.push('=');
                encoded.push('=');
            }
            (None, Some(_)) => unreachable!("chunks of three cannot skip their second byte"),
        }
    }

    encoded
}

/// Decode standard RFC 4648 Base64 into bytes.
///
/// The decoder requires complete four-byte groups, final-only padding, and
/// canonical zero padding bits. Whitespace and the Base64url alphabet are not
/// accepted. Errors report the byte offset of the malformed input.
pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    let input = encoded.as_bytes();
    if input.len() % 4 != 0 {
        return Err(CryptoError::InvalidBase64 { index: input.len() });
    }

    let mut decoded = Vec::with_capacity(input.len() / 4 * 3);
    for (group_index, group) in input.chunks_exact(4).enumerate() {
        let offset = group_index * 4;
        let a = base64_value(group[0])
            .ok_or(CryptoError::InvalidBase64 { index: offset })?;
        let b = base64_value(group[1])
            .ok_or(CryptoError::InvalidBase64 { index: offset + 1 })?;

        decoded.push((a << 2) | (b >> 4));

        if group[2] == b'=' {
            if group[3] != b'=' || offset + 4 != input.len() || b & 0x0f != 0 {
                return Err(CryptoError::InvalidBase64 { index: offset + 2 });
            }
            continue;
        }

        let c = base64_value(group[2])
            .ok_or(CryptoError::InvalidBase64 { index: offset + 2 })?;
        decoded.push((b << 4) | (c >> 2));

        if group[3] == b'=' {
            if offset + 4 != input.len() || c & 0x03 != 0 {
                return Err(CryptoError::InvalidBase64 { index: offset + 3 });
            }
            continue;
        }

        let d = base64_value(group[3])
            .ok_or(CryptoError::InvalidBase64 { index: offset + 3 })?;
        decoded.push((c << 6) | d);
    }

    Ok(decoded)
}

/// Encode arbitrary bytes using the URL-safe Base64 alphabet without padding.
///
/// The output uses '-' and '_' instead of '+' and '/', and omits trailing '='.
/// This is a representation format, not encryption.
pub fn base64url_encode(data: &[u8]) -> String {
    base64_encode(data)
        .trim_end_matches('=')
        .replace('+', "-")
        .replace('/', "_")
}

/// Decode URL-safe Base64 into bytes.
///
/// Both padded and unpadded canonical input are accepted. The standard
/// Base64-only '+' and '/' characters, whitespace, misplaced padding, and
/// non-zero unused padding bits are rejected.
pub fn base64url_decode(encoded: &str) -> Result<Vec<u8>, CryptoError> {
    let input = encoded.as_bytes();
    let first_padding = input.iter().position(|&byte| byte == b'=');
    let data_len = first_padding.unwrap_or(input.len());

    if input[..data_len]
        .iter()
        .any(|&byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
    {
        let index = input[..data_len]
            .iter()
            .position(|&byte| !byte.is_ascii_alphanumeric() && !matches!(byte, b'-' | b'_'))
            .expect("invalid byte was found");
        return Err(CryptoError::InvalidBase64 { index });
    }

    if let Some(index) = first_padding {
        if input[index..].iter().any(|&byte| byte != b'=')
            || input.len() % 4 != 0
            || input.len() - index > 2
        {
            return Err(CryptoError::InvalidBase64 { index });
        }
    }

    let remainder = data_len % 4;
    if remainder == 1 {
        return Err(CryptoError::InvalidBase64 { index: data_len });
    }

    let expected_padding = match remainder {
        0 => 0,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    };
    if first_padding.is_some() && input.len() - data_len != expected_padding {
        return Err(CryptoError::InvalidBase64 {
            index: data_len,
        });
    }

    let mut standard = String::with_capacity(data_len + expected_padding);
    for &byte in &input[..data_len] {
        standard.push(match byte {
            b'-' => '+',
            b'_' => '/',
            other => char::from(other),
        });
    }
    for _ in 0..expected_padding {
        standard.push('=');
    }

    base64_decode(&standard)
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}
/// Verify a file against an expected hexadecimal digest.
///
/// The expected digest must contain exactly the correct number of ASCII
/// hexadecimal characters. Letter case is ignored. Returns `Ok(true)` for a
/// match and `Ok(false)` for a well-formed but incorrect digest.
pub fn verify_file<P: AsRef<Path>>(
    path: P,
    algorithm: HashAlgorithm,
    expected_hex: &str,
) -> Result<bool, CryptoError> {
    validate_digest(algorithm, expected_hex)?;
    let actual = hash_file(path, algorithm)?;
    Ok(actual.eq_ignore_ascii_case(expected_hex))
}

/// Verify an in-memory byte slice against an expected hexadecimal digest.
///
/// The expected digest must contain exactly the correct number of ASCII
/// hexadecimal characters. Letter case is ignored. Returns `Ok(true)` for a
/// match and `Ok(false)` for a well-formed but incorrect digest.
pub fn verify_bytes(
    data: &[u8],
    algorithm: HashAlgorithm,
    expected_hex: &str,
) -> Result<bool, CryptoError> {
    validate_digest(algorithm, expected_hex)?;
    let actual = hash_bytes(data, algorithm);
    Ok(actual.eq_ignore_ascii_case(expected_hex))
}

/// Verify a stream against an expected hexadecimal digest without buffering it
/// in full. The reader is consumed until EOF; interrupted reads are retried.
/// Invalid digests are rejected before the reader is accessed.
pub fn verify_reader<R: Read>(
    reader: &mut R,
    algorithm: HashAlgorithm,
    expected_hex: &str,
) -> Result<bool, CryptoError> {
    validate_digest(algorithm, expected_hex)?;
    let actual = hash_reader(reader, algorithm).map_err(CryptoError::ReaderIo)?;
    Ok(actual.eq_ignore_ascii_case(expected_hex))
}

fn validate_digest(
    algorithm: HashAlgorithm,
    expected_hex: &str,
) -> Result<(), CryptoError> {
    if expected_hex.len() != algorithm.hex_len() {
        return Err(CryptoError::InvalidDigestLength {
            algorithm,
            expected: algorithm.hex_len(),
            actual: expected_hex.len(),
        });
    }

    for (index, byte) in expected_hex.bytes().enumerate() {
        if !byte.is_ascii_hexdigit() {
            return Err(CryptoError::InvalidHexCharacter { index, byte });
        }
    }

    Ok(())
}

/// Hash data from any reader with SHA-256 or SHA-512.
///
/// Reads incrementally using the module's fixed 64 KiB buffer and retries
/// interrupted reads. This is useful for streams, pipes, and in-memory cursors
/// without requiring callers to create a temporary file.
pub fn hash_reader<R: Read>(
    reader: &mut R,
    algorithm: HashAlgorithm,
) -> io::Result<String> {
    hash_reader_raw(reader, algorithm).map(|digest| encode_hex(&digest))
}

/// Hash any reader and return raw digest bytes without buffering the full input.
///
/// SHA-256 returns 32 bytes and SHA-512 returns 64 bytes. Interrupted reads
/// are retried, and other I/O errors are returned unchanged.
pub fn hash_reader_raw<R: Read>(
    reader: &mut R,
    algorithm: HashAlgorithm,
) -> io::Result<Vec<u8>> {
    match algorithm {
        HashAlgorithm::Sha256 => hash_reader_with_digest::<Sha256, _>(reader),
        HashAlgorithm::Sha512 => hash_reader_with_digest::<Sha512, _>(reader),
    }
}

fn hash_reader_with_digest<D: Digest + Default, R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut hasher = D::default();
    let mut buffer = [0u8; HASH_BUFFER_SIZE];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => hasher.update(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }

    Ok(hasher.finalize().to_vec())
}

/// A reusable, in-memory manifest entry for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashRecord {
    /// Path that was hashed.
    pub path: PathBuf,
    /// Lowercase hexadecimal digest.
    pub digest: String,
}

/// A snapshot of file digests using one consistent algorithm.
///
/// The manifest is an in-memory API type. Callers may persist it using their
/// chosen format; this module deliberately does not define an unsafe or
/// ambiguous path-serialization format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashManifest {
    pub algorithm: HashAlgorithm,
    pub entries: Vec<FileHashRecord>,
}

/// A manifest entry that records the algorithm used for this individual file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHashRecordV2 {
    pub path: PathBuf,
    pub algorithm: HashAlgorithm,
    pub digest: String,
}

/// A manifest that permits a different supported algorithm for each file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashManifestV2 {
    pub entries: Vec<FileHashRecordV2>,
}

/// Result of checking one entry in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestCheck {
    pub path: PathBuf,
    pub expected_digest: String,
    pub actual_digest: String,
    pub matches: bool,
}

/// Aggregate outcome of verifying every entry in a manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestVerificationReport {
    /// Per-file verification results, in manifest order.
    pub checks: Vec<ManifestCheck>,
    /// Number of entries in the manifest.
    pub total: usize,
    /// Number of entries whose actual digest matched the expected digest.
    pub matched: usize,
    /// Number of entries whose actual digest differed from the expected digest.
    pub mismatched: usize,
}

/// Build a manifest for an explicit list of files.
///
/// Paths are processed in caller-supplied order. No directory traversal or
/// implicit file discovery is performed.
pub fn create_manifest<P: AsRef<Path>>(
    paths: &[P],
    algorithm: HashAlgorithm,
) -> Result<HashManifest, CryptoError> {
    let mut entries = Vec::with_capacity(paths.len());
    for path in paths {
        let path = path.as_ref();
        entries.push(FileHashRecord {
            path: path.to_path_buf(),
            digest: hash_file(path, algorithm)?,
        });
    }
    Ok(HashManifest { algorithm, entries })
}

/// Verify a manifest and return both per-file checks and aggregate counts.
///
/// The report preserves manifest order. As with [`verify_manifest`], malformed
/// digests and file I/O failures return an error rather than a partial report.
pub fn verify_manifest_report(
    manifest: &HashManifest,
) -> Result<ManifestVerificationReport, CryptoError> {
    let checks = verify_manifest(manifest)?;
    let total = checks.len();
    let matched = checks.iter().filter(|check| check.matches).count();
    let mismatched = total - matched;

    Ok(ManifestVerificationReport { checks, total, matched, mismatched })
}

/// Create a per-file-algorithm manifest from explicit caller-supplied paths.
///
/// Each tuple contains a path and the algorithm to use for that file. Input
/// order is preserved, and no directory traversal is performed.
pub fn create_manifest_v2<P: AsRef<Path>>(
    files: &[(P, HashAlgorithm)],
) -> Result<HashManifestV2, CryptoError> {
    let mut entries = Vec::with_capacity(files.len());
    for (path, algorithm) in files {
        let path = path.as_ref();
        entries.push(FileHashRecordV2 {
            path: path.to_path_buf(),
            algorithm: *algorithm,
            digest: hash_file(path, *algorithm)?,
        });
    }
    Ok(HashManifestV2 { entries })
}

/// Verify a per-file-algorithm manifest and return aggregate counts.
pub fn verify_manifest_v2_report(
    manifest: &HashManifestV2,
) -> Result<ManifestVerificationReport, CryptoError> {
    let checks = verify_manifest_v2(manifest)?;
    let total = checks.len();
    let matched = checks.iter().filter(|check| check.matches).count();
    let mismatched = total - matched;
    Ok(ManifestVerificationReport { checks, total, matched, mismatched })
}

/// Verify each file using the algorithm recorded for that entry.
///
/// Results preserve manifest order. Invalid digests and file I/O errors fail
/// the operation rather than returning a misleading partial report.
pub fn verify_manifest_v2(
    manifest: &HashManifestV2,
) -> Result<Vec<ManifestCheck>, CryptoError> {
    let mut checks = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        validate_digest(entry.algorithm, &entry.digest)?;
        let actual = hash_file(&entry.path, entry.algorithm)?;
        checks.push(ManifestCheck {
            path: entry.path.clone(),
            expected_digest: entry.digest.clone(),
            matches: actual.eq_ignore_ascii_case(&entry.digest),
            actual_digest: actual,
        });
    }
    Ok(checks)
}

/// Verify every file recorded in a manifest.
///
/// Returns one result per entry, preserving manifest order. File I/O errors
/// stop verification and are returned with the affected path. Malformed
/// digests are rejected before the corresponding file is opened.
pub fn verify_manifest(manifest: &HashManifest) -> Result<Vec<ManifestCheck>, CryptoError> {
    let mut checks = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        validate_digest(manifest.algorithm, &entry.digest)?;
        let actual = hash_file(&entry.path, manifest.algorithm)?;
        checks.push(ManifestCheck {
            path: entry.path.clone(),
            expected_digest: entry.digest.clone(),
            matches: actual.eq_ignore_ascii_case(&entry.digest),
            actual_digest: actual,
        });
    }
    Ok(checks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

    struct TestFile {
        directory: PathBuf,
        path: PathBuf,
    }

    impl TestFile {
        fn new(contents: &[u8]) -> Self {
            let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "infernex-crypto-test-{}-{id}",
                std::process::id()
            ));
            fs::create_dir(&directory).expect("create temporary test directory");
            let path = directory.join("fixture.bin");
            fs::write(&path, contents).expect("write temporary test file");
            Self { directory, path }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    #[test]
    fn raw_reader_and_file_hashes_match_hex_apis() {
        use std::io::Cursor;

        let bytes: Vec<u8> = (0..(HASH_BUFFER_SIZE * 2 + 73))
            .map(|index| (index % 239) as u8)
            .collect();
        let file = TestFile::new(&bytes);

        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let mut reader = Cursor::new(bytes.as_slice());
            let reader_digest = hash_reader_raw(&mut reader, algorithm).unwrap();
            let file_digest = hash_file_raw(&file.path, algorithm).unwrap();
            let expected_len = match algorithm {
                HashAlgorithm::Sha256 => 32,
                HashAlgorithm::Sha512 => 64,
            };

            assert_eq!(reader_digest.len(), expected_len);
            assert_eq!(file_digest, reader_digest);
            assert_eq!(
                encode_hex(&reader_digest),
                hash_reader(&mut Cursor::new(&bytes), algorithm).unwrap()
            );
            assert_eq!(encode_hex(&file_digest), hash_file(&file.path, algorithm).unwrap());
        }
    }

    #[test]
    fn raw_reader_hash_handles_empty_input_and_reader_errors() {
        use std::io::Cursor;

        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let digest = hash_reader_raw(&mut Cursor::new([]), algorithm).unwrap();
            assert_eq!(
                digest.len(),
                match algorithm {
                    HashAlgorithm::Sha256 => 32,
                    HashAlgorithm::Sha512 => 64,
                }
            );
            assert_eq!(encode_hex(&digest), hash_bytes(&[], algorithm));
        }

        let error = hash_reader_raw(&mut FailingReader, HashAlgorithm::Sha256).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn hash_reader_matches_byte_and_file_hashes_across_buffer_boundaries() {
        use std::io::Cursor;

        let data = vec![0x5a; HASH_BUFFER_SIZE + 137];
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let mut reader = Cursor::new(data.as_slice());
            assert_eq!(
                hash_reader(&mut reader, algorithm).unwrap(),
                hash_bytes(&data, algorithm)
            );
        }
    }

    #[test]
    fn hash_reader_handles_empty_input() {
        use std::io::Cursor;

        let mut reader = Cursor::new([]);
        assert_eq!(
            hash_reader(&mut reader, HashAlgorithm::Sha256).unwrap(),
            hash_bytes(&[], HashAlgorithm::Sha256)
        );
    }

    #[test]
    fn hash_algorithm_parses_canonical_names_case_insensitively() {
        assert_eq!("sha256".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Sha256);
        assert_eq!("SHA256".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Sha256);
        assert_eq!("Sha512".parse::<HashAlgorithm>().unwrap(), HashAlgorithm::Sha512);
    }

    #[test]
    fn hash_algorithm_rejects_unknown_names_and_aliases() {
        for name in ["sha-256", "sha1", "blake3", "", " sha256"] {
            assert!(matches!(
                name.parse::<HashAlgorithm>(),
                Err(CryptoError::UnsupportedAlgorithm { .. })
            ));
        }
    }

    #[test]
    fn hex_encoding_round_trips_binary_data() {
        let input = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff];
        let encoded = encode_hex(&input);
        assert_eq!(encoded, "00017f80feff");
        assert_eq!(decode_hex(&encoded).unwrap(), input);
    }

    #[test]
    fn hex_encoding_handles_empty_input() {
        assert_eq!(encode_hex(&[]), "");
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decoding_accepts_uppercase() {
        assert_eq!(decode_hex("00A1b2FF").unwrap(), [0x00, 0xa1, 0xb2, 0xff]);
    }

    #[test]
    fn hex_decoding_rejects_odd_length() {
        assert!(matches!(
            decode_hex("abc").unwrap_err(),
            CryptoError::InvalidHexLength { actual: 3 }
        ));
    }

    #[test]
    fn hex_decoding_reports_invalid_character_position() {
        assert!(matches!(
            decode_hex("00xz").unwrap_err(),
            CryptoError::InvalidHexCharacter { index: 2, byte: b'x' }
        ));
    }

    #[test]
    fn sha256_known_vector_abc() {
        let file = TestFile::new(b"abc");
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha256).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_known_vector_abc() {
        let file = TestFile::new(b"abc");
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn hashes_byte_slices_with_known_vectors() {
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hash_bytes(b"abc", HashAlgorithm::Sha512),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            hash_bytes(b"", HashAlgorithm::Sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn raw_byte_slice_hashes_match_known_vectors_and_hex_helpers() {
        let sha256 = hash_bytes_raw(b"abc", HashAlgorithm::Sha256);
        let sha512 = hash_bytes_raw(b"abc", HashAlgorithm::Sha512);

        assert_eq!(sha256.len(), 32);
        assert_eq!(sha512.len(), 64);
        assert_eq!(
            encode_hex(&sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            encode_hex(&sha512),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(hash_bytes(b"abc", HashAlgorithm::Sha256), encode_hex(&sha256));
        assert_eq!(hash_bytes(b"abc", HashAlgorithm::Sha512), encode_hex(&sha512));
    }

    #[test]
    fn raw_hashes_support_empty_and_binary_inputs() {
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let bytes = [0, 0xff, 0x80, b'\\', 0, 42];
            let raw = hash_bytes_raw(&bytes, algorithm);
            assert_eq!(decode_hex(&hash_bytes(&bytes, algorithm)).unwrap(), raw);
            assert_eq!(hash_bytes_raw(&[], algorithm).len(), match algorithm {
                HashAlgorithm::Sha256 => 32,
                HashAlgorithm::Sha512 => 64,
            });
        }
    }

    #[test]
    fn byte_slice_hashes_match_streamed_file_hashes() {
        let bytes = [0, 0xff, 0x80, b'\n', 0x7f, 0, 42];
        let file = TestFile::new(&bytes);
        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            assert_eq!(
                hash_bytes(&bytes, algorithm),
                hash_file(&file.path, algorithm).unwrap()
            );
        }
    }

    #[test]
    fn sha256_empty_file_vector() {
        let file = TestFile::new(b"");
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha256).unwrap(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn sha512_empty_file_vector() {
        let file = TestFile::new(b"");
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                .to_owned()
                + "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn hashes_binary_data() {
        let bytes = [0, 0xff, 0x80, b'\n', 0x7f, 0, 42];
        let file = TestFile::new(&bytes);
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha256).unwrap(),
            encode_hex(&Sha256::digest(bytes))
        );
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            encode_hex(&Sha512::digest(bytes))
        );
    }

    #[test]
    fn streams_files_larger_than_the_buffer() {
        let bytes: Vec<u8> = (0..(HASH_BUFFER_SIZE * 3 + 137))
            .map(|index| (index % 251) as u8)
            .collect();
        let file = TestFile::new(&bytes);
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha256).unwrap(),
            encode_hex(&Sha256::digest(&bytes))
        );
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            encode_hex(&Sha512::digest(&bytes))
        );
    }

    #[test]
    fn verifies_correct_checksum_case_insensitively() {
        let file = TestFile::new(b"abc");
        let correct_uppercase =
            "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        assert!(verify_file(
            &file.path,
            HashAlgorithm::Sha256,
            correct_uppercase
        )
        .unwrap());
    }

    #[test]
    fn verifies_correct_and_incorrect_digests() {
        let file = TestFile::new(b"abc");
        let correct =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let actual =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(correct, actual);
        assert!(verify_file(&file.path, HashAlgorithm::Sha256, actual).unwrap());
        let incorrect =
            "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(!verify_file(&file.path, HashAlgorithm::Sha256, incorrect).unwrap());
        assert!(verify_file(&file.path, HashAlgorithm::Sha256, &actual.to_uppercase()).unwrap());
    }

    #[test]
    fn verifies_byte_slices_with_valid_and_invalid_digests() {
        let expected = hash_bytes(b"abc", HashAlgorithm::Sha256);
        assert!(verify_bytes(b"abc", HashAlgorithm::Sha256, &expected).unwrap());
        assert!(verify_bytes(
            b"abc",
            HashAlgorithm::Sha256,
            &expected.to_uppercase()
        )
        .unwrap());
        assert!(!verify_bytes(
            b"abd",
            HashAlgorithm::Sha256,
            &expected
        )
        .unwrap());
    }

    #[test]
    fn byte_slice_verification_rejects_malformed_digests() {
        assert!(matches!(
            verify_bytes(b"abc", HashAlgorithm::Sha256, "abcd"),
            Err(CryptoError::InvalidDigestLength {
                algorithm: HashAlgorithm::Sha256,
                expected: 64,
                actual: 4
            })
        ));
        let invalid = "g".to_owned() + &"0".repeat(63);
        assert!(matches!(
            verify_bytes(b"abc", HashAlgorithm::Sha256, &invalid),
            Err(CryptoError::InvalidHexCharacter { index: 0, byte: b'g' })
        ));
    }

    #[test]
    fn verifies_streams_and_propagates_reader_errors() {
        use std::io::Cursor;

        for algorithm in [HashAlgorithm::Sha256, HashAlgorithm::Sha512] {
            let expected = hash_bytes(b"stream payload", algorithm);
            assert!(verify_reader(&mut Cursor::new(b"stream payload"), algorithm, &expected).unwrap());
            assert!(!verify_reader(&mut Cursor::new(b"modified payload"), algorithm, &expected).unwrap());
        }

        let error = verify_reader(&mut FailingReader, HashAlgorithm::Sha256, &"0".repeat(64))
            .unwrap_err();
        assert!(matches!(error, CryptoError::ReaderIo(ref source) if source.kind() == io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn stream_verification_rejects_invalid_digest_before_reading() {
        let error = verify_reader(&mut FailingReader, HashAlgorithm::Sha256, "bad").unwrap_err();
        assert!(matches!(error, CryptoError::InvalidDigestLength { .. }));
    }

    #[test]
    fn rejects_invalid_digest_length() {
        let file = TestFile::new(b"abc");
        let error = verify_file(&file.path, HashAlgorithm::Sha256, "abcd").unwrap_err();
        assert!(matches!(
            error,
            CryptoError::InvalidDigestLength {
                algorithm: HashAlgorithm::Sha256,
                expected: 64,
                actual: 4
            }
        ));
    }

    #[test]
    fn rejects_non_hexadecimal_digest() {
        let file = TestFile::new(b"abc");
        let invalid = "g".to_owned() + &"0".repeat(63);
        let error =
            verify_file(&file.path, HashAlgorithm::Sha256, &invalid).unwrap_err();
        assert!(matches!(
            error,
            CryptoError::InvalidHexCharacter { index: 0, byte: b'g' }
        ));
    }

    #[test]
    fn validates_digest_before_opening_file() {
        let missing = std::env::temp_dir().join("infernex-definitely-missing-crypto-file");
        let error = verify_file(&missing, HashAlgorithm::Sha256, "not-a-digest").unwrap_err();
        assert!(matches!(error, CryptoError::InvalidDigestLength { .. }));
    }

    #[test]
    fn reports_missing_file_with_path() {
        let missing = std::env::temp_dir().join(format!(
            "infernex-missing-crypto-{}",
            NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let error = hash_file(&missing, HashAlgorithm::Sha256).unwrap_err();
        match error {
            CryptoError::Io { path, source } => {
                assert_eq!(path, missing);
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected I/O error, got {other}"),
        }
    }

    struct InterruptOnceReader {
        interrupted: bool,
        bytes: &'static [u8],
        offset: usize,
    }

    impl Read for InterruptOnceReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let remaining = &self.bytes[self.offset..];
            if remaining.is_empty() {
                return Ok(0);
            }
            let count = remaining.len().min(buffer.len());
            buffer[..count].copy_from_slice(&remaining[..count]);
            self.offset += count;
            Ok(count)
        }
    }

    #[test]
    fn retries_interrupted_reads() {
        let mut reader = InterruptOnceReader {
            interrupted: false,
            bytes: b"abc",
            offset: 0,
        };
        assert_eq!(
            hash_reader(&mut reader, HashAlgorithm::Sha256).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "test read failure"))
        }
    }

    #[test]
    fn propagates_non_interrupted_read_errors() {
        let error = hash_reader(&mut FailingReader, HashAlgorithm::Sha256).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn percent_encodes_rfc3986_component_bytes() {
        assert_eq!(
            percent_encode(b"AZaz09-._~ /?&=+"),
            "AZaz09-._~%20%2F%3F%26%3D%2B"
        );
    }

    #[test]
    fn percent_decodes_binary_data_and_mixed_case_escapes() {
        assert_eq!(
            percent_decode("%00%ff%aB%7e").unwrap(),
            vec![0x00, 0xff, 0xab, b'~']
        );
    }

    #[test]
    fn percent_round_trip_preserves_arbitrary_bytes() {
        let bytes = [0, 0xff, 0x80, b'%', b'+', b' ', b'~'];
        assert_eq!(percent_decode(&percent_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn percent_decode_does_not_convert_plus_to_space() {
        assert_eq!(percent_decode("a+b%2Bc").unwrap(), b"a+b+c".to_vec());
    }

    #[test]
    fn percent_decode_rejects_incomplete_or_invalid_escapes() {
        for invalid in ["%", "%0", "%GG", "ok%2x", "a%0g"] {
            let error = percent_decode(invalid).unwrap_err();
            assert!(matches!(
                error,
                CryptoError::InvalidPercentEncoding { .. }
            ));
        }
        assert!(matches!(
            percent_decode("ok%2x").unwrap_err(),
            CryptoError::InvalidPercentEncoding { index: 2 }
        ));
    }

    #[test]
    fn base64url_matches_rfc4648_url_safe_vectors() {
        let vectors = [
            (b"" as &[u8], ""),
            (b"f", "Zg"),
            (b"fo", "Zm8"),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg"),
            (b"fooba", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy"),
            (b"\xfb\xff", "-_8"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(base64url_encode(plain), encoded);
            assert_eq!(base64url_decode(encoded).unwrap(), plain);
        }
    }

    #[test]
    fn base64url_accepts_canonical_padding_and_rejects_invalid_alphabet() {
        assert_eq!(base64url_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64url_decode("Zm8=").unwrap(), b"fo");
        for invalid in ["Zg=", "Zg===", "Zg==AAAA", "Z+8", "Z/8", "A", "Zh"] {
            assert!(
                base64url_decode(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn base64_matches_rfc4648_test_vectors() {
        let vectors = [
            (b"" as &[u8], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(base64_encode(plain), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), plain);
        }
    }

    #[test]
    fn base64_round_trips_arbitrary_binary_bytes() {
        let bytes = [0x00, 0xff, 0x80, 0x7f, 0x01, 0x02, 0x03, 0xfe];
        assert_eq!(base64_decode(&base64_encode(&bytes)).unwrap(), bytes);
    }

    #[test]
    fn base64_rejects_incomplete_groups_and_invalid_characters() {
        assert!(matches!(
            base64_decode("Zg="),
            Err(CryptoError::InvalidBase64 { index: 3 })
        ));
        assert!(matches!(
            base64_decode("Zm9v$"),
            Err(CryptoError::InvalidBase64 { index: 5 })
        ));
        assert!(matches!(
            base64_decode("Zm9v\n"),
            Err(CryptoError::InvalidBase64 { index: 5 })
        ));
    }

    #[test]
    fn base64_rejects_malformed_and_noncanonical_padding() {
        for invalid in ["=m9v", "Z=g=", "Zm=8", "Zm9=", "Zg=A", "Zg==AAAA", "Zh==", "Zm9="] {
            assert!(base64_decode(invalid).is_err(), "accepted {invalid:?}");
        }
        assert!(matches!(
            base64_decode("Zm9="),
            Err(CryptoError::InvalidBase64 { index: 3 })
        ));
    }

    #[test]
    fn creates_and_verifies_manifest_for_multiple_files() {
        let first = TestFile::new(b"first file");
        let second = TestFile::new(&[0, 0xff, 0x80, 1]);
        let paths = [&first.path, &second.path];
        let manifest = create_manifest(&paths, HashAlgorithm::Sha256).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        let checks = verify_manifest(&manifest).unwrap();
        assert_eq!(checks.len(), 2);
        assert!(checks.iter().all(|check| check.matches));
    }

    #[test]
    fn manifest_reports_modified_file_without_hiding_actual_digest() {
        let file = TestFile::new(b"original");
        let paths = [&file.path];
        let mut manifest = create_manifest(&paths, HashAlgorithm::Sha512).unwrap();
        fs::write(&file.path, b"modified").unwrap();

        let checks = verify_manifest(&manifest).unwrap();
        assert_eq!(checks.len(), 1);
        assert!(!checks[0].matches);
        assert_ne!(checks[0].expected_digest, checks[0].actual_digest);

        manifest.entries[0].digest = "invalid".to_owned();
        assert!(matches!(
            verify_manifest(&manifest).unwrap_err(),
            CryptoError::InvalidDigestLength { .. }
        ));
    }

    #[test]
    fn manifest_report_aggregates_matching_and_modified_files() {
        let matching = TestFile::new(b"unchanged");
        let modified = TestFile::new(b"before");
        let paths = [&matching.path, &modified.path];
        let mut manifest = create_manifest(&paths, HashAlgorithm::Sha256).unwrap();
        fs::write(&modified.path, b"after").unwrap();

        let report = verify_manifest_report(&manifest).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.matched, 1);
        assert_eq!(report.mismatched, 1);
        assert_eq!(report.checks.len(), 2);
        assert!(report.checks[0].matches);
        assert!(!report.checks[1].matches);
        assert_eq!(report.checks[1].path, modified.path);

        manifest.entries.clear();
        let empty = verify_manifest_report(&manifest).unwrap();
        assert_eq!(empty.total, 0);
        assert_eq!(empty.matched, 0);
        assert_eq!(empty.mismatched, 0);
    }

    #[test]
    fn empty_manifest_is_valid() {
        let manifest = HashManifest {
            algorithm: HashAlgorithm::Sha256,
            entries: Vec::new(),
        };
        assert!(verify_manifest(&manifest).unwrap().is_empty());
    }
    #[test]
    fn manifest_preserves_caller_path_order() {
        let first = TestFile::new(b"first");
        let second = TestFile::new(b"second");
        let paths = [&second.path, &first.path];
        let manifest = create_manifest(&paths, HashAlgorithm::Sha256).unwrap();

        assert_eq!(manifest.entries[0].path, second.path);
        assert_eq!(manifest.entries[1].path, first.path);
    }

    #[test]
    fn manifest_reports_missing_file_with_path() {
        let file = TestFile::new(b"present");
        let manifest = create_manifest(&[&file.path], HashAlgorithm::Sha256).unwrap();
        fs::remove_file(&file.path).unwrap();

        match verify_manifest(&manifest).unwrap_err() {
            CryptoError::Io { path, source } => {
                assert_eq!(path, file.path);
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("expected path-aware I/O error, got {other}"),
        }
    }

    #[test]
    fn manifest_rejects_malformed_digest_before_opening_file() {
        let missing = std::env::temp_dir().join("infernex-missing-manifest-target");
        let manifest = HashManifest {
            algorithm: HashAlgorithm::Sha256,
            entries: vec![FileHashRecord {
                path: missing,
                digest: "z".repeat(64),
            }],
        };

        assert!(matches!(
            verify_manifest(&manifest).unwrap_err(),
            CryptoError::InvalidHexCharacter { index: 0, byte: b'z' }
        ));
    }

    #[test]
    fn manifest_digest_comparison_is_case_insensitive() {
        let file = TestFile::new(b"case-insensitive");
        let mut manifest = create_manifest(&[&file.path], HashAlgorithm::Sha256).unwrap();
        manifest.entries[0].digest.make_ascii_uppercase();

        let checks = verify_manifest(&manifest).unwrap();
        assert!(checks[0].matches);
    }

    #[test]
    fn mixed_algorithm_manifest_verifies_each_file_with_its_recorded_algorithm() {
        let sha256_file = TestFile::new(b"sha256 content");
        let sha512_file = TestFile::new(b"sha512 content");
        let files = [
            (&sha256_file.path, HashAlgorithm::Sha256),
            (&sha512_file.path, HashAlgorithm::Sha512),
        ];
        let manifest = create_manifest_v2(&files).unwrap();

        assert_eq!(manifest.entries[0].algorithm, HashAlgorithm::Sha256);
        assert_eq!(manifest.entries[1].algorithm, HashAlgorithm::Sha512);
        let report = verify_manifest_v2_report(&manifest).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.matched, 2);
        assert_eq!(report.mismatched, 0);
        assert!(report.checks.iter().all(|check| check.matches));
    }

    #[test]
    fn mixed_algorithm_manifest_reports_mismatch_and_rejects_invalid_digest() {
        let first = TestFile::new(b"before");
        let second = TestFile::new(b"stable");
        let files = [
            (&first.path, HashAlgorithm::Sha256),
            (&second.path, HashAlgorithm::Sha512),
        ];
        let mut manifest = create_manifest_v2(&files).unwrap();
        fs::write(&first.path, b"after").unwrap();

        let report = verify_manifest_v2_report(&manifest).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.matched, 1);
        assert_eq!(report.mismatched, 1);
        assert!(!report.checks[0].matches);
        assert!(report.checks[1].matches);

        manifest.entries[1].digest = "invalid".to_owned();
        assert!(matches!(
            verify_manifest_v2(&manifest).unwrap_err(),
            CryptoError::InvalidDigestLength {
                algorithm: HashAlgorithm::Sha512,
                ..
            }
        ));
    }

    #[test]
    fn mixed_algorithm_manifest_accepts_empty_input() {
        let manifest = HashManifestV2 { entries: Vec::new() };
        let report = verify_manifest_v2_report(&manifest).unwrap();
        assert_eq!(report.total, 0);
        assert_eq!(report.matched, 0);
        assert_eq!(report.mismatched, 0);
        assert!(report.checks.is_empty());
    }

}
