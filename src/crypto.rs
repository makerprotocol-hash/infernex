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

/// Maximum amount of file data held in memory while hashing.
pub const HASH_BUFFER_SIZE: usize = 64 * 1024;

/// Hash algorithm supported by the native INFERNEX file-integrity module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha256,
    Sha512,
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
    /// A supplied checksum has the wrong number of hexadecimal characters.
    InvalidDigestLength {
        algorithm: HashAlgorithm,
        expected: usize,
        actual: usize,
    },
    /// A supplied checksum contains a non-ASCII-hexadecimal byte.
    InvalidHexCharacter { index: usize, byte: u8 },
    /// A percent-encoded URL component contains an incomplete or invalid escape.
    InvalidPercentEncoding { index: usize },
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "cannot read '{}': {source}", path.display())
            }
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
            Self::InvalidPercentEncoding { index } => write!(
                f,
                "invalid percent escape at byte {index}: expected two hexadecimal digits"
            ),
        }
    }
}

impl std::error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidDigestLength { .. }
            | Self::InvalidHexCharacter { .. }
            | Self::InvalidPercentEncoding { .. } => None,
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
    let path = path.as_ref();
    let mut file = File::open(path).map_err(|source| CryptoError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    match algorithm {
        HashAlgorithm::Sha256 => hash_reader::<Sha256, _>(&mut file).map_err(|source| {
            CryptoError::Io {
                path: path.to_path_buf(),
                source,
            }
        }),
        HashAlgorithm::Sha512 => hash_reader::<Sha512, _>(&mut file).map_err(|source| {
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
    match algorithm {
        HashAlgorithm::Sha256 => digest_to_hex(Sha256::digest(data)),
        HashAlgorithm::Sha512 => digest_to_hex(Sha512::digest(data)),
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

        let high = hex_value(input[index + 1])
            .ok_or(CryptoError::InvalidPercentEncoding { index })?;
        let low = hex_value(input[index + 2])
            .ok_or(CryptoError::InvalidPercentEncoding { index })?;

        decoded.push((high << 4) | low);
        index += 3;
    }

    Ok(decoded)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn digest_to_hex(digest: impl AsRef<[u8]>) -> String {
    digest
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

fn hash_reader<D: Digest + Default, R: Read>(reader: &mut R) -> io::Result<String> {
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

    Ok(digest_to_hex(hasher.finalize()))
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
            format!("{:x}", Sha256::digest(bytes))
        );
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            format!("{:x}", Sha512::digest(bytes))
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
            format!("{:x}", Sha256::digest(&bytes))
        );
        assert_eq!(
            hash_file(&file.path, HashAlgorithm::Sha512).unwrap(),
            format!("{:x}", Sha512::digest(&bytes))
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
            hash_reader::<Sha256, _>(&mut reader).unwrap(),
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
        let error = hash_reader::<Sha256, _>(&mut FailingReader).unwrap_err();
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

}
