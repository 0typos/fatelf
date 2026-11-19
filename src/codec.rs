//! Bounded object compression, public header encoding, and authenticated encryption.

use serde::{Deserialize, Serialize};

use crate::Error;

#[cfg(feature = "encryption")]
use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305, XNonce};
#[cfg(feature = "encryption")]
use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt, path::Path};
#[cfg(feature = "encryption")]
use zeroize::{Zeroize, Zeroizing};

/// Hard ceiling on an object's original or unencrypted stored bytes.
pub(crate) const MAX_OBJECT: usize = 1024 * 1024;
/// XChaCha20-Poly1305 appends one authentication tag to each stored object.
pub(crate) const TAG_LENGTH: usize = 16;

/// Requested build-time compression; raw fallback remains available.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[cfg(any(feature = "builder", test))]
#[serde(rename_all = "lowercase")]
#[cfg_attr(feature = "builder", derive(clap::ValueEnum))]
pub(crate) enum Compression {
    #[default]
    None,
    Lz4,
}

/// Actual object decompression recorded after any raw fallback.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum StoredCodec {
    Raw,
    Lz4Block,
}

/// Public reversible encoding applied to source bytes before compression.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Encoding {
    Identity,
    ElfHeaderXorA5,
}

/// External-key identity and fresh nonce needed to authenticate a stored object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Encryption {
    pub(crate) key: String,
    #[serde(with = "nonce_hex")]
    pub(crate) nonce: [u8; 24],
}

/// Fixed-width nonce text keeps manifest length independent of random nonce bytes.
mod nonce_hex {
    use std::fmt;

    use serde::{
        Deserializer, Serializer,
        de::{self, Visitor},
    };

    /// Serialize every nonce as exactly 48 lowercase hexadecimal characters.
    pub(super) fn serialize<S: Serializer>(
        nonce: &[u8; 24],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(48);
        for byte in nonce {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 15)]));
        }
        serializer.serialize_str(&text)
    }

    /// Reject nonce strings outside the canonical fixed-width lowercase form.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 24], D::Error> {
        deserializer.deserialize_str(NonceVisitor)
    }

    /// Decode bounded nonce text without an input-sized allocation.
    struct NonceVisitor;

    impl<'de> Visitor<'de> for NonceVisitor {
        type Value = [u8; 24];

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("exactly 48 lowercase hexadecimal nonce characters")
        }

        fn visit_str<E: de::Error>(self, text: &str) -> Result<Self::Value, E> {
            if text.len() != 48 {
                return Err(E::custom(
                    "nonce must have exactly 48 lowercase hexadecimal characters",
                ));
            }
            let mut nonce = [0; 24];
            for (index, pair) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
                let high = nibble(pair[0])
                    .ok_or_else(|| E::custom("nonce must be lowercase hexadecimal"))?;
                let low = nibble(pair[1])
                    .ok_or_else(|| E::custom("nonce must be lowercase hexadecimal"))?;
                nonce[index] = high * 16 + low;
            }
            Ok(nonce)
        }
    }

    /// Accept the canonical lowercase ASCII hexadecimal alphabet only.
    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        }
    }
}

/// Encode source bytes and retain LZ4 only when it is strictly smaller.
#[cfg(any(feature = "builder", test))]
pub(crate) fn prepare(
    bytes: &[u8],
    compression: Compression,
    encoding: Encoding,
) -> Result<(Vec<u8>, StoredCodec), Error> {
    validate_length(bytes.len())?;
    let mut source = bytes.to_vec();
    apply_encoding(&mut source, encoding);
    if compression == Compression::None {
        return Ok((source, StoredCodec::Raw));
    }
    #[cfg(feature = "compression")]
    {
        let capacity = lz4_flex::block::get_maximum_output_size(source.len());
        if capacity > 2 * MAX_OBJECT {
            return Err(Error::Invalid(
                "compression scratch exceeds its limit".into(),
            ));
        }
        let mut compressed = vec![0; capacity];
        let written = lz4_flex::block::compress_into(&source, &mut compressed)
            .map_err(|_| Error::Invalid("LZ4 object compression failed".into()))?;
        if written < source.len() {
            compressed.truncate(written);
            return Ok((compressed, StoredCodec::Lz4Block));
        }
        Ok((source, StoredCodec::Raw))
    }
    #[cfg(not(feature = "compression"))]
    {
        Err(Error::Invalid(
            "this binary does not support LZ4 compression".into(),
        ))
    }
}

/// Decode into an exact bounded output, then restore original source bytes.
pub(crate) fn decode(
    mut bytes: Vec<u8>,
    decoded_length: usize,
    codec: StoredCodec,
    encoding: Encoding,
) -> Result<Vec<u8>, Error> {
    validate_length(decoded_length)?;
    validate_length(bytes.len())?;
    match codec {
        StoredCodec::Raw => {
            if bytes.len() != decoded_length {
                return Err(Error::Invalid(
                    "raw object length does not match decoded length".into(),
                ));
            }
        }
        StoredCodec::Lz4Block => {
            if bytes.len() >= decoded_length {
                return Err(Error::Invalid(
                    "LZ4 object must be smaller than its decoded bytes".into(),
                ));
            }
            #[cfg(feature = "compression")]
            {
                let mut output = vec![0; decoded_length];
                let written = lz4_flex::block::decompress_into(&bytes, &mut output)
                    .map_err(|_| Error::Invalid("invalid LZ4 object".into()))?;
                if written != decoded_length {
                    return Err(Error::Invalid(
                        "LZ4 decoded length does not match manifest".into(),
                    ));
                }
                bytes = output;
            }
            #[cfg(not(feature = "compression"))]
            {
                return Err(Error::Invalid(
                    "this binary does not support LZ4 decompression".into(),
                ));
            }
        }
    }
    apply_encoding(&mut bytes, encoding);
    Ok(bytes)
}

/// Encrypt one prepared object, binding the exact manifest and object index.
#[cfg(any(feature = "builder", test))]
pub(crate) fn encrypt(
    bytes: &mut Vec<u8>,
    key: &[u8; 32],
    nonce: &[u8; 24],
    manifest_hash: &[u8; 32],
    object_index: usize,
) -> Result<(), Error> {
    validate_length(bytes.len())?;
    #[cfg(feature = "encryption")]
    {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Invalid("invalid encryption key length".into()))?;
        let aad = associated_data(manifest_hash, object_index)?;
        cipher
            .encrypt_in_place(&XNonce::from(*nonce), &aad, bytes)
            .map_err(|_| Error::Invalid("object encryption failed".into()))
    }
    #[cfg(not(feature = "encryption"))]
    {
        let _ = (key, nonce, manifest_hash, object_index);
        Err(Error::Invalid(
            "this binary does not support encryption".into(),
        ))
    }
}

/// Authenticate before exposing prepared bytes to decompression or reconstruction.
#[cfg(any(feature = "encryption", test))]
pub(crate) fn decrypt(
    bytes: &mut Vec<u8>,
    key: &[u8; 32],
    nonce: &[u8; 24],
    manifest_hash: &[u8; 32],
    object_index: usize,
) -> Result<(), Error> {
    if bytes.len() <= TAG_LENGTH || bytes.len() > MAX_OBJECT + TAG_LENGTH {
        return Err(Error::Invalid(
            "encrypted object length exceeds supported bounds".into(),
        ));
    }
    #[cfg(feature = "encryption")]
    {
        let cipher = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| Error::Invalid("invalid encryption key length".into()))?;
        let aad = associated_data(manifest_hash, object_index)?;
        if cipher
            .decrypt_in_place(&XNonce::from(*nonce), &aad, bytes)
            .is_err()
        {
            bytes.zeroize();
            return Err(Error::Invalid("object authentication failed".into()));
        }
        Ok(())
    }
    #[cfg(not(feature = "encryption"))]
    {
        let _ = (key, nonce, manifest_hash, object_index);
        Err(Error::Invalid(
            "this binary does not support decryption".into(),
        ))
    }
}

/// Obtain a fresh OS nonce; random-source failures abort packing.
#[cfg(any(feature = "builder", test))]
pub(crate) fn random_nonce() -> Result<[u8; 24], Error> {
    #[cfg(feature = "encryption")]
    {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce)
            .map_err(|_| Error::Invalid("OS nonce generation failed".into()))?;
        Ok(nonce)
    }
    #[cfg(not(feature = "encryption"))]
    {
        Err(Error::Invalid(
            "this binary does not support encryption".into(),
        ))
    }
}

/// Read exactly 32 raw key bytes from a regular file without unbounded allocation.
#[cfg(feature = "encryption")]
pub(crate) fn read_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid("key source must be a regular file".into()));
    }
    let mut scratch = Zeroizing::new([0; 33]);
    let mut length = 0;
    while length < scratch.len() {
        let count = file.read(&mut scratch[length..])?;
        if count == 0 {
            break;
        }
        length += count;
    }
    if length != 32 {
        return Err(Error::Invalid(
            "key file must contain exactly 32 raw bytes".into(),
        ));
    }
    let mut key = Zeroizing::new([0; 32]);
    key.copy_from_slice(&scratch[..32]);
    Ok(key)
}

/// Reject empty objects and oversized buffers before encoding or allocation.
fn validate_length(length: usize) -> Result<(), Error> {
    if length == 0 || length > MAX_OBJECT {
        return Err(Error::Invalid(
            "object length must be between 1 byte and 1 MiB".into(),
        ));
    }
    Ok(())
}

/// Apply the fixed public header mask; the operation is its own inverse.
fn apply_encoding(bytes: &mut [u8], encoding: Encoding) {
    if encoding == Encoding::ElfHeaderXorA5 {
        for byte in bytes {
            *byte ^= 0xa5;
        }
    }
}

/// Bind ciphertext to the exact versioned manifest and logical object identity.
#[cfg(feature = "encryption")]
fn associated_data(manifest_hash: &[u8; 32], object_index: usize) -> Result<[u8; 57], Error> {
    let index = u64::try_from(object_index)
        .map_err(|_| Error::Invalid("object index exceeds supported bounds".into()))?;
    let mut aad = [0; 57];
    aad[..17].copy_from_slice(b"fatelf-v2-object\0");
    aad[17..49].copy_from_slice(manifest_hash);
    aad[49..].copy_from_slice(&index.to_le_bytes());
    Ok(aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_json_is_canonical_fixed_width_and_round_trips() {
        let nonce = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 255,
        ];
        let encryption = Encryption {
            key: "ps".into(),
            nonce,
        };
        let json = serde_json::to_string(&encryption).unwrap();
        assert_eq!(
            json,
            r#"{"key":"ps","nonce":"000102030405060708090a0b0c0d0e0f10111213141516ff"}"#
        );
        assert_eq!(
            serde_json::from_str::<Encryption>(&json).unwrap().nonce,
            nonce
        );
        let low = serde_json::to_string(&Encryption {
            key: "ps".into(),
            nonce: [0; 24],
        })
        .unwrap();
        let high = serde_json::to_string(&Encryption {
            key: "ps".into(),
            nonce: [255; 24],
        })
        .unwrap();
        assert_eq!(
            low.len(),
            high.len(),
            "random nonces must not change planned manifest length"
        );
    }

    #[test]
    fn nonce_json_rejects_wrong_width_nonhex_and_noncanonical_text() {
        for nonce in [
            "0".repeat(47),
            "0".repeat(49),
            "g".repeat(48),
            "A".repeat(48),
            "é".repeat(24),
        ] {
            let json = serde_json::json!({"key": "ps", "nonce": nonce});
            assert!(serde_json::from_value::<Encryption>(json).is_err());
        }
        let error = match serde_json::from_value::<Encryption>(
            serde_json::json!({"key": "ps", "nonce": vec![0; 24]}),
        ) {
            Ok(_) => panic!("an array must not be accepted as a nonce"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("exactly 48 lowercase hexadecimal nonce characters")
        );
    }

    #[test]
    fn header_encoding_survives_raw_storage_and_reconstructs_exact_bytes() {
        let header = b"\x7fELF\x02\x01\x01\0";
        let (stored, codec) = prepare(header, Compression::None, Encoding::ElfHeaderXorA5).unwrap();
        assert_ne!(stored, header);
        assert_ne!(&stored[..4], b"\x7fELF");
        assert_eq!(
            decode(stored, header.len(), codec, Encoding::ElfHeaderXorA5).unwrap(),
            header
        );
    }

    #[test]
    fn object_limits_reject_empty_oversized_and_wrong_raw_length() {
        assert!(prepare(&[], Compression::None, Encoding::Identity).is_err());
        assert!(
            prepare(
                &vec![0; MAX_OBJECT + 1],
                Compression::None,
                Encoding::Identity
            )
            .is_err()
        );
        assert!(
            decode(
                vec![1],
                MAX_OBJECT + 1,
                StoredCodec::Raw,
                Encoding::Identity
            )
            .is_err()
        );
        assert!(decode(vec![1], 2, StoredCodec::Raw, Encoding::Identity).is_err());
        assert!(
            decode(
                vec![0; MAX_OBJECT + 1],
                1,
                StoredCodec::Raw,
                Encoding::Identity
            )
            .is_err()
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn incompressible_header_fallback_keeps_encoding() {
        let header = b"\x7fELF\x02\x01\x01\0";
        let (stored, codec) = prepare(header, Compression::Lz4, Encoding::ElfHeaderXorA5).unwrap();
        assert_eq!(codec, StoredCodec::Raw);
        assert_ne!(stored, header);
        assert_eq!(
            decode(stored, header.len(), codec, Encoding::ElfHeaderXorA5).unwrap(),
            header
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn compressed_masked_objects_restore_original_source() {
        let original = vec![0x7f; 4096];
        let (stored, codec) =
            prepare(&original, Compression::Lz4, Encoding::ElfHeaderXorA5).unwrap();
        assert_eq!(codec, StoredCodec::Lz4Block);
        assert!(stored.len() < original.len());
        assert_eq!(
            decode(stored, original.len(), codec, Encoding::ElfHeaderXorA5).unwrap(),
            original
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn independent_lz4_block_restores_literals_and_overlap_match() {
        // One literal A, an offset-one match of 19 bytes, then five literals.
        let stored = vec![0x1f, b'A', 1, 0, 0, 0x50, b'b', b'c', b'd', b'e', b'f'];
        let mut expected = vec![b'A'; 20];
        expected.extend_from_slice(b"bcdef");
        assert_eq!(
            decode(stored, 25, StoredCodec::Lz4Block, Encoding::Identity).unwrap(),
            expected
        );
    }

    #[cfg(feature = "compression")]
    #[test]
    fn lz4_rejects_truncated_blocks_overexpansion_and_wrong_output_length() {
        // An independent raw-block literal vector: token 0x30 and three literals.
        assert!(
            decode(
                vec![0x30, b'a', b'b', b'c'],
                8,
                StoredCodec::Lz4Block,
                Encoding::Identity
            )
            .is_err()
        );
        assert!(decode(vec![0xf0], 64, StoredCodec::Lz4Block, Encoding::Identity).is_err());
        let (stored, codec) =
            prepare(&vec![1; 4096], Compression::Lz4, Encoding::Identity).unwrap();
        assert!(decode(stored.clone(), 2048, codec, Encoding::Identity).is_err());
        assert!(decode(stored, 8192, codec, Encoding::Identity).is_err());
    }

    #[cfg(feature = "compression")]
    #[test]
    fn a_one_mib_object_can_be_compressed_and_decoded() {
        let original = vec![7; 1_048_576];
        let (stored, codec) = prepare(&original, Compression::Lz4, Encoding::Identity).unwrap();
        assert_eq!(codec, StoredCodec::Lz4Block);
        assert_eq!(
            decode(stored, original.len(), codec, Encoding::Identity).unwrap(),
            original
        );
    }

    #[cfg(not(feature = "compression"))]
    #[test]
    fn unavailable_compression_fails_explicitly() {
        assert!(prepare(&[1; 64], Compression::Lz4, Encoding::Identity).is_err());
        assert!(decode(vec![0], 64, StoredCodec::Lz4Block, Encoding::Identity).is_err());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn ciphertext_authenticates_key_nonce_manifest_and_object_identity() {
        let key = [3; 32];
        let nonce = [7; 24];
        let hash = [11; 32];
        let original = b"prepared payload".to_vec();
        let mut ciphertext = original.clone();
        encrypt(&mut ciphertext, &key, &nonce, &hash, 17).unwrap();
        assert_eq!(ciphertext.len(), original.len() + TAG_LENGTH);
        let mut restored = ciphertext.clone();
        decrypt(&mut restored, &key, &nonce, &hash, 17).unwrap();
        assert_eq!(restored, original);
        for (candidate_key, candidate_nonce, candidate_hash, index) in [
            ([4; 32], nonce, hash, 17),
            (key, [8; 24], hash, 17),
            (key, nonce, [12; 32], 17),
            (key, nonce, hash, 18),
        ] {
            let mut altered = ciphertext.clone();
            assert!(
                decrypt(
                    &mut altered,
                    &candidate_key,
                    &candidate_nonce,
                    &candidate_hash,
                    index
                )
                .is_err()
            );
            assert!(altered.is_empty());
        }
        let mut altered = ciphertext;
        altered[0] ^= 1;
        assert!(decrypt(&mut altered, &key, &nonce, &hash, 17).is_err());
        assert!(altered.is_empty());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn key_files_are_exact_length_and_regular_files_only() {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&[9; 32]).unwrap();
        assert_eq!(*read_key(file.path()).unwrap(), [9; 32]);
        file.write_all(&[9]).unwrap();
        assert!(read_key(file.path()).is_err());
        let empty = tempfile::NamedTempFile::new().unwrap();
        assert!(read_key(empty.path()).is_err());
        let directory = tempfile::tempdir().unwrap();
        assert!(read_key(directory.path()).is_err());
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn nonces_are_fresh_and_ciphertext_lengths_are_bounded() {
        let first = random_nonce().unwrap();
        assert_ne!(first, random_nonce().unwrap());
        assert!(decrypt(&mut vec![0; TAG_LENGTH], &[0; 32], &first, &[0; 32], 0).is_err());
        assert!(
            decrypt(
                &mut vec![0; MAX_OBJECT + TAG_LENGTH + 1],
                &[0; 32],
                &first,
                &[0; 32],
                0
            )
            .is_err()
        );
    }

    #[cfg(feature = "encryption")]
    #[test]
    fn authenticated_object_length_must_still_be_within_the_format_bounds() {
        let key = [0; 32];
        let nonce = [0; 24];
        let mut aad = [0; 57];
        aad[..17].copy_from_slice(b"fatelf-v2-object\0");
        let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
        for (length, valid) in [(0, false), (1_048_576, true), (1_048_577, false)] {
            let mut ciphertext = vec![7; length];
            cipher
                .encrypt_in_place(&XNonce::from(nonce), &aad, &mut ciphertext)
                .unwrap();
            let result = decrypt(&mut ciphertext, &key, &nonce, &[0; 32], 0);
            assert_eq!(
                result.is_ok(),
                valid,
                "authenticated plaintext length {length}"
            );
            if valid {
                assert_eq!(ciphertext, vec![7; length]);
            }
        }
    }

    #[cfg(not(feature = "encryption"))]
    #[test]
    fn unavailable_encryption_fails_explicitly() {
        assert!(random_nonce().is_err());
        assert!(encrypt(&mut vec![1], &[0; 32], &[0; 24], &[0; 32], 0).is_err());
        assert!(
            decrypt(
                &mut vec![0; TAG_LENGTH + 1],
                &[0; 32],
                &[0; 24],
                &[0; 32],
                0
            )
            .is_err()
        );
    }
}
