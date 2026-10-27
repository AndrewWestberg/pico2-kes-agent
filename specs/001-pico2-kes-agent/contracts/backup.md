# Initial-key artifact and local restoration contract

## Format decision

Adopt the predecessor forge `KESBKP01` version-1 format, not the older Pico HSM binary artifact. Compatibility includes its existing domain strings: changing project names in cryptographic domains would break byte compatibility. Governing sources are `cardano-kes-forge/crates/kes-core/src/backup.rs` and `cardano-kes-forge/src/backup/recover.rs` at the research source pin; maintain local reviewed code rather than depending on a mutable sibling path. RFC 9180 governs HPKE. Cardano's pinned Sum6KES codec governs secret-state encoding.

The artifact is 8-byte ASCII `KESBKP01` followed by the predecessor's deterministic CBOR map, at most 2,048 bytes. No indefinite lengths, duplicate keys, unknown fields, noncanonical encodings or trailing bytes are accepted. The signed map has exactly 16 fields; the unsigned map omits `device_signature` and has 15; the header omits `encapsulation`, `ciphertext` and `device_signature` and has 13. Preserve source-defined field order and encoded bytes in interoperability vectors.

| Field | Type / constraint |
|---|---|
| `version` | Integer 1 |
| `kem`, `kdf`, `aead` | Integers 32, 1, 3: X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20-Poly1305 |
| `device`, `pool`, `incarnation`, `generation` | Respectively 16, 28, 16 and 16 identity bytes; pool is the Cardano Blake2b-224 cold-key hash |
| `generation_number` | Positive monotonic generation number |
| `verification_key` | 32-byte Sum6KES root verification key |
| `period` | Integer 0 only |
| `recipient_public_key`, `recipient_id` | 32-byte X25519 public key; SHA-256 of that exact key |
| `encapsulation` | 32-byte HPKE encapsulated key |
| `ciphertext` | 624 bytes: the exact 608-byte initial state plus 16-byte AEAD tag |
| `device_signature` | 64-byte Ed25519 signature verified against the separately trusted device identity key |

HPKE base-mode `info` is ASCII `cardano-kes-forge/backup/v1` concatenated with the encoded header. AEAD associated data is magic concatenated with the header. Ed25519 signs ASCII `cardano-kes-forge/backup-signature/v1` followed by magic followed by the unsigned map. Authentication of origin is the Ed25519 signature, not a claim that HPKE base mode authenticates its sender. The expected device identity public key must come from the operator's attended device enrollment record, not an untrusted key supplied by the artifact itself.

## Generation and retirement

Generation uses health-checked device entropy; no caller seed or plaintext import exists. Construct the period-zero state, produce exactly one artifact using a snapshot of the shared recipient policy, and durably commit it with the new staged generation and automatic-activation intent before returning success. Public export retrieval does not authorize a second encryption and has no recipient override. It returns the same retained bytes even after evolution, daemon restart or recipient-policy change.

Uncertified generations stay at period zero. A valid certificate and period context cause ordinary evolution/automatic activation without requiring artifact download, backup acknowledgment, decryption, remote notification or a separate activation command. Download is not a lifecycle transition.

Both active and staged artifacts are retained until their own generation is replaced, expires or is discarded. Pool deletion removes both. Retirement makes device retrieval unavailable even when no copy was downloaded. External copies survive; neither deletion nor recipient-policy change revokes them. Generation/export results disclose this policy and identify the generation. CLI discard/delete warns before submitting the mutation; automatic transitions never wait for acknowledgment.

## Local backup-host commands

`pico2-kes-agent-cli recipient create --out RECIPIENT --public-out PUBLIC` creates one passphrase-protected recipient key file on the backup host, using interactive terminal passphrase input. Reuse the forge recipient-file format and Argon2id/AEAD limits after source review; do not accept passphrases in argv, environment variables or logs. This is custody setup for the required shared recipient, not device provisioning. `recipient set --public-key PUBLIC` is a separate service-connected operation that transmits only the public key.

`pico2-kes-agent-cli restore --artifact ARTIFACT --recipient-key RECIPIENT --device-identity IDENTITY --pool POOL --incarnation INCARNATION --generation GENERATION --verification-key VKEY --out KES_SKEY`

`restore` never opens a management socket or USB device and never invokes a producer. All expected identities are required; there is no trust-on-artifact bypass. It must:

1. Bound and validate input paths, artifact size and canonical structure.
2. Check suite/version, trusted device signature, all expected bindings and recipient fingerprint.
3. Unlock the recipient only in protected backup-host memory; decrypt and require exactly 608 bytes of canonical period-zero Sum6KES state.
4. Validate state and derive its root verification key; require equality with both artifact and expected verification key.
5. Construct a Cardano JSON text envelope with `type: "KesSigningKey_ed25519_kes_2^6"`, a nonsecret description, and `cborHex: "590260" + hex(state)`.
6. Publish an owner-only regular file (mode 0600) in an owner-controlled directory, with no symlink following and atomic no-clobber publication. Validate everything before any plaintext temporary output; fsync the file and parent directory. Refuse an existing output, including a symlink. Remove unpublished temporary files on failure; a crash never exposes a partial usable destination file.
7. Wipe decrypted state, KDF/key scratch and passphrase buffers. Do not claim erasure of external copies or conventional filesystem remnants.

On wrong recipient, malformed/tampered input, identity mismatch or invalid KES state, publish zero usable destination keys and return a non-success exit. Diagnostic output must not contain secret bytes. The explicit restored file is the only intended durable plaintext output and is allowed only in the recipient-host workflow. Deployment must keep the recipient private key off the primary; the utility cannot prove a physical host's role from its hostname.

## Fidelity oracle

Disposable qualification firmware permits a protected in-memory reference to generation-time key0, never a production plaintext initial-export command. Compare recovered state byte-for-byte with that reference, then use the independently pinned Haskell/Cardano text-envelope decoder to extract the same 608 bytes from the published file. Verify the root key and signing compatibility independently. Test wrong recipient, wrong device/pool/incarnation/generation/vkey, every authenticated-field mutation, truncation, output collision and interrupted publication. Destroy the disposable key0 reference; do not write it into evidence. Backup producer runtime/accepted-block tests are explicitly outside this acceptance gate.
