# libdave protocol-glue layer -- host validation tests

These are **not** part of TriCord's 3DS build. They validate the vendored
libdave protocol-glue layer (`src/`) on a normal PC, on top of the Phase 1/2
mlspp core and its mbedTLS backend (see `library/mlspp/host_tests/README.md`).

- `dave_session_lifecycle_test.cpp` -- a full DAVE-level 2-then-3-party voice
  channel lifecycle through `discord::dave::mls::Session`,
  `Encryptor`/`Decryptor`, `MlsKeyRatchet`, and the mbedTLS `Cryptor`: join via
  an externally-signed Add proposal (mirroring how Discord's voice gateway,
  not the client, authors these), Commit/Welcome exchange, Opus frame
  encrypt/decrypt, tamper rejection, a second member joining (epoch
  transition), and a frame still in flight when the transition happens still
  decrypting inside the retained-old-key grace window
  (TOB-DISCE2EC-5 mitigation).
- `dave_frame_processors_fuzz_test.cpp` -- hand-picked edge cases plus 20000
  random malformed frames against the unencrypted-ranges parsing/validation in
  `frame_processors.cpp` (TOB-DISCE2EC-7 mitigation: rejecting frames whose
  declared "unencrypted ranges" metadata could be used to smuggle ciphertext
  as authenticated plaintext, or vice versa). Confirms no crash/UB and correct
  accept/reject behavior, not just on the curated cases.
- `dave_epoch_expiry_test.cpp` -- Phase 6 hardening: a *real* wall-clock test
  of the epoch-transition grace window. `dave_session_lifecycle_test.cpp`
  above only proves an in-flight old-epoch frame still decrypts milliseconds
  after a transition; this test passes `TransitionToKeyRatchet()` a short
  (1s) real expiry and actually `std::this_thread::sleep_for()`s past it,
  then confirms the old epoch's frames are rejected afterwards while the new
  epoch keeps working -- exercising the real `std::chrono::steady_clock`-
  backed `Clock` in `decryptor.h`/`cryptor_manager.h`, no fake/injected clock
  and no changes to that vendored code.

The first two passed when last run (2026-06-18) against mbedTLS 2.28.8
(matching the 3DS portlib version) built from source with clang on Windows
x86_64. `dave_epoch_expiry_test.cpp` was written in a later 2026-06-18
session but **not yet executed** -- that session's sandbox blocked the
mbedTLS source download needed to rebuild the host static lib. It follows
the exact same build recipe as the other two (see below) and should be run
once before relying on it.

## Prerequisite: host mbedTLS build

Same one-time step as `library/mlspp/host_tests/README.md`:

```sh
curl -sL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.8.tar.gz -o mbedtls.tar.gz
tar xzf mbedtls.tar.gz
cd mbedtls-2.28.8/library
mkdir -p ../hostbuild_obj
for f in *.c; do clang -c "$f" -I../include -O1 -o "../hostbuild_obj/${f%.c}.o"; done
llvm-ar rcs ../hostbuild_obj/libmbedcrypto_host.a ../hostbuild_obj/*.o
```

## Building and running

```sh
MBEDTLS=/path/to/mbedtls-2.28.8
MLSPP=library/mlspp
LIBDAVE=library/libdave

INCLUDES="-I$LIBDAVE/include -I$LIBDAVE/src -I$MLSPP/include -I$MLSPP/include/mlspp_namespace -I$MLSPP/lib/bytes/include -I$MLSPP/lib/tls_syntax/include -I$MLSPP/lib/hpke/include -I$MLSPP/lib/hpke/src -I$MBEDTLS/include"

MLSPP_SRCS="$MLSPP/src/common.cpp $MLSPP/src/core_types.cpp $MLSPP/src/credential.cpp $MLSPP/src/crypto.cpp $MLSPP/src/grease.cpp $MLSPP/src/key_schedule.cpp $MLSPP/src/messages.cpp $MLSPP/src/state.cpp $MLSPP/src/tree_math.cpp $MLSPP/src/treekem.cpp"

HPKE_SRCS="$MLSPP/lib/bytes/src/bytes.cpp $MLSPP/lib/tls_syntax/src/tls_syntax.cpp $MLSPP/lib/hpke/src/hpke.cpp $MLSPP/lib/hpke/src/common.cpp $MLSPP/lib/hpke/src/dhkem.cpp $MLSPP/lib/hpke/src/hkdf.cpp $MLSPP/lib/hpke/src/signature.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_common.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_random.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_digest.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_aead_cipher.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_group.cpp"

LIBDAVE_SRCS="$LIBDAVE/src/cryptor.cpp $LIBDAVE/src/cryptor_manager.cpp $LIBDAVE/src/codec_utils.cpp $LIBDAVE/src/encryptor.cpp $LIBDAVE/src/decryptor.cpp $LIBDAVE/src/frame_processors.cpp $LIBDAVE/src/logger.cpp $LIBDAVE/src/version.cpp $LIBDAVE/src/mls_key_ratchet.cpp $LIBDAVE/src/mls/session.cpp $LIBDAVE/src/mls/parameters.cpp $LIBDAVE/src/mls/util.cpp $LIBDAVE/src/mls/user_credential.cpp $LIBDAVE/src/mls/persisted_key_pair_null.cpp $LIBDAVE/src/mbedtls/mbedtls_cryptor.cpp $LIBDAVE/src/utils/leb128.cpp"

clang++ -std=c++17 $INCLUDES $LIBDAVE/host_tests/dave_session_lifecycle_test.cpp \
  $MLSPP_SRCS $HPKE_SRCS $LIBDAVE_SRCS \
  $MBEDTLS/hostbuild_obj/libmbedcrypto_host.a -ladvapi32 \
  -o dave_session_lifecycle_test.exe
./dave_session_lifecycle_test.exe

# The fuzz test only needs the codec-agnostic frame_processors/codec_utils/
# leb128/logger units, not the full mlspp+crypto stack.
clang++ -std=c++17 -I$LIBDAVE/include -I$LIBDAVE/src \
  $LIBDAVE/host_tests/dave_frame_processors_fuzz_test.cpp \
  $LIBDAVE/src/frame_processors.cpp $LIBDAVE/src/codec_utils.cpp \
  $LIBDAVE/src/utils/leb128.cpp $LIBDAVE/src/logger.cpp \
  -o dave_frame_processors_fuzz_test.exe
./dave_frame_processors_fuzz_test.exe

# The epoch-expiry test needs the same mlspp+crypto stack as the lifecycle
# test above (it builds MlsKeyRatchet/Encryptor/Decryptor instances directly)
# plus pthread for std::this_thread::sleep_for on some platforms.
clang++ -std=c++17 $INCLUDES $LIBDAVE/host_tests/dave_epoch_expiry_test.cpp \
  $MLSPP_SRCS $HPKE_SRCS $LIBDAVE_SRCS \
  $MBEDTLS/hostbuild_obj/libmbedcrypto_host.a -ladvapi32 \
  -o dave_epoch_expiry_test.exe
./dave_epoch_expiry_test.exe
```

## What's vendored, what's not, and why

See the file-by-file comments throughout `library/libdave/src/` for what was
trimmed and why; the short version (all the same scope-reduction principle as
Phases 1-2 -- removed outright, not just excluded by a flag):

- **Not vendored at all:** `bindings_capi.cpp`/`bindings_wasm.cpp` (other-
  language bindings, irrelevant for direct C++ embedding by `Discord::DaveSession`
  in Phase 5); `boringssl_cryptor.*`/`openssl_cryptor.*` (replaced by
  `src/mbedtls/mbedtls_cryptor.*`); `mls/detail/*` and `mls/persisted_key_pair.cpp`
  (native/generic per-platform signing-key persistence -- `mls/persisted_key_pair_null.cpp`
  is vendored instead, so every session generates a fresh signing key; avoids
  `std::filesystem` and matches that our trimmed `Signature` backend doesn't
  support the JWK serialization the generic backend would need); `key_ratchet.h`
  (dead/unused upstream -- nothing includes it, `IKeyRatchet` lives in
  `dave_interfaces.h`).
- **Trimmed:** `Codec` enum is Opus-only (TriCord is audio-only, no 3DS video
  calls) -- `codec_utils.cpp`'s VP8/VP9/H264/H265/AV1 frame-splitting and
  `frame_processors.cpp`'s codec switch are cut accordingly.
  `ISession::GetPairwiseFingerprint` (the manual SAS-style identity
  verification in Discord's "Verify End-to-End Encryption" UI) is removed: it
  depends on OpenSSL's `EVP_PBE_scrypt`, which the mbedTLS-only crypto stack
  doesn't provide, and it isn't required for the encrypted call itself to work.
- **Everything else** (the actual MLS-to-SFrame glue: `Session`, `Encryptor`/
  `Decryptor`, `CryptorManager`, `frame_processors`' range validation,
  `MlsKeyRatchet`, `leb128`) is vendored as close to verbatim as possible.

**Pitfall to remember:** `CreateSession()`'s `authSessionId` parameter MUST be
empty. `persisted_key_pair_null.cpp` makes `GetPersistedKeyPair()` always
return `nullptr`, and `Session::InitLeafNode()` only falls back to generating
a fresh signing key when `signingKeyId_` (== `authSessionId`) is empty -- a
non-empty value silently aborts leaf-node init (logged via `DISCORD_LOG`, not
thrown, so there's no way for a caller to notice except everything downstream
failing).
