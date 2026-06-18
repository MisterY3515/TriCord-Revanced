# mlspp/libdave mbedTLS backend — host validation tests

These are **not** part of TriCord's 3DS build. They validate the mbedTLS-backed
HPKE backend (`lib/hpke/src/mbedtls/`) on a normal PC, against:

- `hpke_rfc9180_vector_test.cpp` — a standalone (no mlspp class dependency)
  reimplementation of the same formulas, checked byte-for-byte against RFC 9180
  test vector #64 from mlspp's own `lib/hpke/scripts/test-vectors.json`
  (DHKEM(P-256,HKDF-SHA256), HKDF-SHA256, AES-128-GCM, mode base).
- `hpke_real_api_test.cpp` — exercises the actual vendored `hpke::` class
  hierarchy (`HPKE::setup_base_s/r`, `Signature::get<P256_SHA256>()`) end to
  end: encap/decap round trip, exporter secret agreement, AEAD tamper
  detection, ECDSA-P256 sign/verify.

Both passed when last run (2026-06-18) against mbedTLS 2.28.8 (matching the
3DS portlib version) built from source with clang on Windows x86_64.

## Building mbedTLS for the host (one-time, not committed to this repo)

```sh
curl -sL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.8.tar.gz -o mbedtls.tar.gz
tar xzf mbedtls.tar.gz
cd mbedtls-2.28.8/library
mkdir -p ../hostbuild_obj
for f in *.c; do clang -c "$f" -I../include -O1 -o "../hostbuild_obj/${f%.c}.o"; done
llvm-ar rcs ../hostbuild_obj/libmbedcrypto_host.a ../hostbuild_obj/*.o
```

## Running the tests

```sh
MBEDTLS=/path/to/mbedtls-2.28.8
MLSPP=library/mlspp
INCLUDES="-I$MLSPP/include/mlspp_namespace -I$MLSPP/lib/bytes/include -I$MLSPP/lib/tls_syntax/include -I$MLSPP/lib/hpke/include -I$MLSPP/lib/hpke/src -I$MBEDTLS/include"
SRCS="$MLSPP/lib/bytes/src/bytes.cpp $MLSPP/lib/tls_syntax/src/tls_syntax.cpp $MLSPP/lib/hpke/src/hpke.cpp $MLSPP/lib/hpke/src/common.cpp $MLSPP/lib/hpke/src/dhkem.cpp $MLSPP/lib/hpke/src/hkdf.cpp $MLSPP/lib/hpke/src/signature.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_common.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_random.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_digest.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_aead_cipher.cpp $MLSPP/lib/hpke/src/mbedtls/mbedtls_group.cpp"

clang++ -std=c++17 $INCLUDES $MLSPP/host_tests/hpke_real_api_test.cpp $SRCS \
  $MBEDTLS/hostbuild_obj/libmbedcrypto_host.a -ladvapi32 -o hpke_real_api_test.exe
./hpke_real_api_test.exe

clang++ -std=c++17 -I$MBEDTLS/include $MLSPP/host_tests/hpke_rfc9180_vector_test.cpp \
  $MBEDTLS/hostbuild_obj/libmbedcrypto_host.a -ladvapi32 -o hpke_rfc9180_vector_test.exe
./hpke_rfc9180_vector_test.exe
```

(`-ladvapi32` is only needed on Windows, for mbedTLS's entropy source.)

## Scope note

Only DAVE ciphersuite 2 (`DHKEMP256_AES128GCM_SHA256_P256`) is implemented.
Every other KEM/KDF/AEAD/Signature/Group algorithm mlspp defines is
intentionally left undefined in this backend (not just excluded by a config
flag) so that any accidental use of an unsupported ciphersuite is a **link
error**, not a silent runtime fallback. See the per-file comments in
`lib/hpke/src/mbedtls/` for what was trimmed and why.
