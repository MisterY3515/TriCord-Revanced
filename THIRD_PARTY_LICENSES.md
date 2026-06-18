# Third-Party Licenses

TriCord is licensed under the GNU GPLv3 (see `LICENSE`). It vendors the following
third-party components, each under its own permissive license. The original
copyright/license notice is preserved at the top of each vendored file; this
document is an index, not a replacement for those notices.

## qrcodegen

- **Location:** `library/qrcodegen/`
- **Source:** https://www.nayuki.io/page/qr-code-generator-library
- **License:** MIT
- **Copyright:** Project Nayuki

## RapidJSON

- **Location:** `library/rapidjson/`
- **Source:** https://github.com/Tencent/rapidjson
- **License:** MIT
- **Copyright:** THL A29 Limited, a Tencent company, and Milo Yip

## stb_image

- **Location:** `library/stb_image/`
- **Source:** https://github.com/nothings/stb
- **License:** Dual-licensed, MIT or Public Domain (Unlicense) at the user's option
- **Copyright:** Sean Barrett and contributors

## 3DSware

- **Location:** `3DSware/` (git submodule)
- **Source:** https://github.com/MisterY3515/3DSware
- **License:** MIT
- **Copyright:** TriCord Contributors

## mlspp (DAVE/MLS voice encryption, not yet wired into the 3DS build)

- **Location:** `library/mlspp/`
- **Source:** https://github.com/cisco/mlspp
- **License:** BSD-2-Clause
- **Copyright:** Cisco Systems, Inc. and contributors
- **Note:** Only the subset needed for DAVE ciphersuite 2 (`DHKEMP256_AES128GCM_SHA256_P256`)
  is vendored; the bundled crypto backend is replaced with a new mbedTLS-based
  implementation (TriCord-authored, same license terms as the surrounding files)
  since OpenSSL/BoringSSL are not practical to port to devkitARM.

## libdave (DAVE/MLS voice encryption, not yet wired into the 3DS build)

- **Location:** `library/libdave/`
- **Source:** https://github.com/discord/libdave
- **License:** MIT
- **Copyright:** Discord Inc.
- **Note:** Only the protocol-glue layer (SFrame-like media framing, per-sender key
  ratchet, frame processors) is vendored, trimmed to the audio-only/ciphersuite-2
  subset TriCord needs (see `library/libdave/host_tests/README.md` for the full
  list of trims); its OpenSSL/BoringSSL-backed AEAD cryptor is replaced with a new
  mbedTLS-based implementation for the same reason as mlspp above. Other-language
  bindings (`bindings_capi.cpp`/`bindings_wasm.cpp`) are not vendored.
