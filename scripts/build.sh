set -euo pipefail

source "$HOME/.cargo/env"

LIBGCC_DIR="$(dirname "$(gcc -print-file-name=libgcc_s.so.1)")"
export LD_LIBRARY_PATH="${LIBGCC_DIR}:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="${LIBGCC_DIR}:${LIBRARY_PATH:-}"

mkdir -p target/bindgen
mkdir -p dist

cargo build --target wasm32-unknown-unknown --release

wasm-bindgen \
    --target web \
    --no-typescript \
    --out-dir target/bindgen \
    target/wasm32-unknown-unknown/release/paradise_matrix_push_crypto.wasm

WASM_FEATURES=(
    --enable-bulk-memory
    --enable-bulk-memory-opt
    --enable-nontrapping-float-to-int
    --enable-sign-ext
    --enable-mutable-globals
)

wasm-opt -Oz "${WASM_FEATURES[@]}" \
         target/bindgen/paradise_matrix_push_crypto_bg.wasm \
         -o target/bindgen/paradise_matrix_push_crypto_opt.wasm

wasm2js -Oz "${WASM_FEATURES[@]}" \
        target/bindgen/paradise_matrix_push_crypto_opt.wasm \
        -o target/bindgen/paradise_matrix_push_crypto_asm.js

{
  sed 's/__ nativeGetRandomBytes/__nativeGetRandomBytes/g' src/js/jsc_shim.js

  cat << 'EOF'
(function (global) {
  "use strict";
EOF

  sed -E \
    -e 's/import\.meta\.url/""/g' \
    -e 's/^export (function|class|const|let|var) /\1 /' \
    -e 's/^export \{[^}]*\};?//' \
    -e 's/^export default .*//' \
    -e 's/cachedUint8ArrayMemory0\.byteLength === 0/cachedUint8ArrayMemory0.buffer !== wasm.memory.buffer/g' \
    -e 's/cachedDataViewMemory0\.buffer\.detached === true/cachedDataViewMemory0.buffer !== wasm.memory.buffer/g' \
    target/bindgen/paradise_matrix_push_crypto.js

  cat << 'EOF'
  function __instantiate_asm(__wbg_imports) {
EOF

  sed -E \
    -e 's#^import \* as ([A-Za-z0-9_$]+) from [\x27"]([^\x27"]+)[\x27"];?#const \1 = __wbg_imports["\2"] || Object.values(__wbg_imports)[0];#' \
    -e 's/^export var .*//' \
    target/bindgen/paradise_matrix_push_crypto_asm.js

  cat << 'EOF'
    return retasmFunc;
  }

  const __imports = __wbg_get_imports();
  const __exports = __instantiate_asm(__imports);
  __wbg_finalize_init({ exports: __exports });
  global.ParadisePushCrypto = {
    create_shadow_account,
    sign_shadow_device_with_ssk,
    replenish_one_time_keys,
    decrypt_olm_with_session,
    decrypt_olm_prekey_with_account,
    create_inbound_group_session,
    import_exported_group_session,
    decrypt_megolm,
  };
})(typeof globalThis !== "undefined" ? globalThis : this);
EOF
} > dist/paradise_matrix_push_crypto_bundle.js

node -e '
  const fs = require("fs");
  const raw = fs.readFileSync("dist/paradise_matrix_push_crypto_bundle.js", "utf8");
  const cjs = [
    "require(\"./paradise_matrix_push_crypto_bundle.js\");",
    "exports.BUNDLE_SOURCE = " + JSON.stringify(raw) + ";",
    "exports.ParadisePushCrypto = globalThis.ParadisePushCrypto;"
  ].join("\n");
  fs.writeFileSync("dist/index.js", cjs);
'

ls -lh dist/paradise_matrix_push_crypto_bundle.js dist/index.js

