set -euo pipefail

source "$HOME/.cargo/env"

LIBGCC_DIR="$(dirname "$(gcc -print-file-name=libgcc_s.so.1)")"
export LD_LIBRARY_PATH="${LIBGCC_DIR}:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="${LIBGCC_DIR}:${LIBRARY_PATH:-}"

sh ./scripts/build.sh
cargo test -- --nocapture
