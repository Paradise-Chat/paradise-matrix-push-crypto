export LD_LIBRARY_PATH="$(dirname $(gcc -print-file-name=libgcc_s.so.1)):$LD_LIBRARY_PATH"
export LIBRARY_PATH="$(dirname $(gcc -print-file-name=libgcc_s.so.1)):$LIBRARY_PATH"
export RUSTUP_DIST_SERVER=https://dev-static.rust-lang.org


curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

source ~/.cargo/env


rustup default 1.93.0
rustup target add wasm32-unknown-unknown
rustup component add rust-src
rustup component add rust-analyzer

cargo install -f wasm-bindgen-cli --version 0.2.114
