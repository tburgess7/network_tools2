Install instructions

Follow the on-screen instructions, The installer will set up Rust, Cargo (Rust’s build tool), and rustup.

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

Restart your terminal or load the new environment with:
source $HOME/.cargo/env

Verify the installation by checking the versions:
rustc --version
cargo --version

Download the network tools github and extract
git clone git@github.com:tburgess7/network_tools2.git

Compile the project
cargo build --release
