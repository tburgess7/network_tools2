Install instructions


1. Follow the on-screen instructions, The installer will set up Rust, Cargo (Rust’s build tool), and rustup.

  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


2. Restart your terminal or load the new environment with

  source $HOME/.cargo/env


3. Verify the installation by checking the versions:

  rustc --version
  cargo --version


4. Download the network tools github and extract:

  git clone git@github.com:tburgess7/network_tools2.git


5. Compile the project:

  cargo build --release

