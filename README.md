**Install Instructions**

1. **Install Rust**  
   Follow the on-screen instructions—the installer will set up Rust, Cargo (Rust’s build tool), and rustup.
   ```sh
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. **Restart Your Terminal or Load the Environment**  
   Either restart your terminal or run:
   ```sh
   source $HOME/.cargo/env
   ```

3. **Verify the Installation**  
   Check the versions of Rust and Cargo:
   ```sh
   rustc --version
   cargo --version
   ```

4. **Download the Network Tools Repository**  
   Clone the repository from GitHub:
   ```sh
   git clone git@github.com:tburgess7/network_tools2.git
   ```

5. **Compile the Project**  
   Navigate to the project directory and build in release mode:
   ```sh
   cd network_tools2
   cargo build --release
   ```
6. **Install and configure NGINX, add the following to your /etc/nginx/conf.d/default.conf**
   ```sh
       # Reverse proxy for second API requests (secondary network tools on port 18085)
    location /ntools2_api/ {
        proxy_pass http://127.0.0.1:18085/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
   ```
