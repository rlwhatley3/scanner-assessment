# Secrets Scanner Playground

A local full-stack starter for building a secrets-scanning playground. The React/Vite interface and Rust/Axum API are intentionally incomplete: the scan flow, detection rules, and scan API are yours to design and implement.

## Create your assessment repository

Create a private repository from this GitHub template before you begin.

1. On this repository's GitHub page, select **Use this template**, then **Create a new repository**.
2. Choose your personal account as the owner, enter a repository name, and set visibility to **Public** so it can be shared with our team easily.
3. Select **Create repository**. GitHub creates an independent repository from the starter files without the template's commit history.
4. On the new repository page, select **Code**, copy its clone URL, then clone your new repository:

```sh
git clone <YOUR_PRIVATE_REPOSITORY_URL>
cd <YOUR_REPOSITORY_NAME>
```

Run the setup commands below from the root of your new repository. Keep your assessment work in this private repository and commit your changes there.

## Requirements

- Node.js 24 or newer - install and manage Node with [nvm](https://github.com/nvm-sh/nvm#installing-and-updating).
- Rustup - install Rust with [rustup.rs](https://rustup.rs/). The backend toolchain is pinned in `server/rust-toolchain.toml`.

### Install Node.js with nvm

On macOS and Linux, after installing nvm, run these commands from the repository root. They use the version in `.nvmrc`:

```sh
nvm install
nvm use
```

On Windows, install Node.js 24.x using the [official installer](https://nodejs.org/en/download) or [nvm-windows](https://github.com/coreybutler/nvm-windows). nvm-windows does not use `.nvmrc`.

### Install the pinned Rust toolchain

After installing rustup, run Rust commands from `server/`. Rustup reads `rust-toolchain.toml` there and selects or installs the pinned toolchain automatically:

```sh
cd server
rustc --version
cargo --version
cd ..
```

## Start

From the repository root, start the project with the script for your platform:

macOS or Linux:

```sh
./start.sh
```

Windows PowerShell:

```powershell
.\start.ps1
```

Both scripts check Node.js and Rust versions, install the pinned Rust toolchain through rustup when needed, sync locked project dependencies, install `cargo-watch` if needed, and run both hot-reloading servers in one terminal. Install Node.js and rustup first; the scripts do not install those tools.

Open the Vite URL it prints (normally `http://127.0.0.1:5173`).

### Change the development ports

The default UI port is `5173` and the API port is `3001`. Set `UI_PORT` and `API_PORT` before starting the stack to use different ports.

macOS or Linux:

```sh
UI_PORT=5180 API_PORT=3011 ./start.sh
```

Windows PowerShell:

```powershell
$env:UI_PORT = "5180"
$env:API_PORT = "3011"
.\start.ps1
```

## Dev Containers

Open this repository in VS Code and choose **Reopen in Container**. The
Dev Container installs the pinned Rust toolchain and locked npm dependencies,
then starts the hot-reloading stack. Port `5173` is forwarded automatically.

## Coder

Coder 2.24+ can discover `.devcontainer/devcontainer.json` automatically; this
repository does not need its own Terraform template. Open the repository in a
Coder workspace whose template provides Docker access and the Dev Containers
CLI, then start the detected container from the workspace dashboard. The
Dev Container forwards the UI on port `5173`.

Coder's server still uses Terraform internally to provision workspaces, but
that configuration belongs to the Coder installation/template, not this
repository.
