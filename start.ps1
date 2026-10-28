$ErrorActionPreference = "Stop"

$RootDir = $PSScriptRoot
$ServerDir = Join-Path $RootDir "server"
$UiDir = Join-Path $RootDir "ui"
$NodeMin = 24
$CargoWatchVersion = "8.5.3"

function Fail([string]$Message) {
    throw "Error: $Message"
}

function Need([string]$Name, [string]$Hint) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Fail $Hint
    }
}

Write-Host "`n== Check tools =="
Need "node" "Install Node.js $NodeMin or newer, then reopen PowerShell."
Need "npm" "Install Node.js $NodeMin or newer (npm is included)."
Need "rustup" "Install Rustup from https://rustup.rs, then reopen PowerShell."
Need "cargo" "Cargo is missing. Install Rustup from https://rustup.rs."
Need "rustc" "rustc is missing. Install Rustup from https://rustup.rs."

$NodeVersion = (& node -p "process.versions.node" | Out-String).Trim()
if ($LASTEXITCODE -ne 0) {
    Fail "Could not determine the installed Node.js version."
}
if ([int]($NodeVersion.Split(".")[0]) -lt $NodeMin) {
    Fail "Node.js $NodeVersion found; version $NodeMin or newer is required."
}

$ToolchainFile = Join-Path $ServerDir "rust-toolchain.toml"
$ToolchainText = Get-Content -Raw $ToolchainFile
if ($ToolchainText -notmatch '(?m)^\s*channel\s*=\s*"([^"]+)"') {
    Fail "Cannot read the pinned Rust version from server/rust-toolchain.toml."
}
$RustPin = $Matches[1]

Push-Location $ServerDir
try {
    $RustInfo = (& rustc --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $RustInfo -notmatch '^rustc ([^\s]+)') {
        Fail "Cannot run the pinned Rust toolchain ($RustPin). Rustup will install it from rust-toolchain.toml when available."
    }
    $RustVersion = $Matches[1]
    if ($RustVersion -ne $RustPin) {
        Fail "Rust $RustVersion active; this project requires $RustPin."
    }

    $CargoInfo = (& cargo --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $CargoInfo -notmatch '^cargo ([^\s]+)') {
        Fail "Cannot run Cargo with the pinned Rust toolchain ($RustPin)."
    }
    $CargoVersion = $Matches[1]
    if ($CargoVersion -ne $RustPin) {
        Fail "Cargo $CargoVersion active; this project requires $RustPin."
    }
}
finally {
    Pop-Location
}

Write-Host "Node.js $NodeVersion - Rust $RustVersion - Cargo $CargoVersion"

Write-Host "`n== Install dependencies =="
& npm ci --prefix $UiDir
if ($LASTEXITCODE -ne 0) {
    throw "npm ci failed with exit code $LASTEXITCODE."
}

Push-Location $ServerDir
try {
    & cargo fetch --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo fetch failed with exit code $LASTEXITCODE."
    }

    $null = & cargo watch --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        & cargo install cargo-watch --version $CargoWatchVersion --locked
        if ($LASTEXITCODE -ne 0) {
            throw "cargo-watch installation failed with exit code $LASTEXITCODE."
        }
    }
}
finally {
    Pop-Location
}

Write-Host "`n== Start UI and API =="
& npm --prefix $UiDir run dev:stack
