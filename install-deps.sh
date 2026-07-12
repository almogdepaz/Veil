#!/bin/bash

# CLVM ZK Prover Dependency Installer
# This script installs all required dependencies for CLVM ZK proof generation

set -e  # Exit on any error

RUST_VERSION="1.89.0"
RISC0_VERSION="3.0.4"
RISC0_RUST_VERSION="1.88.0"
SP1_VERSION="v5.2.4"
SP1_COMMIT="2a51f3d"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_system() {
    log_info "Checking system requirements..."
    
    case "$(uname -s)" in
        Linux*)     PLATFORM=linux;;
        Darwin*)    PLATFORM=macos;;
        CYGWIN*|MINGW*|MSYS*) PLATFORM=windows;;
        *)          PLATFORM=unknown;;
    esac
    
    log_info "Detected platform: $PLATFORM"
    
    if [ "$PLATFORM" = "unknown" ]; then
        log_error "Unsupported platform. This installer supports Linux, macOS, and Windows."
        exit 1
    fi
    
    ARCH=$(uname -m)
    log_info "Detected architecture: $ARCH"
}

# Install the repository-pinned Rust toolchain without changing the global default.
install_rust() {
    if ! command_exists rustup; then
        if [ "$PLATFORM" = "windows" ]; then
            log_error "Install rustup from https://rustup.rs/ and rerun this script."
            exit 1
        fi

        log_info "Installing rustup..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck source=/dev/null
        source "$HOME/.cargo/env"
    fi

    log_info "Installing Rust $RUST_VERSION with rustfmt and clippy..."
    rustup toolchain install "$RUST_VERSION" --profile minimal --component rustfmt --component clippy
    log_success "Rust toolchain ready: $(rustc +"$RUST_VERSION" --version)"
}

# Install the host-side RISC-V target on the pinned repository toolchain.
install_riscv_target() {
    log_info "Installing RISC-V target for Rust $RUST_VERSION..."

    if rustup target list --installed --toolchain "$RUST_VERSION" | grep -q "riscv32im-unknown-none-elf"; then
        log_success "RISC-V target already installed ($RUST_VERSION)"
    else
        rustup target add riscv32im-unknown-none-elf --toolchain "$RUST_VERSION"
        log_success "RISC-V target installed successfully ($RUST_VERSION)"
    fi
}

# Install the exact RISC Zero host, VM, and guest Rust components.
install_risc0() {
    log_info "Installing RISC Zero $RISC0_VERSION..."

    if ! command_exists rzup; then
        curl --proto '=https' --tlsv1.2 -sSfL https://risczero.com/install | bash
        export PATH="$HOME/.risc0/bin:$PATH"
    fi

    if ! command_exists rzup; then
        log_error "Failed to install rzup."
        exit 1
    fi

    # rzup uses this token only for GitHub API rate limits in this process.
    if [ -z "${GITHUB_TOKEN:-}" ] && command_exists gh; then
        GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
        export GITHUB_TOKEN
    fi

    if ! rzup default cargo-risczero "$RISC0_VERSION"; then
        rzup install cargo-risczero "$RISC0_VERSION"
    fi
    if ! rzup default r0vm "$RISC0_VERSION"; then
        rzup install r0vm "$RISC0_VERSION"
    fi
    if ! rzup default rust "$RISC0_RUST_VERSION"; then
        rzup install rust "$RISC0_RUST_VERSION"
    fi

    rzup default cargo-risczero "$RISC0_VERSION"
    rzup default r0vm "$RISC0_VERSION"
    rzup default rust "$RISC0_RUST_VERSION"

    log_success "RISC Zero ready: $(cargo risczero --version)"
}

# Install the exact SP1 release used by the workspace crates.
install_sp1() {
    log_info "Installing SP1 $SP1_VERSION..."

    if ! command_exists sp1up; then
        curl --proto '=https' --tlsv1.2 -sSfL https://sp1.succinct.xyz | bash
        export PATH="$HOME/.sp1/bin:$PATH"
    fi

    if ! command_exists sp1up; then
        log_error "Failed to install sp1up."
        exit 1
    fi

    local installed
    installed=$(cargo prove --version 2>/dev/null || true)
    if [[ "$installed" != *"$SP1_COMMIT"* ]]; then
        sp1up --version "$SP1_VERSION"
        installed=$(cargo prove --version)
    fi
    if [[ "$installed" != *"$SP1_COMMIT"* ]]; then
        log_error "Expected SP1 $SP1_VERSION ($SP1_COMMIT), found: $installed"
        exit 1
    fi

    log_success "SP1 ready: $installed"
}

# Check if package is installed (Linux)
package_installed() {
    local pkg="$1"
    case "$PLATFORM" in
        linux)
            if command_exists dpkg; then
                dpkg -l | grep -q "^ii  $pkg " 2>/dev/null
            elif command_exists rpm; then
                rpm -q "$pkg" >/dev/null 2>&1
            elif command_exists pacman; then
                pacman -Q "$pkg" >/dev/null 2>&1
            else
                return 1
            fi
            ;;
        *)
            return 1
            ;;
    esac
}

# Install system dependencies
install_system_deps() {
    log_info "Checking system dependencies..."
    
    case "$PLATFORM" in
        linux)
            if command_exists apt-get; then
                # Check if essential packages are already installed
                local missing_pkgs=()
                for pkg in build-essential curl git pkg-config libssl-dev; do
                    if ! package_installed "$pkg"; then
                        missing_pkgs+=("$pkg")
                    fi
                done
                
                if [ ${#missing_pkgs[@]} -eq 0 ]; then
                    log_success "All Ubuntu/Debian dependencies already installed"
                else
                    log_info "Installing missing dependencies for Ubuntu/Debian: ${missing_pkgs[*]}"
                    sudo apt-get update
                    sudo apt-get install -y "${missing_pkgs[@]}"
                fi
            elif command_exists yum; then
                # Check essential tools for RHEL/CentOS
                local need_install=false
                if ! command_exists gcc || ! command_exists make; then
                    need_install=true
                fi
                for cmd in curl git pkg-config; do
                    if ! command_exists "$cmd"; then
                        need_install=true
                        break
                    fi
                done
                
                if [ "$need_install" = true ]; then
                    log_info "Installing dependencies for CentOS/RHEL/Fedora..."
                    sudo yum groupinstall -y "Development Tools"
                    sudo yum install -y curl git pkg-config openssl-devel
                else
                    log_success "All CentOS/RHEL/Fedora dependencies already installed"
                fi
            elif command_exists pacman; then
                # Check essential packages for Arch
                local missing_pkgs=()
                for pkg in base-devel curl git pkg-config openssl; do
                    if ! package_installed "$pkg"; then
                        missing_pkgs+=("$pkg")
                    fi
                done
                
                if [ ${#missing_pkgs[@]} -eq 0 ]; then
                    log_success "All Arch Linux dependencies already installed"
                else
                    log_info "Installing missing dependencies for Arch Linux: ${missing_pkgs[*]}"
                    sudo pacman -S --noconfirm "${missing_pkgs[@]}"
                fi
            else
                log_warning "Unknown Linux distribution. Please ensure you have build tools, curl, git, and OpenSSL dev libraries installed."
            fi
            ;;
        macos)
            if command_exists brew; then
                local missing_pkgs=()
                for pkg in git curl; do
                    if ! command_exists "$pkg"; then
                        missing_pkgs+=("$pkg")
                    fi
                done
                
                if [ ${#missing_pkgs[@]} -eq 0 ]; then
                    log_success "All macOS dependencies already available"
                else
                    log_info "Installing missing dependencies with Homebrew: ${missing_pkgs[*]}"
                    brew install "${missing_pkgs[@]}"
                fi
            else
                if command_exists git && command_exists curl; then
                    log_success "Essential macOS tools already available"
                else
                    log_info "Please install Xcode Command Line Tools:"
                    log_info "  xcode-select --install"
                    log_warning "Consider installing Homebrew for easier dependency management: https://brew.sh"
                fi
            fi
            ;;
        windows)
            if command_exists git && command_exists curl; then
                log_success "Essential Windows tools already available"
            else
                log_info "On Windows, please ensure you have:"
                log_info "  - Git for Windows: https://git-scm.com/download/win"
                log_info "  - Visual Studio Build Tools or Visual Studio with C++ workload"
                log_info "  - Windows Subsystem for Linux (WSL) is recommended for better compatibility"
            fi
            ;;
    esac
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    if command_exists rustc && command_exists cargo && [[ "$(rustc --version)" == "rustc $RUST_VERSION "* ]]; then
        log_success "✓ Rust: $(rustc --version)"
    else
        log_error "✗ Expected Rust $RUST_VERSION, found: $(rustc --version 2>/dev/null || echo missing)"
        return 1
    fi

    if rustup target list --installed --toolchain "$RUST_VERSION" | grep -q "riscv32im-unknown-none-elf"; then
        log_success "✓ RISC-V target ($RUST_VERSION): riscv32im-unknown-none-elf"
    else
        log_error "✗ RISC-V target not installed for Rust $RUST_VERSION"
        return 1
    fi

    if command_exists rzup && [[ "$(cargo risczero --version)" == "cargo-risczero $RISC0_VERSION" ]]; then
        log_success "✓ RISC Zero toolchain: $(cargo risczero --version)"
    else
        log_error "✗ Expected cargo-risczero $RISC0_VERSION"
        return 1
    fi

    if command_exists sp1up && [[ "$(cargo prove --version)" == *"$SP1_COMMIT"* ]]; then
        log_success "✓ SP1 toolchain: $(cargo prove --version)"
    else
        log_error "✗ Expected SP1 $SP1_VERSION ($SP1_COMMIT)"
        return 1
    fi
    
    log_info "Testing CLVM ZK compilation..."
    if cargo build --release > /dev/null 2>&1; then
        log_success "✓ CLVM ZK project compiles successfully"
    else
        log_warning "CLVM ZK project compilation failed - this may be due to missing runtime dependencies"
        log_info "Try running: cargo build --release"
    fi
}

# Install Docker
install_docker() {
    log_info "Checking Docker installation..."
    
    if command_exists docker && docker info >/dev/null 2>&1; then
        log_success "Docker is already installed and running: $(docker --version)"
        return 0
    elif command_exists docker; then
        log_warning "Docker is installed but not running. Please start Docker Desktop or the Docker daemon."
        return 0
    fi
    
    log_info "Installing Docker..."
    
    case "$PLATFORM" in
        macos)
            if command_exists brew; then
                brew install docker
                log_success "Docker installed via Homebrew"
                log_info "Please start Docker Desktop from Applications or run 'open -a Docker'"
            else
                log_info "Please download Docker Desktop from: https://docs.docker.com/desktop/install/mac-install/"
                log_info "Or install Homebrew first: https://brew.sh"
            fi
            ;;
        linux)
            if command_exists apt-get; then
                log_info "Installing Docker via apt..."
                sudo apt-get update
                sudo apt-get install -y docker.io docker-compose
                sudo systemctl enable docker
                sudo systemctl start docker
                sudo usermod -aG docker "$USER"
                log_success "Docker installed. Please log out and back in for group permissions to take effect."
            elif command_exists yum; then
                log_info "Installing Docker via yum..."
                sudo yum install -y docker docker-compose
                sudo systemctl enable docker
                sudo systemctl start docker  
                sudo usermod -aG docker "$USER"
                log_success "Docker installed. Please log out and back in for group permissions to take effect."
            elif command_exists pacman; then
                log_info "Installing Docker via pacman..."
                sudo pacman -S --noconfirm docker docker-compose
                sudo systemctl enable docker
                sudo systemctl start docker
                sudo usermod -aG docker "$USER"
                log_success "Docker installed. Please log out and back in for group permissions to take effect."
            else
                log_warning "Unknown Linux distribution. Please install Docker manually:"
                log_info "https://docs.docker.com/engine/install/"
            fi
            ;;
        windows)
            log_info "Please download Docker Desktop from: https://docs.docker.com/desktop/install/windows-install/"
            log_info "Or use Windows Subsystem for Linux (WSL) with Docker"
            ;;
    esac
}

# Update shell profile
update_shell_profile() {
    log_info "Checking shell profile configuration..."
    
    SHELL_NAME=$(basename "$SHELL")
    
    case "$SHELL_NAME" in
        bash) PROFILE_FILE="$HOME/.bashrc";;
        zsh) PROFILE_FILE="$HOME/.zshrc";;
        fish) PROFILE_FILE="$HOME/.config/fish/config.fish";;
        *) PROFILE_FILE="$HOME/.profile";;
    esac
    
    local changes_made=false
    
    if [ -f "$PROFILE_FILE" ]; then
        if ! grep -q "\.cargo/bin" "$PROFILE_FILE"; then
            echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> "$PROFILE_FILE"
            log_info "Added Cargo to PATH in $PROFILE_FILE"
            changes_made=true
        fi
        if ! grep -q "\.risc0/bin" "$PROFILE_FILE"; then
            echo 'export PATH="$HOME/.risc0/bin:$PATH"' >> "$PROFILE_FILE"
            log_info "Added RISC Zero to PATH in $PROFILE_FILE"
            changes_made=true
        fi
        if ! grep -q "\.sp1/bin" "$PROFILE_FILE"; then
            echo 'export PATH="$HOME/.sp1/bin:$PATH"' >> "$PROFILE_FILE"
            log_info "Added SP1 to PATH in $PROFILE_FILE"
            changes_made=true
        fi
        
        if [ "$changes_made" = false ]; then
            log_success "All PATH entries already present in $PROFILE_FILE"
        fi
    else
        log_warning "Profile file $PROFILE_FILE not found, creating it..."
        echo 'export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$HOME/.sp1/bin:$PATH"' > "$PROFILE_FILE"
        log_info "Created $PROFILE_FILE with tool paths"
    fi
    
    export PATH="$HOME/.cargo/bin:$HOME/.risc0/bin:$HOME/.sp1/bin:$PATH"
}

# Main
main() {
    local install_docker_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--docker)
                install_docker_flag=true
                shift
                ;;
            -h|--help)
                echo "CLVM ZK Prover Dependency Installer"
                echo "======================================"
                echo ""
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  -d, --docker    Also install Docker (required for SP1 plonk/groth16 modes)"
                echo "  -h, --help      Show this help message"
                echo ""
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                echo "Use -h or --help for usage information"
                exit 1
                ;;
        esac
    done
    
    echo "CLVM ZK Prover Dependency Installer"
    echo "======================================"
    echo ""
    
    check_system
    echo ""
    
    install_system_deps
    echo ""
    
    install_rust
    echo ""
    
    update_shell_profile
    echo ""
    
    install_riscv_target
    echo ""
    
    install_risc0
    echo ""
    
    install_sp1
    echo ""
    
    if [ "$install_docker_flag" = true ]; then
        install_docker
        echo ""
    fi
    
    verify_installation
    echo ""
    
    log_success "Installation completed successfully!"
    echo ""
    log_info "Next steps:"
    log_info "1. Restart your terminal or run: source ~/.bashrc (or ~/.zshrc)"
    log_info "2. Compile the CLVM ZK project: cargo build --release"
    log_info "3. Run tests: cargo test"
    log_info "4. Generate ZK proofs: cargo run --bin clvm-zk prove --program-type add --arg1 5 --arg2 3"
    if [ "$install_docker_flag" = true ]; then
        log_info "5. Test SP1 plonk/groth16 modes: SP1_PROOF_MODE=plonk cargo run --example backend_benchmark --features sp1 --no-default-features --release"
    else
        log_info "5. To enable SP1 plonk/groth16 modes, install Docker: ./install-deps.sh -d"
    fi
    echo ""
    log_info "For troubleshooting, see: https://dev.risczero.com/api/zkvm/install"
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi
