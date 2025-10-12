#!/bin/bash

# CLVM ZK Prover Dependency Installer
# This script installs all required dependencies for CLVM ZK proof generation

set -e  # Exit on any error

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

# Install Rust if not present
install_rust() {
    if command_exists rustc; then
        local rust_version=$(rustc --version | cut -d' ' -f2)
        local major_version=$(echo "$rust_version" | cut -d'.' -f1)
        local minor_version=$(echo "$rust_version" | cut -d'.' -f2)
        
        # Check if Rust version is >= 1.70 (reasonable minimum for modern projects)
        if [ "$major_version" -gt 1 ] || ([ "$major_version" -eq 1 ] && [ "$minor_version" -ge 70 ]); then
            log_success "Rust is already installed with adequate version: $(rustc --version)"
            return 0
        else
            log_warning "Rust version $rust_version is outdated, updating..."
            rustup update stable
            log_success "Rust updated to: $(rustc --version)"
            return 0
        fi
    fi
    
    log_info "Installing Rust..."
    
    if [ "$PLATFORM" = "windows" ]; then
        log_info "Please download and install Rust from: https://rustup.rs/"
        log_warning "After installing Rust, please restart your terminal and run this script again."
        exit 1
    else
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
        log_success "Rust installed successfully"
    fi
}

# Install RISC-V target (force stable)
install_riscv_target() {
    log_info "Installing RISC-V target for Rust (stable toolchain)..."
    
    if rustup target list --installed --toolchain stable | grep -q "riscv32im-unknown-none-elf"; then
        log_success "RISC-V target already installed (stable)"
    else
        rustup target add riscv32im-unknown-none-elf --toolchain stable
        log_success "RISC-V target installed successfully (stable)"
    fi
}

# Install risc0 toolchain
install_risc0() {
    log_info "Checking RISC Zero toolchain..."
    
    # Check if risc0 is already properly installed
    if command_exists rzup && command_exists cargo; then
        # Try to check if risc0 tools are working
        if cargo --version >/dev/null 2>&1 && [ -d "$HOME/.risc0" ]; then
            # Check if risc0 crates can be found
            if cargo search risc0-zkvm --limit 1 >/dev/null 2>&1 || [ -f "$HOME/.risc0/bin/rzup" ]; then
                local rzup_version=$(rzup --version 2>/dev/null || echo "unknown")
                log_success "RISC Zero toolchain already installed: $rzup_version"
                return 0
            fi
        fi
        
        log_info "rzup found but incomplete installation, updating..."
        rzup install
        log_success "RISC Zero toolchain updated successfully"
        return 0
    fi
    
    log_info "Installing RISC Zero toolchain..."
    curl -L https://risczero.com/install | bash
    export PATH="$HOME/.risc0/bin:$PATH"
    
    if command_exists rzup; then
        rzup install
        log_success "RISC Zero toolchain installed successfully"
    else
        log_error "Failed to install rzup. Please check your internet connection and try again."
        log_info "You can manually install from: https://dev.risczero.com/api/zkvm/install"
        exit 1
    fi
}

# Install SP1 toolchain (with stable reset)
install_sp1() {
    log_info "Checking SP1 toolchain..."
    
    # Check if SP1 is already properly installed
    if command_exists sp1up && command_exists cargo; then
        if cargo prove --version >/dev/null 2>&1; then
            local sp1_version=$(sp1up --version 2>/dev/null || echo "unknown")
            log_success "SP1 toolchain already installed and verified: $sp1_version"
            return 0
        fi
        log_info "sp1up found but incomplete installation, updating..."
        sp1up
    else
        log_info "Installing SP1 toolchain..."
        curl -L https://sp1.succinct.xyz | bash
        
        if [ -f "$HOME/.bashrc" ]; then
            source "$HOME/.bashrc"
        elif [ -f "$HOME/.zshrc" ]; then
            source "$HOME/.zshrc"
        fi
        
        export PATH="$HOME/.sp1/bin:$PATH"
        
        if command_exists sp1up; then
            sp1up
        else
            log_error "Failed to install sp1up..."
            exit 1
        fi
    fi
    
    # sleep 2
    
    # if command_exists rustup; then
    #     log_info "Resetting Rust toolchain to stable..."
    #     rustup toolchain install stable || true
    #     rustup override unset || true
    #     rustup default stable || {
    #         log_warning "Could not set stable as default toolchain, but SP1 should still work"
    #     }
    #     local current_toolchain=$(rustup show active-toolchain 2>/dev/null | cut -d' ' -f1 || echo "unknown")
    #     log_info "Active Rust toolchain: $current_toolchain"
    # fi
    
    # if command_exists cargo && cargo prove --version >/dev/null 2>&1; then
    #     log_success "SP1 toolchain installed and verified successfully"
    # elif [ -f "$HOME/.sp1/bin/cargo-prove" ]; then
    #     log_success "SP1 toolchain installed successfully (cargo-prove available in ~/.sp1/bin/)"
    # else
    #     log_warning "SP1 installed but cargo-prove not found in PATH. You may need to restart your shell."
    # fi
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
    
    if command_exists rustc && command_exists cargo; then
        log_success "✓ Rust: $(rustc --version)"
    else
        log_error "✗ Rust installation failed"
        return 1
    fi
    
    if rustup target list --installed --toolchain stable | grep -q "riscv32im-unknown-none-elf"; then
        log_success "✓ RISC-V target (stable): riscv32im-unknown-none-elf"
    else
        log_error "✗ RISC-V target not installed"
        return 1
    fi
    
    if command_exists rzup; then
        log_success "✓ RISC Zero toolchain: $(rzup --version 2>/dev/null || echo 'installed')"
    else
        log_error "✗ RISC Zero toolchain not found"
        return 1
    fi
    
    if command_exists sp1up; then
        log_success "✓ SP1 toolchain: $(sp1up --version 2>/dev/null || echo 'installed')"
    else
        log_warning "SP1 toolchain not found (optional)"
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
