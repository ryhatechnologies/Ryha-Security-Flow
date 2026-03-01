#!/bin/bash
set -e
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

print_success() { echo -e "${GREEN}✓ $1${NC}"; }
print_error() { echo -e "${RED}✗ $1${NC}"; }
print_warning() { echo -e "${YELLOW}⚠ $1${NC}"; }
print_info() { echo -e "${BLUE}ℹ $1${NC}"; }

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

update_system() {
    print_info "Updating system..."
    apt-get update -qq
}

install_nodejs() {
    print_info "Installing Node.js 20.x..."
    if command -v node &> /dev/null; then
        NODE_V=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$NODE_V" -ge 20 ]; then
            print_success "Node.js already installed"
            return 0
        fi
    fi
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs
    print_success "Node.js installed"
}

install_security_tools() {
    print_info "Installing security tools..."
    for tool in nmap nikto sqlmap gobuster sslscan whatweb metasploit-framework burpsuite hydra john hashcat dirb wpscan recon-ng dnsenum whois masscan tcpdump tshark; do
        apt-get install -y "$tool" &>/dev/null || print_warning "$tool failed"
    done
    print_success "Security tools installed"
}

install_deps() {
    cd "$PROJECT_DIR"
    print_info "Installing npm dependencies..."
    npm install
    print_success "Dependencies installed"
}

build_project() {
    cd "$PROJECT_DIR"
    print_info "Building TypeScript..."
    npm run build
    print_success "Build complete"
}

create_symlink() {
    cd "$PROJECT_DIR"
    print_info "Creating global symlink..."
    npm link
    print_success "Global command created"
}

create_dirs() {
    mkdir -p "$HOME/.ryha"/{authorizations,reports,evidence,logs,config,keys,sessions}
    chmod 700 "$HOME/.ryha" "$HOME/.ryha/keys" "$HOME/.ryha/authorizations"
    print_success "Directories created"
}

print_success "Starting Ryha Security Flow installation..."
check_root
update_system
install_nodejs
install_security_tools
install_deps
build_project
create_symlink
create_dirs
print_success "Installation complete!"
echo "Run 'ryha auth login' to get started"
