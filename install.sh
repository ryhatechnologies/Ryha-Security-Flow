#!/bin/bash

##############################################################################
# Ryha Security Flow - One-Time Global Installation Script
# Complete setup: Prerequisites → Dependencies → Build → Global Link
# For Kali Linux / Linux systems
##############################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored messages
print_step() {
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}▶ $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ ERROR: $1${NC}"
    exit 1
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

##############################################################################
# STEP 1: Check Prerequisites
##############################################################################
print_step "STEP 1: Checking Prerequisites"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_warning "Not running as root. Some operations may require sudo."
    print_info "Consider running: sudo bash install.sh"
fi

# Check Node.js
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 18+ first."
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    print_error "Node.js version $NODE_VERSION is too old. Please upgrade to Node.js 18+"
fi
print_success "Node.js $(node -v) is installed"

# Check npm
if ! command -v npm &> /dev/null; then
    print_error "npm is not installed"
fi

NPM_VERSION=$(npm -v | cut -d'.' -f1)
if [ "$NPM_VERSION" -lt 9 ]; then
    print_error "npm version $(npm -v) is too old. Please upgrade to npm 9+"
fi
print_success "npm $(npm -v) is installed"

# Check git
if ! command -v git &> /dev/null; then
    print_error "git is not installed"
fi
print_success "git $(git --version | awk '{print $3}') is installed"

##############################################################################
# STEP 2: Get Project Directory
##############################################################################
print_step "STEP 2: Determining Project Directory"

# If run from a different directory, try to find Ryha
if [ ! -f "package.json" ]; then
    print_info "package.json not found in current directory"
    print_info "Searching for Ryha Security Flow..."

    # Look for Ryha in common locations
    for dir in . .. ~/ryha-security-flow ~/Ryha-Security-Flow /opt/ryha-security-flow; do
        if [ -f "$dir/package.json" ] && grep -q "ryha-security-flow" "$dir/package.json" 2>/dev/null; then
            cd "$dir"
            print_success "Found project at: $(pwd)"
            break
        fi
    done

    if [ ! -f "package.json" ]; then
        print_error "Could not find Ryha Security Flow. Please run this script from the project directory."
    fi
fi

PROJECT_DIR=$(pwd)
print_success "Working directory: $PROJECT_DIR"

##############################################################################
# STEP 3: Clean Previous Installation
##############################################################################
print_step "STEP 3: Cleaning Previous Installation (if any)"

if [ -d "node_modules" ]; then
    print_info "Removing old node_modules..."
    rm -rf node_modules
    print_success "Cleaned node_modules"
fi

if [ -d "dist" ]; then
    print_info "Removing old dist directory..."
    rm -rf dist
    print_success "Cleaned dist"
fi

if [ -f "package-lock.json" ]; then
    print_info "Removing old package-lock.json..."
    rm -f package-lock.json
    print_success "Cleaned package-lock.json"
fi

print_success "Previous installation cleaned"

##############################################################################
# STEP 4: Install Dependencies
##############################################################################
print_step "STEP 4: Installing npm Dependencies"

print_info "Running: npm install"
npm install --verbose

if [ ! -d "node_modules" ]; then
    print_error "npm install failed - node_modules not created"
fi

print_success "npm dependencies installed"

##############################################################################
# STEP 5: Install TypeScript Globally
##############################################################################
print_step "STEP 5: Installing TypeScript"

print_info "Installing TypeScript..."
npm install --save-dev typescript @types/node

# Verify TypeScript is available
if ! npx tsc --version &> /dev/null; then
    print_error "TypeScript installation failed"
fi

print_success "TypeScript $(npx tsc --version) installed"

##############################################################################
# STEP 6: Build TypeScript
##############################################################################
print_step "STEP 6: Building TypeScript"

print_info "Running: npm run build"
npm run build

if [ ! -d "dist" ]; then
    print_error "Build failed - dist directory not created"
fi

if [ ! -f "dist/cli.js" ]; then
    print_error "Build failed - dist/cli.js not found"
fi

print_success "TypeScript build completed successfully"
print_info "Compiled files in: $PROJECT_DIR/dist"

##############################################################################
# STEP 7: Unlink Previous Global Installation (if exists)
##############################################################################
print_step "STEP 7: Preparing Global Installation"

if npm list -g ryha-security-flow &> /dev/null; then
    print_info "Previous global installation found. Removing..."
    npm unlink -g ryha-security-flow 2>/dev/null || true
fi

print_success "Global installation prepared"

##############################################################################
# STEP 8: Link CLI Globally
##############################################################################
print_step "STEP 8: Linking CLI Globally"

print_info "Running: npm link"
npm link

# Verify global link
sleep 1
if ! command -v ryha &> /dev/null; then
    print_warning "ryha command not found in PATH immediately"
    print_info "Updating PATH..."
    export PATH="$PATH:$(npm config get prefix)/bin"

    sleep 1
    if ! command -v ryha &> /dev/null; then
        print_error "Failed to link ryha command globally"
    fi
fi

print_success "ryha command linked globally"
print_info "Test with: ryha --version"

##############################################################################
# STEP 9: Verify Installation
##############################################################################
print_step "STEP 9: Verifying Installation"

print_info "Testing ryha command..."
if ! ryha --version &> /dev/null; then
    print_warning "ryha command test failed - you may need to restart your terminal"
    print_info "Or run: source ~/.bashrc"
else
    print_success "ryha command is working"
fi

print_info "Checking configuration..."
if [ ! -d "$HOME/.ryha" ]; then
    mkdir -p "$HOME/.ryha"
    print_success "Created ~/.ryha directory"
else
    print_success "~/.ryha directory exists"
fi

##############################################################################
# STEP 10: Summary
##############################################################################
print_step "INSTALLATION COMPLETE"

echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════════════════════════════════════╗"
echo "║                   Ryha Security Flow Installation Complete                     ║"
echo "╚════════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "\n${BLUE}✅ Installation Status:${NC}"
echo "   ✓ Node.js $(node -v)"
echo "   ✓ npm $(npm -v)"
echo "   ✓ TypeScript $(npx tsc --version)"
echo "   ✓ Project built at: $PROJECT_DIR"
echo "   ✓ CLI linked globally"
echo "   ✓ Configuration directory: ~/.ryha"

echo -e "\n${BLUE}📝 Next Steps:${NC}"
echo "   1. Restart your terminal or run:"
echo "      ${YELLOW}source ~/.bashrc${NC}"
echo ""
echo "   2. Verify installation:"
echo "      ${YELLOW}ryha --version${NC}"
echo ""
echo "   3. Run one-time setup (IMPORTANT - do this first!):"
echo "      ${YELLOW}ryha setup${NC}"
echo ""
echo "   4. Start the web dashboard:"
echo "      ${YELLOW}ryha server${NC}"
echo ""
echo "   5. Open in browser:"
echo "      ${YELLOW}http://localhost:3000${NC}"

echo -e "\n${BLUE}📚 Documentation:${NC}"
echo "   - README: $PROJECT_DIR/README.md"
echo "   - AI Models: $PROJECT_DIR/docs/AI-MODEL-CONFIGURATION.md"
echo "   - Full Guide: $PROJECT_DIR/docs/README.md"

echo -e "\n${BLUE}🚀 Quick Start Command:${NC}"
echo "   ${YELLOW}ryha setup${NC}              # One-time authentication + authorization"
echo "   ${YELLOW}ryha server${NC}             # Start web dashboard (http://localhost:3000)"
echo "   ${YELLOW}ryha pentest -d target.com -t full${NC}  # Run a full pentest"

echo -e "\n${BLUE}⚠️  Important:${NC}"
echo "   - GitHub Copilot account required (Free/Pro/Enterprise)"
echo "   - Run ${YELLOW}ryha setup${NC} before first use"
echo "   - If ryha command not found, restart terminal"

echo -e "\n${GREEN}✨ Installation successful! Ready for authorized security testing.${NC}\n"

##############################################################################
# STEP 11: Help with PATH if needed
##############################################################################
# Check if npm bin is in PATH
NPM_BIN=$(npm config get prefix)/bin
if [[ ":$PATH:" != *":$NPM_BIN:"* ]]; then
    echo -e "\n${YELLOW}⚠️  npm bin directory not in PATH${NC}"
    echo -e "Add this to your ${YELLOW}~/.bashrc${NC} or ${YELLOW}~/.zshrc${NC}:"
    echo -e "   ${YELLOW}export PATH=\"\$(npm config get prefix)/bin:\$PATH\"${NC}"
fi

exit 0
