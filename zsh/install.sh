#!/bin/zsh

# Better zsh completion installation script
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1" >&2
}

# Check if running on zsh
if [[ -z "$ZSH_VERSION" ]]; then
    log_warn "This script is designed for zsh. You're currently running: $SHELL"
    # shellcheck disable=SC2162
    read -q "?Do you want to continue anyway? (y/n): " || exit 1
    echo
fi

# Create completion directory
COMPLETION_DIR="$HOME/.zsh/completion"
log_info "Creating completion directory: $COMPLETION_DIR"
mkdir -p "$COMPLETION_DIR"

# Check if _autocc file exists in current directory
if [[ ! -f "_autocc" ]]; then
    log_error "Completion file '_autocc' not found in current directory"
    exit 1
fi

# Copy completion file
log_info "Installing completion file..."
cp "_autocc" "$COMPLETION_DIR/_autocc"

# Check if zshrc exists, create if it doesn't
ZSHRC="$HOME/.zshrc"
if [[ ! -f "$ZSHRC" ]]; then
    log_warn "Creating ~/.zshrc file"
    touch "$ZSHRC"
fi

# Check if completion setup already exists
COMPLETION_LINE="fpath+=~/.zsh/completion"
AUTOLOAD_LINE="autoload -Uz compinit"
COMPINIT_LINE="compinit"

# Function to check if line exists in file
line_exists() {
    grep -Fq "$1" "$ZSHRC" 2>/dev/null
}

log_info "Updating ~/.zshrc configuration..."

# Add completion path if not already present
if ! line_exists "$COMPLETION_LINE"; then
    echo "$COMPLETION_LINE" >> "$ZSHRC"
    log_info "Added completion path to ~/.zshrc"
else
    log_warn "Completion path already exists in ~/.zshrc"
fi

# Add autoload if not already present
if ! line_exists "$AUTOLOAD_LINE"; then
    echo "$AUTOLOAD_LINE" >> "$ZSHRC"
    log_info "Added autoload command to ~/.zshrc"
else
    log_warn "Autoload already configured in ~/.zshrc"
fi

# Add compinit if not already present
if ! line_exists "$COMPINIT_LINE"; then
    echo "$COMPINIT_LINE" >> "$ZSHRC"
    log_info "Added compinit to ~/.zshrc"
else
    log_warn "Compinit already configured in ~/.zshrc"
fi

# Source the updated zshrc
log_info "Sourcing updated ~/.zshrc..."
# shellcheck disable=SC1090
if source "$ZSHRC" 2>/dev/null; then
    log_info "Successfully sourced ~/.zshrc"
else
    log_warn "Failed to source ~/.zshrc automatically. Please run: source ~/.zshrc"
fi

log_info "Installation complete! You may need to restart your terminal or run:"
log_info "  source ~/.zshrc"
log_info "Then test with: autocc <TAB>"