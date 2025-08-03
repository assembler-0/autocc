#!/usr/bin/env zsh

# Uninstall autocc zsh completion
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

log_info() {
    echo "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo "${RED}[ERROR]${NC} $1" >&2
}

COMPLETION_DIR="$HOME/.zsh/completion"
COMPLETION_FILE="$COMPLETION_DIR/_autocc"
# shellcheck disable=SC2034
ZSHRC="$HOME/.zshrc"

log_info "Removing autocc completion..."

# Remove completion file
if [[ -f "$COMPLETION_FILE" ]]; then
    rm "$COMPLETION_FILE"
    log_info "Removed $COMPLETION_FILE"
else
    log_info "Completion file not found (already removed)"
fi

# Optionally remove empty completion directory
if [[ -d "$COMPLETION_DIR" ]] && [[ -z "$(ls -A "$COMPLETION_DIR")" ]]; then
    rmdir "$COMPLETION_DIR"
    log_info "Removed empty completion directory"
fi

log_info "Please manually remove any autocc-related lines from ~/.zshrc if desired"
log_info "Then run: source ~/.zshrc"