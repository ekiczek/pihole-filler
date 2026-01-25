#!/bin/bash
#
# Deploy and run the Pi-hole Elapsed Time Trigger
#
# Usage:
#   ./deploy.sh           Deploy and run the script
#   ./deploy.sh --unblock Deploy and run with --unblock flag
#

set -e

# Load configuration from .env file
SCRIPT_DIR="$(dirname "$0")"
ENV_FILE="${SCRIPT_DIR}/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Error: .env file not found at $ENV_FILE"
    echo "Copy .env.example to .env and configure your Pi-hole settings."
    exit 1
fi

# Source the .env file
source "$ENV_FILE"

# Validate required variables
if [[ -z "$PIHOLE_HOST" ]]; then
    echo "Error: PIHOLE_HOST not set in .env"
    exit 1
fi

# Configuration
PIHOLE_USER="${PIHOLE_USER:-pi}"
SSH_KEY="${PIHOLE_SSH_KEY:-$HOME/.ssh/id_rsa}"
REMOTE_HOST="${PIHOLE_USER}@${PIHOLE_HOST}"
SSH_OPTS="-i $SSH_KEY"
SCRIPT_NAME="pihole_elapsed_time_trigger.py"
REMOTE_PATH="~/${SCRIPT_NAME}"
LOCAL_SCRIPT="${SCRIPT_DIR}/${SCRIPT_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if local script exists
if [[ ! -f "$LOCAL_SCRIPT" ]]; then
    log_error "Script not found: $LOCAL_SCRIPT"
    exit 1
fi

# Build properly quoted arguments for remote shell
SCRIPT_ARGS=""
for arg in "$@"; do
    # Escape single quotes and wrap in single quotes for remote shell
    escaped_arg=$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")
    SCRIPT_ARGS="$SCRIPT_ARGS '$escaped_arg'"
done

if [[ -n "$SCRIPT_ARGS" ]]; then
    log_info "Will run with args:$SCRIPT_ARGS"
fi

# Step 1: Copy script to remote host
log_info "Copying ${SCRIPT_NAME} to ${REMOTE_HOST}..."
if scp $SSH_OPTS "$LOCAL_SCRIPT" "${REMOTE_HOST}:${REMOTE_PATH}"; then
    log_info "Copy successful"
else
    log_error "Failed to copy script to remote host"
    exit 1
fi

# Step 2: SSH in and run the script with sudo
log_info "Connecting to ${REMOTE_HOST} and running script..."
log_info "Logs will be saved to ~/limiter.log on the remote host"
echo "--------------------------------------------------------------"

# Use ssh with pseudo-terminal allocation for interactive output
# The script requires sudo, so we run it with sudo
# Use tee to log to both terminal and file for later troubleshooting
# -u flag forces unbuffered output so logs appear immediately
ssh $SSH_OPTS -t "$REMOTE_HOST" "sudo python3 -u ${REMOTE_PATH} ${SCRIPT_ARGS} 2>&1 | tee ~/limiter.log"

EXIT_CODE=$?

echo "--------------------------------------------------------------"
if [[ $EXIT_CODE -eq 0 ]]; then
    log_info "Script exited normally"
elif [[ $EXIT_CODE -eq 130 ]]; then
    log_warn "Script interrupted (Ctrl+C)"
else
    log_error "Script exited with code: $EXIT_CODE"
fi

echo ""
log_info "To share logs with Claude for troubleshooting, run:"
echo "  scp ${REMOTE_HOST}:~/limiter.log /tmp/ && cat /tmp/limiter.log"

exit $EXIT_CODE
