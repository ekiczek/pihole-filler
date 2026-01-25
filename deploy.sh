#!/bin/bash
#
# Deploy and manage the Pi-hole Elapsed Time Trigger daemon
#
# Usage:
#   ./deploy.sh                Deploy script and restart daemon
#   ./deploy.sh --status       Check daemon status
#   ./deploy.sh --logs         View daemon logs (live)
#   ./deploy.sh --stop         Stop the daemon
#   ./deploy.sh --start        Start the daemon
#   ./deploy.sh --list         List configured triggers
#   ./deploy.sh --add ...      Add a new trigger
#   ./deploy.sh --remove ID    Remove a trigger
#   ./deploy.sh --unblock      Remove all active blocks
#

set -e

# Load configuration from .env file
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
SERVICE_NAME="pihole-trigger"
SERVICE_FILE="${SERVICE_NAME}.service"
REMOTE_SCRIPT_PATH="/home/pi/${SCRIPT_NAME}"
REMOTE_SERVICE_PATH="/etc/systemd/system/${SERVICE_FILE}"
LOCAL_SCRIPT="${SCRIPT_DIR}/${SCRIPT_NAME}"
LOCAL_SERVICE="${SCRIPT_DIR}/${SERVICE_FILE}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

log_cmd() {
    echo -e "${BLUE}[CMD]${NC} $1"
}

# Run a command on the remote host
remote_cmd() {
    ssh $SSH_OPTS "$REMOTE_HOST" "$@"
}

# Run a command on the remote host with sudo
remote_sudo() {
    ssh $SSH_OPTS "$REMOTE_HOST" "sudo $*"
}

# Check if local files exist
check_local_files() {
    if [[ ! -f "$LOCAL_SCRIPT" ]]; then
        log_error "Script not found: $LOCAL_SCRIPT"
        exit 1
    fi
    if [[ ! -f "$LOCAL_SERVICE" ]]; then
        log_error "Service file not found: $LOCAL_SERVICE"
        exit 1
    fi
}

# Deploy the script and service file to the remote host
deploy_files() {
    check_local_files

    log_info "Deploying files to ${REMOTE_HOST}..."

    # Copy the Python script
    log_info "Copying ${SCRIPT_NAME}..."
    scp $SSH_OPTS "$LOCAL_SCRIPT" "${REMOTE_HOST}:${REMOTE_SCRIPT_PATH}"

    # Copy the service file to a temp location, then move with sudo
    log_info "Installing systemd service..."
    scp $SSH_OPTS "$LOCAL_SERVICE" "${REMOTE_HOST}:/tmp/${SERVICE_FILE}"
    remote_sudo "mv /tmp/${SERVICE_FILE} ${REMOTE_SERVICE_PATH}"
    remote_sudo "chmod 644 ${REMOTE_SERVICE_PATH}"

    # Reload systemd
    log_info "Reloading systemd..."
    remote_sudo "systemctl daemon-reload"

    # Enable the service to start on boot
    log_info "Enabling service to start on boot..."
    remote_sudo "systemctl enable ${SERVICE_NAME}"

    log_info "Deployment complete!"
}

# Restart the daemon
restart_daemon() {
    log_info "Restarting ${SERVICE_NAME} daemon..."
    remote_sudo "systemctl restart ${SERVICE_NAME}"
    sleep 2
    show_status
}

# Start the daemon
start_daemon() {
    log_info "Starting ${SERVICE_NAME} daemon..."
    remote_sudo "systemctl start ${SERVICE_NAME}"
    sleep 2
    show_status
}

# Stop the daemon
stop_daemon() {
    log_info "Stopping ${SERVICE_NAME} daemon..."
    remote_sudo "systemctl stop ${SERVICE_NAME}"
    log_info "Daemon stopped"
}

# Show daemon status
show_status() {
    echo ""
    log_info "Daemon status:"
    echo "--------------------------------------------------------------"
    remote_sudo "systemctl status ${SERVICE_NAME} --no-pager" || true
    echo "--------------------------------------------------------------"
}

# Show daemon logs
show_logs() {
    log_info "Showing logs for ${SERVICE_NAME} (Ctrl+C to exit)..."
    echo "--------------------------------------------------------------"
    remote_sudo "journalctl -u ${SERVICE_NAME} -f"
}

# Run a management command (--list, --add, --remove, etc.)
run_management_cmd() {
    check_local_files

    # Build properly quoted arguments for remote shell
    local SCRIPT_ARGS=""
    for arg in "$@"; do
        escaped_arg=$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")
        SCRIPT_ARGS="$SCRIPT_ARGS '$escaped_arg'"
    done

    log_info "Running management command..."

    # Copy latest script first
    scp $SSH_OPTS "$LOCAL_SCRIPT" "${REMOTE_HOST}:${REMOTE_SCRIPT_PATH}" >/dev/null

    # Run the command
    echo "--------------------------------------------------------------"
    ssh $SSH_OPTS "$REMOTE_HOST" "sudo python3 ${REMOTE_SCRIPT_PATH} ${SCRIPT_ARGS}"
    local EXIT_CODE=$?
    echo "--------------------------------------------------------------"

    return $EXIT_CODE
}

# Print usage
print_usage() {
    echo "Pi-hole Elapsed Time Trigger - Deployment Script"
    echo ""
    echo "Usage:"
    echo "  ./deploy.sh                Deploy script and restart daemon"
    echo "  ./deploy.sh --status       Check daemon status"
    echo "  ./deploy.sh --logs         View daemon logs (live)"
    echo "  ./deploy.sh --stop         Stop the daemon"
    echo "  ./deploy.sh --start        Start the daemon (without redeploying)"
    echo ""
    echo "Trigger Management:"
    echo "  ./deploy.sh --list         List configured triggers"
    echo "  ./deploy.sh --add NAME GROUP_IDS TIME_LIMIT DOMAINS REGEX"
    echo "                             Add a new trigger"
    echo "  ./deploy.sh --remove ID    Remove a trigger"
    echo "  ./deploy.sh --enable ID    Enable a trigger"
    echo "  ./deploy.sh --disable ID   Disable a trigger"
    echo "  ./deploy.sh --unblock      Remove all active blocks"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh --add 'YouTube Limit' '2,3' 3600 'youtube,googlevideo.com' 'youtube|googlevideo\\.com'"
}

# Main logic
case "${1:-}" in
    --help|-h)
        print_usage
        exit 0
        ;;
    --status)
        show_status
        exit 0
        ;;
    --logs)
        show_logs
        exit 0
        ;;
    --stop)
        stop_daemon
        exit 0
        ;;
    --start)
        start_daemon
        exit 0
        ;;
    --list|--add|--remove|--enable|--disable|--unblock)
        run_management_cmd "$@"
        exit $?
        ;;
    "")
        # Default: deploy and restart
        deploy_files
        restart_daemon
        exit 0
        ;;
    *)
        log_error "Unknown option: $1"
        print_usage
        exit 1
        ;;
esac
