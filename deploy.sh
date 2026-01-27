#!/bin/bash
#
# Deploy and manage the Pi-hole Elapsed Time Trigger daemon and web interface
#
# Usage:
#   ./deploy.sh                Deploy script and restart daemon
#   ./deploy.sh --status       Check daemon status
#   ./deploy.sh --logs         View daemon logs (live)
#   ./deploy.sh --stop         Stop the daemon
#   ./deploy.sh --start        Start the daemon
#   ./deploy.sh --list         List configured triggers
#   ./deploy.sh --add ...      Add a new trigger
#   ./deploy.sh --edit ID ...  Edit a trigger
#   ./deploy.sh --remove ID    Remove a trigger
#   ./deploy.sh --reset ID     Reset a trigger (remove block)
#   ./deploy.sh --unblock      Remove all active blocks
#
# Web Interface:
#   ./deploy.sh --web-status   Check web server status
#   ./deploy.sh --web-logs     View web server logs (live)
#   ./deploy.sh --web-stop     Stop the web server
#   ./deploy.sh --web-start    Start the web server
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
REMOTE_SCRIPT_PATH="/home/${PIHOLE_USER}/${SCRIPT_NAME}"
REMOTE_SERVICE_PATH="/etc/systemd/system/${SERVICE_FILE}"
LOCAL_SCRIPT="${SCRIPT_DIR}/${SCRIPT_NAME}"
LOCAL_SERVICE="${SCRIPT_DIR}/${SERVICE_FILE}"

# Web interface configuration
WEB_SERVICE_NAME="trigger-web"
WEB_SERVICE_FILE="${WEB_SERVICE_NAME}.service"
REMOTE_WEB_PATH="/home/${PIHOLE_USER}/trigger_web"
REMOTE_WEB_SERVICE_PATH="/etc/systemd/system/${WEB_SERVICE_FILE}"
LOCAL_WEB_DIR="${SCRIPT_DIR}/trigger_web"
LOCAL_WEB_SERVICE="${SCRIPT_DIR}/${WEB_SERVICE_FILE}"

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

# Check if web local files exist
check_web_files() {
    if [[ ! -d "$LOCAL_WEB_DIR" ]]; then
        log_error "Web directory not found: $LOCAL_WEB_DIR"
        exit 1
    fi
    if [[ ! -f "$LOCAL_WEB_DIR/app.py" ]]; then
        log_error "Web app not found: $LOCAL_WEB_DIR/app.py"
        exit 1
    fi
    if [[ ! -f "$LOCAL_WEB_SERVICE" ]]; then
        log_error "Web service file not found: $LOCAL_WEB_SERVICE"
        exit 1
    fi
}

# Deploy the script and service file to the remote host
deploy_files() {
    check_local_files

    log_info "Deploying daemon files to ${REMOTE_HOST}..."

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

    log_info "Daemon deployment complete!"
}

# Deploy the web interface files to the remote host
deploy_web() {
    check_web_files

    log_info "Deploying web interface to ${REMOTE_HOST}..."

    # Create remote directory structure
    log_info "Creating directory structure..."
    remote_cmd "mkdir -p ${REMOTE_WEB_PATH}/templates ${REMOTE_WEB_PATH}/static"

    # Copy web app files
    log_info "Copying web app files..."
    scp $SSH_OPTS "$LOCAL_WEB_DIR/app.py" "${REMOTE_HOST}:${REMOTE_WEB_PATH}/app.py"

    # Copy templates
    log_info "Copying templates..."
    scp $SSH_OPTS "$LOCAL_WEB_DIR/templates/"*.html "${REMOTE_HOST}:${REMOTE_WEB_PATH}/templates/"

    # Copy static files
    log_info "Copying static files..."
    scp $SSH_OPTS "$LOCAL_WEB_DIR/static/"* "${REMOTE_HOST}:${REMOTE_WEB_PATH}/static/"

    # Install Flask if not present
    log_info "Checking Flask installation..."
    remote_sudo "pip3 show flask > /dev/null 2>&1 || pip3 install flask"

    # Copy the service file to a temp location, then move with sudo
    log_info "Installing web service..."
    scp $SSH_OPTS "$LOCAL_WEB_SERVICE" "${REMOTE_HOST}:/tmp/${WEB_SERVICE_FILE}"
    remote_sudo "mv /tmp/${WEB_SERVICE_FILE} ${REMOTE_WEB_SERVICE_PATH}"
    remote_sudo "chmod 644 ${REMOTE_WEB_SERVICE_PATH}"

    # Reload systemd
    log_info "Reloading systemd..."
    remote_sudo "systemctl daemon-reload"

    # Enable the service to start on boot
    log_info "Enabling web service to start on boot..."
    remote_sudo "systemctl enable ${WEB_SERVICE_NAME}"

    log_info "Web interface deployment complete!"
}

# Deploy everything (daemon + web)
deploy_all() {
    deploy_files
    deploy_web
}

# Clean previous installation
clean() {
    log_info "Cleaning previous installation from ${REMOTE_HOST}..."

    # Stop services if running
    log_info "Stopping services..."
    remote_sudo "systemctl stop ${SERVICE_NAME} 2>/dev/null || true"
    remote_sudo "systemctl stop ${WEB_SERVICE_NAME} 2>/dev/null || true"

    # Disable services
    log_info "Disabling services..."
    remote_sudo "systemctl disable ${SERVICE_NAME} 2>/dev/null || true"
    remote_sudo "systemctl disable ${WEB_SERVICE_NAME} 2>/dev/null || true"

    # Remove service files
    log_info "Removing service files..."
    remote_sudo "rm -f ${REMOTE_SERVICE_PATH}"
    remote_sudo "rm -f ${REMOTE_WEB_SERVICE_PATH}"

    # Remove script and web directory
    log_info "Removing application files..."
    remote_cmd "rm -f ${REMOTE_SCRIPT_PATH}"
    remote_cmd "rm -rf ${REMOTE_WEB_PATH}"

    # Reload systemd
    log_info "Reloading systemd..."
    remote_sudo "systemctl daemon-reload"

    log_info "Clean complete!"
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

# Web server control functions
restart_web() {
    log_info "Restarting ${WEB_SERVICE_NAME} web server..."
    remote_sudo "systemctl restart ${WEB_SERVICE_NAME}"
    sleep 2
    show_web_status
}

start_web() {
    log_info "Starting ${WEB_SERVICE_NAME} web server..."
    remote_sudo "systemctl start ${WEB_SERVICE_NAME}"
    sleep 2
    show_web_status
}

stop_web() {
    log_info "Stopping ${WEB_SERVICE_NAME} web server..."
    remote_sudo "systemctl stop ${WEB_SERVICE_NAME}"
    log_info "Web server stopped"
}

show_web_status() {
    echo ""
    log_info "Web server status:"
    echo "--------------------------------------------------------------"
    remote_sudo "systemctl status ${WEB_SERVICE_NAME} --no-pager" || true
    echo "--------------------------------------------------------------"
    log_info "Web interface: http://${PIHOLE_HOST}:8080"
}

show_web_logs() {
    log_info "Showing logs for ${WEB_SERVICE_NAME} (Ctrl+C to exit)..."
    echo "--------------------------------------------------------------"
    remote_sudo "journalctl -u ${WEB_SERVICE_NAME} -f"
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
    echo "  ./deploy.sh                Deploy everything and restart services (same as --all)"
    echo "  ./deploy.sh --all          Deploy daemon + web interface, restart both services"
    echo "  ./deploy.sh --cli-only     Deploy daemon only (no web interface), restart daemon"
    echo "  ./deploy.sh --clean        Remove previous installation (stop/disable services, remove files)"
    echo "  ./deploy.sh --status       Check daemon status"
    echo "  ./deploy.sh --logs         View daemon logs (live)"
    echo "  ./deploy.sh --stop         Stop the daemon"
    echo "  ./deploy.sh --start        Start the daemon (without redeploying)"
    echo ""
    echo "Web Interface:"
    echo "  ./deploy.sh --web-status   Check web server status"
    echo "  ./deploy.sh --web-logs     View web server logs (live)"
    echo "  ./deploy.sh --web-stop     Stop the web server"
    echo "  ./deploy.sh --web-start    Start the web server"
    echo ""
    echo "Trigger Management:"
    echo "  ./deploy.sh --list                       List configured triggers"
    echo "  ./deploy.sh --add [OPTIONS]              Add a new trigger"
    echo "  ./deploy.sh --edit ID [OPTIONS]          Edit a trigger"
    echo "  ./deploy.sh --remove ID                  Remove a trigger"
    echo "  ./deploy.sh --reset ID                   Reset a trigger (remove active block)"
    echo "  ./deploy.sh --unblock                    Remove all active blocks"
    echo ""
    echo "Trigger field options (for --add and --edit):"
    echo "  -n, --name NAME        Trigger name"
    echo "  -g, --groups IDS       Pi-hole group IDs (comma-separated)"
    echo "  -t, --time SECONDS     Time limit in seconds"
    echo "  -d, --domains DOMAINS  Trigger domains (comma-separated)"
    echo "  -r, --regex PATTERN    Block regex pattern"
    echo "  --enable               Enable the trigger"
    echo "  --disable              Disable the trigger"
    echo ""
    echo "Examples:"
    echo "  ./deploy.sh --add -n 'YouTube' -g 2,3 -t 3600 -d 'youtube,googlevideo.com' -r 'youtube|googlevideo\\.com'"
    echo "  ./deploy.sh --edit 1 -t 7200             Change time limit for trigger 1"
    echo "  ./deploy.sh --edit 1 --disable           Disable trigger 1"
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
    --web-status)
        show_web_status
        exit 0
        ;;
    --web-logs)
        show_web_logs
        exit 0
        ;;
    --web-stop)
        stop_web
        exit 0
        ;;
    --web-start)
        start_web
        exit 0
        ;;
    --clean)
        clean
        exit 0
        ;;
    --cli-only)
        deploy_files
        restart_daemon
        exit 0
        ;;
    --all)
        deploy_all
        restart_daemon
        restart_web
        exit 0
        ;;
    --list|--add|--edit|--remove|--reset|--unblock)
        run_management_cmd "$@"
        exit $?
        ;;
    "")
        # Default: deploy everything and restart services
        deploy_all
        restart_daemon
        restart_web
        exit 0
        ;;
    *)
        log_error "Unknown option: $1"
        print_usage
        exit 1
        ;;
esac
