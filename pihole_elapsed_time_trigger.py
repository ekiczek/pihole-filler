#!/usr/bin/env python3
"""
Pi-hole v6 Elapsed Time Trigger

Monitors Pi-hole DNS queries and blocks specified domains for device groups
after a configurable time period from first access. Supports multiple triggers.

Usage:
    sudo python3 pihole_elapsed_time_trigger.py              Run all enabled triggers
    sudo python3 pihole_elapsed_time_trigger.py --list       List all triggers
    sudo python3 pihole_elapsed_time_trigger.py --add        Add a new trigger
    sudo python3 pihole_elapsed_time_trigger.py --remove ID  Remove a trigger
    sudo python3 pihole_elapsed_time_trigger.py --enable ID  Enable a trigger
    sudo python3 pihole_elapsed_time_trigger.py --disable ID Disable a trigger
    sudo python3 pihole_elapsed_time_trigger.py --unblock    Remove all active blocks

Requirements:
    - Pi-hole v6+
    - Must run as root (for database access and log reading)
    - No external Python dependencies
"""

import subprocess
import time
import re
import os
import sys
import signal
from datetime import datetime, timedelta
from pathlib import Path

# =============================================================================
# CONFIGURATION
# =============================================================================

# Pi-hole paths (v6 locations) - these are fixed system paths
PIHOLE_LOG = "/var/log/pihole/pihole.log"
GRAVITY_DB = "/etc/pihole/gravity.db"
FTL_DB = "/etc/pihole/pihole-FTL.db"

# Trigger configuration database (same directory as this script)
TRIGGER_DB = Path(__file__).parent / "trigger.db"

# Domain list type for regex denylist
DOMAINLIST_TYPE_REGEX_DENY = 3

# =============================================================================
# GLOBAL STATE
# =============================================================================

running = True
triggers = []  # List of active trigger configs
trigger_states = {}  # State for each trigger: {trigger_id: {'first_access': datetime, 'is_blocked': bool, 'target_ips': set}}

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def run_sqlite(query, db_path=GRAVITY_DB):
    """
    Run a SQLite query using pihole-FTL's embedded sqlite3.
    Returns (success, output) tuple.
    """
    try:
        result = subprocess.run(
            ["pihole-FTL", "sqlite3", "-separator", "␞", str(db_path), query],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
            return (False, error_msg)
        return (True, result.stdout.strip())
    except Exception as e:
        print(f"[DB] Error running query: {e}")
        return (False, str(e))

def init_trigger_db():
    """Initialize the trigger configuration database if it doesn't exist."""
    create_table = """
        CREATE TABLE IF NOT EXISTS triggers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            group_id INTEGER NOT NULL,
            time_limit_seconds INTEGER NOT NULL,
            trigger_domains TEXT NOT NULL,
            block_regex TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """
    success, output = run_sqlite(create_table, db_path=TRIGGER_DB)
    if not success:
        print(f"[DB] Failed to initialize trigger database: {output}")
        return False
    return True

def load_triggers():
    """Load all enabled triggers from the database."""
    query = "SELECT id, name, group_id, time_limit_seconds, trigger_domains, block_regex FROM triggers WHERE enabled = 1"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if not success:
        print(f"[DB] Failed to load triggers: {output}")
        return []

    if not output:
        return []

    triggers = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 6:
            triggers.append({
                'id': int(parts[0]),
                'name': parts[1],
                'group_id': int(parts[2]),
                'time_limit_seconds': int(parts[3]),
                'trigger_domains': [d.strip() for d in parts[4].split(',')],
                'block_regex': parts[5],
            })
    return triggers

def list_triggers():
    """List all triggers in the database."""
    query = "SELECT id, name, group_id, time_limit_seconds, trigger_domains, enabled FROM triggers ORDER BY id"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if not success:
        print(f"Error: Failed to query triggers: {output}")
        return

    if not output:
        print("No triggers configured.")
        print("\nUse --add to create a new trigger.")
        return

    print("\nConfigured Triggers:")
    print("=" * 80)
    print(f"{'ID':<4} {'Name':<20} {'Group':<6} {'Time':<8} {'Domains':<30} {'Status':<8}")
    print("-" * 80)

    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 6:
            trigger_id = parts[0]
            name = parts[1][:18] + '..' if len(parts[1]) > 20 else parts[1]
            group_id = parts[2]
            time_limit = f"{parts[3]}s"
            domains = parts[4][:28] + '..' if len(parts[4]) > 30 else parts[4]
            status = "Enabled" if parts[5] == '1' else "Disabled"
            print(f"{trigger_id:<4} {name:<20} {group_id:<6} {time_limit:<8} {domains:<30} {status:<8}")

    print("=" * 80)

def add_trigger_cli(name, group_id, time_limit, trigger_domains, block_regex):
    """Add a new trigger via command-line arguments."""
    # Validate inputs
    if not name:
        print("Error: Name is required")
        return False

    try:
        group_id = int(group_id)
    except ValueError:
        print("Error: Group ID must be a number")
        return False

    try:
        time_limit = int(time_limit)
    except ValueError:
        print("Error: Time limit must be a number")
        return False

    if not trigger_domains:
        print("Error: At least one trigger domain is required")
        return False

    if not block_regex:
        print("Error: Block regex is required")
        return False

    # Escape single quotes for SQL
    name_escaped = name.replace("'", "''")
    trigger_domains_escaped = trigger_domains.replace("'", "''")
    block_regex_escaped = block_regex.replace("'", "''")

    query = f"""
        INSERT INTO triggers (name, group_id, time_limit_seconds, trigger_domains, block_regex)
        VALUES ('{name_escaped}', {group_id}, {time_limit}, '{trigger_domains_escaped}', '{block_regex_escaped}')
    """

    success, output = run_sqlite(query, db_path=TRIGGER_DB)
    if success:
        print(f"Trigger '{name}' added successfully!")
        return True
    else:
        print(f"Error: Failed to add trigger: {output}")
        return False

def add_trigger():
    """Interactively add a new trigger."""
    print("\nAdd New Trigger")
    print("=" * 40)

    try:
        name = input("Trigger name (e.g., 'YouTube Limit'): ").strip()
        group_id = input("Pi-hole Group ID to monitor: ").strip()
        time_limit = input("Time limit in seconds (e.g., 3600 for 1 hour): ").strip()
        trigger_domains = input("Trigger domains (comma-separated, e.g., 'youtube,googlevideo.com'): ").strip()
        block_regex = input("Block regex pattern: ").strip()

        return add_trigger_cli(name, group_id, time_limit, trigger_domains, block_regex)

    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return False

def remove_trigger(trigger_id):
    """Remove a trigger by ID."""
    # First check if it exists
    check_query = f"SELECT name FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(check_query, db_path=TRIGGER_DB)

    if not success or not output:
        print(f"Error: Trigger with ID {trigger_id} not found")
        return False

    name = output.strip()

    query = f"DELETE FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if success:
        print(f"Trigger '{name}' (ID: {trigger_id}) removed successfully!")
        return True
    else:
        print(f"Error: Failed to remove trigger: {output}")
        return False

def set_trigger_enabled(trigger_id, enabled):
    """Enable or disable a trigger."""
    # First check if it exists
    check_query = f"SELECT name FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(check_query, db_path=TRIGGER_DB)

    if not success or not output:
        print(f"Error: Trigger with ID {trigger_id} not found")
        return False

    name = output.strip()

    query = f"UPDATE triggers SET enabled = {1 if enabled else 0} WHERE id = {trigger_id}"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if success:
        status = "enabled" if enabled else "disabled"
        print(f"Trigger '{name}' (ID: {trigger_id}) {status}!")
        return True
    else:
        print(f"Error: Failed to update trigger: {output}")
        return False

def get_block_comment(trigger):
    """Generate a unique block comment for a trigger."""
    return f"Time trigger [{trigger['id']}] - {trigger['name']}"

def get_existing_block(trigger):
    """Check if the block rule for a trigger already exists."""
    comment = get_block_comment(trigger)
    query = f"SELECT id FROM domainlist WHERE comment = '{comment}' AND type = {DOMAINLIST_TYPE_REGEX_DENY}"
    success, output = run_sqlite(query)

    if success and output:
        return int(output.split('\n')[0])
    return None

def add_block(trigger):
    """Add blocking regex to the database for a trigger's group."""
    comment = get_block_comment(trigger)
    print(f"[{trigger['name']}] Adding block rule...")

    # Check if it already exists
    existing_id = get_existing_block(trigger)
    if existing_id:
        print(f"[{trigger['name']}] Rule already exists (ID: {existing_id}), enabling it...")
        return enable_block(trigger, existing_id)

    # Escape single quotes in regex
    block_regex = trigger['block_regex'].replace("'", "''")

    # Insert the new regex deny rule
    insert_query = f"""
        INSERT INTO domainlist (type, domain, enabled, comment)
        VALUES ({DOMAINLIST_TYPE_REGEX_DENY}, '{block_regex}', 1, '{comment}')
    """

    success, output = run_sqlite(insert_query)

    # Verify the insert
    domain_id = get_existing_block(trigger)
    if not domain_id:
        print(f"[{trigger['name']}] Failed to insert rule: {output}")
        return False

    if not success:
        print(f"[{trigger['name']}] Note: INSERT reported error but succeeded (ID: {domain_id})")
    else:
        print(f"[{trigger['name']}] Inserted rule (ID: {domain_id})")

    # Remove from default group (0) and add to our target group
    delete_default = f"DELETE FROM domainlist_by_group WHERE domainlist_id = {domain_id} AND group_id = 0"
    run_sqlite(delete_default)

    add_to_group = f"INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES ({domain_id}, {trigger['group_id']})"
    success, output = run_sqlite(add_to_group)

    if not success:
        print(f"[{trigger['name']}] Failed to assign to group: {output}")
        return False

    print(f"[{trigger['name']}] Assigned rule to group {trigger['group_id']}")
    return True

def enable_block(trigger, domain_id):
    """Enable an existing block rule."""
    query = f"UPDATE domainlist SET enabled = 1 WHERE id = {domain_id}"
    success, output = run_sqlite(query)

    if success:
        print(f"[{trigger['name']}] Enabled rule (ID: {domain_id})")
        return True
    else:
        print(f"[{trigger['name']}] Failed to enable rule: {output}")
        return False

def remove_block(trigger):
    """Remove the blocking rule for a trigger."""
    domain_id = get_existing_block(trigger)

    if not domain_id:
        return False

    print(f"[{trigger['name']}] Removing rule (ID: {domain_id})...")

    query = f"DELETE FROM domainlist WHERE id = {domain_id}"
    success, output = run_sqlite(query)

    # Verify the delete
    still_exists = get_existing_block(trigger)
    if still_exists:
        print(f"[{trigger['name']}] Failed to remove rule: {output}")
        return False

    print(f"[{trigger['name']}] Rule removed")
    return True

def remove_all_blocks():
    """Remove all block rules created by triggers."""
    query = f"SELECT id, comment FROM domainlist WHERE comment LIKE 'Time trigger [%' AND type = {DOMAINLIST_TYPE_REGEX_DENY}"
    success, output = run_sqlite(query)

    if not success:
        print(f"Error querying blocks: {output}")
        return False

    if not output:
        print("No active blocks found.")
        return True

    removed = 0
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 2:
            domain_id = parts[0]
            comment = parts[1]

            delete_query = f"DELETE FROM domainlist WHERE id = {domain_id}"
            success, _ = run_sqlite(delete_query)
            if success:
                print(f"Removed: {comment}")
                removed += 1

    if removed > 0:
        reload_pihole()
        print(f"\nRemoved {removed} block(s).")

    return True

def reload_pihole():
    """Restart Pi-hole FTL to apply changes."""
    print("[Pi-hole] Restarting FTL service...")
    result = subprocess.run(
        ["systemctl", "restart", "pihole-FTL"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("[Pi-hole] FTL restart successful")
    else:
        print(f"[Pi-hole] FTL restart may have failed: {result.stderr}")

def get_group_clients(group_id):
    """Get all client IPs that belong to a specific group."""
    query = f"""
        SELECT c.ip FROM client c
        JOIN client_by_group cbg ON c.id = cbg.client_id
        WHERE cbg.group_id = {group_id}
    """
    success, output = run_sqlite(query)

    if not success:
        print(f"[DB] Failed to get group clients: {output}")
        return set()

    if not output:
        return set()

    client_ids = set(line.strip() for line in output.split('\n') if line.strip())
    ip_addresses = set()

    for client_id in client_ids:
        if ':' in client_id:
            # MAC address - resolve to IP
            mac_lower = client_id.lower()
            mac_query = f"""
                SELECT na.ip FROM network n
                JOIN network_addresses na ON n.id = na.network_id
                WHERE n.hwaddr = '{mac_lower}'
            """
            success, ip_output = run_sqlite(mac_query, db_path=FTL_DB)
            if success and ip_output:
                for ip in ip_output.split('\n'):
                    ip = ip.strip()
                    if ip:
                        ip_addresses.add(ip)
                        print(f"[DB] Resolved {client_id} -> {ip}")
            else:
                print(f"[DB] Warning: Could not resolve IP for MAC {client_id}")
        else:
            ip_addresses.add(client_id)

    return ip_addresses

# =============================================================================
# LOG MONITORING
# =============================================================================

def is_trigger_domain(domain, trigger):
    """Check if a domain matches any trigger domain for a specific trigger."""
    domain_lower = domain.lower()
    return any(td in domain_lower for td in trigger['trigger_domains'])

def parse_pihole_log_line(line):
    """
    Parse a Pi-hole log line and extract query information.
    Returns (timestamp, client_ip, domain) or None if not a query line.
    """
    query_pattern = r"^(\w+\s+\d+\s+[\d:]+).*query\[.*\]\s+(\S+)\s+from\s+(\S+)"
    match = re.search(query_pattern, line)

    if match:
        timestamp_str = match.group(1)
        domain = match.group(2)
        client_ip = match.group(3)
        return (timestamp_str, client_ip, domain)

    return None

def tail_log(filepath):
    """Generator that yields new lines from a log file (like 'tail -f')."""
    while running:
        try:
            with open(filepath, 'r') as f:
                f.seek(0, 2)

                while running:
                    line = f.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.1)

                        try:
                            if os.stat(filepath).st_ino != os.fstat(f.fileno()).st_ino:
                                print("[Monitor] Log file rotated, reopening...")
                                break
                        except FileNotFoundError:
                            print("[Monitor] Log file not found, waiting...")
                            time.sleep(1)
                            break

        except FileNotFoundError:
            print(f"[Monitor] Waiting for log file: {filepath}")
            time.sleep(1)

# =============================================================================
# MAIN LOGIC
# =============================================================================

def handle_trigger_access(trigger, client_ip):
    """Handle detection of trigger domain access from a target IP."""
    state = trigger_states[trigger['id']]

    if state['is_blocked']:
        return

    now = datetime.now()

    if state['first_access'] is None:
        state['first_access'] = now
        block_time = now + timedelta(seconds=trigger['time_limit_seconds'])
        print(f"[{trigger['name']}] First access from {client_ip} at {now.strftime('%H:%M:%S')}")
        print(f"[{trigger['name']}] Will block at {block_time.strftime('%H:%M:%S')}")
    else:
        elapsed = (now - state['first_access']).total_seconds()
        remaining = trigger['time_limit_seconds'] - elapsed

        if remaining > 0:
            print(f"[{trigger['name']}] Access from {client_ip} - {remaining:.0f}s remaining")
        else:
            print(f"[{trigger['name']}] Time limit exceeded! Blocking...")
            if add_block(trigger):
                state['is_blocked'] = True
                reload_pihole()
                print(f"[{trigger['name']}] Domains are now BLOCKED for group {trigger['group_id']}")
            else:
                print(f"[{trigger['name']}] Failed to add block - will retry")

def check_timers_expired():
    """Check if any trigger timers have expired."""
    for trigger in triggers:
        state = trigger_states[trigger['id']]

        if state['is_blocked'] or state['first_access'] is None:
            continue

        elapsed = (datetime.now() - state['first_access']).total_seconds()
        if elapsed >= trigger['time_limit_seconds']:
            print(f"[{trigger['name']}] Time limit expired! Blocking...")
            if add_block(trigger):
                state['is_blocked'] = True
                reload_pihole()
                print(f"[{trigger['name']}] Domains are now BLOCKED for group {trigger['group_id']}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global running
    print("\n[Shutdown] Received signal, shutting down...")
    running = False

def main():
    global running, triggers, trigger_states

    # Check if running as root
    if os.geteuid() != 0:
        print("Error: This script must be run as root (sudo)")
        sys.exit(1)

    # Check paths
    if not Path(PIHOLE_LOG).exists():
        print(f"Error: Pi-hole log not found at {PIHOLE_LOG}")
        sys.exit(1)
    if not Path(GRAVITY_DB).exists():
        print(f"Error: Gravity database not found at {GRAVITY_DB}")
        sys.exit(1)
    if not Path(FTL_DB).exists():
        print(f"Error: FTL database not found at {FTL_DB}")
        sys.exit(1)

    # Initialize trigger database
    if not init_trigger_db():
        sys.exit(1)

    # Load triggers
    triggers = load_triggers()
    if not triggers:
        print("No enabled triggers found.")
        print("Use --add to create a trigger, or --list to see all triggers.")
        sys.exit(1)

    # Initialize state for each trigger
    for trigger in triggers:
        target_ips = get_group_clients(trigger['group_id'])
        if not target_ips:
            print(f"Warning: No clients found in group {trigger['group_id']} for trigger '{trigger['name']}'")

        trigger_states[trigger['id']] = {
            'first_access': None,
            'is_blocked': False,
            'target_ips': target_ips
        }

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Display status
    print("=" * 70)
    print("Pi-hole v6 Elapsed Time Trigger")
    print("=" * 70)
    print(f"Monitoring {len(triggers)} trigger(s):\n")

    for trigger in triggers:
        state = trigger_states[trigger['id']]
        print(f"  [{trigger['id']}] {trigger['name']}")
        print(f"      Group: {trigger['group_id']} ({len(state['target_ips'])} clients)")
        print(f"      Time limit: {trigger['time_limit_seconds']} seconds")
        print(f"      Watching: {', '.join(trigger['trigger_domains'][:3])}{'...' if len(trigger['trigger_domains']) > 3 else ''}")
        print()

    print(f"Log file: {PIHOLE_LOG}")
    print("=" * 70)

    # Clear any previous blocks on startup
    print("\n[Setup] Clearing any previous blocks...")
    for trigger in triggers:
        remove_block(trigger)

    print("\n[Monitor] Starting log monitoring...")
    print("-" * 70)

    last_timer_check = datetime.now()

    try:
        for line in tail_log(PIHOLE_LOG):
            if not running:
                break

            parsed = parse_pihole_log_line(line)
            if parsed:
                _, client_ip, domain = parsed

                # Check each trigger
                for trigger in triggers:
                    state = trigger_states[trigger['id']]
                    if client_ip in state['target_ips'] and is_trigger_domain(domain, trigger):
                        handle_trigger_access(trigger, client_ip)

            # Periodically check if any timers expired
            now = datetime.now()
            if (now - last_timer_check).total_seconds() >= 1:
                check_timers_expired()
                last_timer_check = now

    except Exception as e:
        print(f"[Error] {e}")
        raise
    finally:
        print("\n[Shutdown] Script ended")
        for trigger in triggers:
            state = trigger_states[trigger['id']]
            print(f"[{trigger['name']}] Blocked: {state['is_blocked']}")

def print_help():
    """Print help message."""
    print("Usage:")
    print("  sudo python3 pihole_elapsed_time_trigger.py              Run all enabled triggers")
    print("  sudo python3 pihole_elapsed_time_trigger.py --list       List all triggers")
    print("  sudo python3 pihole_elapsed_time_trigger.py --add        Add a new trigger (interactive)")
    print("  sudo python3 pihole_elapsed_time_trigger.py --add NAME GROUP_ID TIME_LIMIT DOMAINS REGEX")
    print("                                                           Add a trigger (non-interactive)")
    print("  sudo python3 pihole_elapsed_time_trigger.py --remove ID  Remove a trigger")
    print("  sudo python3 pihole_elapsed_time_trigger.py --enable ID  Enable a trigger")
    print("  sudo python3 pihole_elapsed_time_trigger.py --disable ID Disable a trigger")
    print("  sudo python3 pihole_elapsed_time_trigger.py --unblock    Remove all active blocks")
    print("  sudo python3 pihole_elapsed_time_trigger.py --help       Show this help")
    print()
    print("Examples:")
    print("  --add 'YouTube Limit' 2 3600 'youtube,googlevideo.com' 'youtube|googlevideo\\.com'")

if __name__ == "__main__":
    # Initialize database for management commands (doesn't require root for some)
    if len(sys.argv) > 1:
        cmd = sys.argv[1]

        if cmd == "--help":
            print_help()
            sys.exit(0)

        # These commands need root
        if os.geteuid() != 0:
            print("Error: Must run as root (sudo)")
            sys.exit(1)

        # Initialize DB for all commands
        if not init_trigger_db():
            sys.exit(1)

        if cmd == "--list":
            list_triggers()
            sys.exit(0)

        elif cmd == "--add":
            if len(sys.argv) == 2:
                # Interactive mode
                if add_trigger():
                    sys.exit(0)
            elif len(sys.argv) == 7:
                # Non-interactive mode: --add NAME GROUP_ID TIME_LIMIT DOMAINS REGEX
                if add_trigger_cli(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]):
                    sys.exit(0)
            else:
                print("Error: --add requires either no arguments (interactive) or 5 arguments:")
                print("  --add NAME GROUP_ID TIME_LIMIT DOMAINS REGEX")
                print()
                print("Example:")
                print("  --add 'YouTube Limit' 2 3600 'youtube,googlevideo.com' 'youtube|googlevideo\\.com'")
            sys.exit(1)

        elif cmd == "--remove":
            if len(sys.argv) < 3:
                print("Error: --remove requires a trigger ID")
                print("Usage: --remove ID")
                sys.exit(1)
            try:
                trigger_id = int(sys.argv[2])
            except ValueError:
                print("Error: ID must be a number")
                sys.exit(1)
            if remove_trigger(trigger_id):
                sys.exit(0)
            sys.exit(1)

        elif cmd == "--enable":
            if len(sys.argv) < 3:
                print("Error: --enable requires a trigger ID")
                sys.exit(1)
            try:
                trigger_id = int(sys.argv[2])
            except ValueError:
                print("Error: ID must be a number")
                sys.exit(1)
            if set_trigger_enabled(trigger_id, True):
                sys.exit(0)
            sys.exit(1)

        elif cmd == "--disable":
            if len(sys.argv) < 3:
                print("Error: --disable requires a trigger ID")
                sys.exit(1)
            try:
                trigger_id = int(sys.argv[2])
            except ValueError:
                print("Error: ID must be a number")
                sys.exit(1)
            if set_trigger_enabled(trigger_id, False):
                sys.exit(0)
            sys.exit(1)

        elif cmd == "--unblock":
            print("Removing all blocks...")
            remove_all_blocks()
            sys.exit(0)

        else:
            print(f"Unknown option: {cmd}")
            print_help()
            sys.exit(1)

    main()
