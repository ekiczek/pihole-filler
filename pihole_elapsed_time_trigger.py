#!/usr/bin/env python3
"""
Pi-hole v6 Elapsed Time Trigger

Monitors Pi-hole DNS queries and blocks specified domains for device groups
after a configurable time period from first access. Supports multiple triggers.

Usage:
    sudo python3 pihole_elapsed_time_trigger.py                    Run the daemon
    sudo python3 pihole_elapsed_time_trigger.py --list             List all triggers
    sudo python3 pihole_elapsed_time_trigger.py --add [OPTIONS]    Add a new trigger
    sudo python3 pihole_elapsed_time_trigger.py --edit ID [OPTS]   Edit a trigger
    sudo python3 pihole_elapsed_time_trigger.py --remove ID        Remove a trigger
    sudo python3 pihole_elapsed_time_trigger.py --reset ID         Reset trigger (remove block)
    sudo python3 pihole_elapsed_time_trigger.py --unblock          Remove all active blocks

Trigger field options (for --add and --edit):
    -n, --name NAME        Trigger name
    -g, --groups IDS       Pi-hole group IDs (comma-separated, e.g., "2,3")
    -t, --time SECONDS     Time limit in seconds
    -d, --domains DOMAINS  Trigger domains (comma-separated)
    -r, --regex PATTERN    Block regex pattern
    --enable               Enable the trigger
    --disable              Disable the trigger

Examples:
    --add -n 'YouTube' -g 2,3 -t 3600 -d 'youtube,youtu.be,googlevideo.com,ytimg.com' -r 'youtube|(^|\.)youtu\.be$|(^|\.)googlevideo\.com$|(^|\.)ytimg\.com$'
    --edit 1 -t 7200                    Change time limit for trigger 1
    --edit 1 --disable                  Disable trigger 1

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

# Default daily reset hour (24-hour format, local time)
# Can be overridden via settings in the database
DEFAULT_RESET_HOUR = 3  # 3:00 AM

# =============================================================================
# GLOBAL STATE
# =============================================================================

running = True
triggers = []  # List of active trigger configs
trigger_states = {}  # State for each trigger: {trigger_id: {'first_access': datetime, 'is_blocked': bool, 'target_ips': set}}
last_reset_date = None  # Track the last date we performed a daily reset

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
    # Create table with group_ids (comma-separated) and is_triggered flag
    create_table = """
        CREATE TABLE IF NOT EXISTS triggers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            group_ids TEXT NOT NULL,
            time_limit_seconds INTEGER NOT NULL,
            trigger_domains TEXT NOT NULL,
            block_regex TEXT NOT NULL,
            enabled INTEGER DEFAULT 1,
            is_triggered INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """
    success, output = run_sqlite(create_table, db_path=TRIGGER_DB)
    if not success:
        print(f"[DB] Failed to initialize trigger database: {output}")
        return False

    # Check current schema for migrations
    check_col = "SELECT sql FROM sqlite_master WHERE type='table' AND name='triggers'"
    success, schema = run_sqlite(check_col, db_path=TRIGGER_DB)

    if success and schema:
        # Migration: rename group_id to group_ids if old schema exists
        if 'group_id INTEGER' in schema:
            print("[DB] Migrating database: group_id -> group_ids...")
            # SQLite doesn't support RENAME COLUMN in older versions, so we recreate
            migrate_queries = [
                "ALTER TABLE triggers RENAME TO triggers_old",
                """CREATE TABLE triggers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    group_ids TEXT NOT NULL,
                    time_limit_seconds INTEGER NOT NULL,
                    trigger_domains TEXT NOT NULL,
                    block_regex TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    is_triggered INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )""",
                """INSERT INTO triggers (id, name, group_ids, time_limit_seconds, trigger_domains, block_regex, enabled, is_triggered, created_at)
                   SELECT id, name, CAST(group_id AS TEXT), time_limit_seconds, trigger_domains, block_regex, enabled, 0, created_at
                   FROM triggers_old""",
                "DROP TABLE triggers_old"
            ]
            for query in migrate_queries:
                success, output = run_sqlite(query, db_path=TRIGGER_DB)
                if not success:
                    print(f"[DB] Migration failed: {output}")
                    return False
            print("[DB] Migration complete")

        # Migration: add is_triggered column if it doesn't exist
        elif 'is_triggered' not in schema:
            print("[DB] Adding is_triggered column...")
            add_col = "ALTER TABLE triggers ADD COLUMN is_triggered INTEGER DEFAULT 0"
            success, output = run_sqlite(add_col, db_path=TRIGGER_DB)
            if not success:
                print(f"[DB] Failed to add is_triggered column: {output}")
                return False
            print("[DB] Column added")

    return True

def get_setting(key, default=None):
    """Get a setting value from the database."""
    query = f"SELECT value FROM settings WHERE key = '{key}'"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)
    if success and output:
        return output.strip()
    return default


def get_reset_hour():
    """Get the configured daily reset hour from the database."""
    value = get_setting('daily_reset_hour', str(DEFAULT_RESET_HOUR))
    try:
        hour = int(value)
        if 0 <= hour <= 23:
            return hour
    except ValueError:
        pass
    return DEFAULT_RESET_HOUR


def load_triggers():
    """Load all enabled triggers from the database."""
    query = "SELECT id, name, group_ids, time_limit_seconds, trigger_domains, block_regex FROM triggers WHERE enabled = 1"
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
                'group_ids': [int(g.strip()) for g in parts[2].split(',')],
                'time_limit_seconds': int(parts[3]),
                'trigger_domains': [d.strip() for d in parts[4].split(',')],
                'block_regex': parts[5],
            })
    return triggers

def list_triggers():
    """List all triggers in the database."""
    query = "SELECT id, name, group_ids, time_limit_seconds, trigger_domains, enabled, is_triggered FROM triggers ORDER BY id"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if not success:
        print(f"Error: Failed to query triggers: {output}")
        return

    if not output:
        print("No triggers configured.")
        print("\nUse --add to create a new trigger.")
        return

    print("\nConfigured Triggers:")
    print("=" * 100)
    print(f"{'ID':<4} {'Name':<20} {'Groups':<10} {'Time':<8} {'Domains':<25} {'Status':<10} {'Triggered':<10}")
    print("-" * 100)

    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 7:
            trigger_id = parts[0]
            name = parts[1][:18] + '..' if len(parts[1]) > 20 else parts[1]
            group_ids = parts[2][:8] + '..' if len(parts[2]) > 10 else parts[2]
            time_limit = f"{parts[3]}s"
            domains = parts[4][:23] + '..' if len(parts[4]) > 25 else parts[4]
            status = "Enabled" if parts[5] == '1' else "Disabled"
            triggered = "BLOCKED" if parts[6] == '1' else "-"
            print(f"{trigger_id:<4} {name:<20} {group_ids:<10} {time_limit:<8} {domains:<25} {status:<10} {triggered:<10}")

    print("=" * 100)

def add_trigger_cli(name, group_ids, time_limit, trigger_domains, block_regex):
    """Add a new trigger via command-line arguments."""
    # Validate inputs
    if not name:
        print("Error: Name is required")
        return False

    # Validate group IDs (comma-separated)
    try:
        group_id_list = [int(g.strip()) for g in group_ids.split(',')]
        if not group_id_list:
            raise ValueError("Empty list")
    except ValueError:
        print("Error: Group IDs must be comma-separated numbers (e.g., '2' or '2,3,4')")
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

    # Normalize group_ids (remove spaces, ensure consistent format)
    group_ids_normalized = ','.join(str(g) for g in group_id_list)

    # Escape single quotes for SQL
    name_escaped = name.replace("'", "''")
    trigger_domains_escaped = trigger_domains.replace("'", "''")
    block_regex_escaped = block_regex.replace("'", "''")

    query = f"""
        INSERT INTO triggers (name, group_ids, time_limit_seconds, trigger_domains, block_regex)
        VALUES ('{name_escaped}', '{group_ids_normalized}', {time_limit}, '{trigger_domains_escaped}', '{block_regex_escaped}')
    """

    success, output = run_sqlite(query, db_path=TRIGGER_DB)
    if success:
        print(f"Trigger '{name}' added successfully!")
        print(f"  Groups: {group_ids_normalized}")
        restart_daemon_service()
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
        group_ids = input("Pi-hole Group ID(s) to monitor (comma-separated, e.g., '2' or '2,3,4'): ").strip()
        time_limit = input("Time limit in seconds (e.g., 3600 for 1 hour): ").strip()
        trigger_domains = input("Trigger domains (comma-separated, e.g., 'youtube,googlevideo.com'): ").strip()
        block_regex = input("Block regex pattern: ").strip()

        return add_trigger_cli(name, group_ids, time_limit, trigger_domains, block_regex)

    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.")
        return False

def remove_trigger(trigger_id):
    """Remove a trigger by ID."""
    # First check if it exists and get its details for cleanup
    check_query = f"SELECT id, name, group_ids, time_limit_seconds, trigger_domains, block_regex FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(check_query, db_path=TRIGGER_DB)

    if not success or not output:
        print(f"Error: Trigger with ID {trigger_id} not found")
        return False

    parts = output.split('␞')
    name = parts[1] if len(parts) > 1 else "Unknown"

    # Build trigger dict to check for existing block
    if len(parts) >= 6:
        trigger = {
            'id': int(parts[0]),
            'name': parts[1],
            'group_ids': [int(g.strip()) for g in parts[2].split(',')],
            'time_limit_seconds': int(parts[3]),
            'trigger_domains': [d.strip() for d in parts[4].split(',')],
            'block_regex': parts[5],
        }
        # Remove any active block for this trigger
        block_id = get_existing_block(trigger)
        if block_id:
            print(f"Removing active block rule (ID: {block_id})...")
            remove_block(trigger)
            reload_pihole()

    query = f"DELETE FROM triggers WHERE id = {trigger_id}"
    success, _ = run_sqlite(query, db_path=TRIGGER_DB)

    if success:
        print(f"Trigger '{name}' (ID: {trigger_id}) removed successfully!")
        restart_daemon_service()
        return True
    else:
        print(f"Error: Failed to remove trigger")
        return False

def edit_trigger(trigger_id, name=None, group_ids=None, time_limit=None,
                 trigger_domains=None, block_regex=None, enabled=None):
    """Edit a trigger's fields. Only specified fields are updated."""
    # First get current trigger data
    query = f"SELECT id, name, group_ids, time_limit_seconds, trigger_domains, block_regex, enabled, is_triggered FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if not success or not output:
        print(f"Error: Trigger with ID {trigger_id} not found")
        return False

    parts = output.split('␞')
    if len(parts) < 8:
        print(f"Error: Invalid trigger data")
        return False

    current = {
        'id': int(parts[0]),
        'name': parts[1],
        'group_ids': parts[2],
        'time_limit_seconds': int(parts[3]),
        'trigger_domains': parts[4],
        'block_regex': parts[5],
        'enabled': parts[6] == '1',
        'is_triggered': parts[7] == '1',
    }

    # Check if trigger has an active block that needs to be removed
    if current['is_triggered']:
        trigger_for_block = {
            'id': current['id'],
            'name': current['name'],
            'group_ids': [int(g.strip()) for g in current['group_ids'].split(',')],
            'block_regex': current['block_regex'],
        }
        print(f"Removing active block before editing...")
        block_id = get_existing_block(trigger_for_block)
        if block_id:
            remove_block(trigger_for_block)
            reload_pihole()

    # Build update query with only changed fields
    updates = []
    if name is not None:
        updates.append(f"name = '{name.replace(chr(39), chr(39)+chr(39))}'")
    if group_ids is not None:
        # Validate and normalize group IDs
        try:
            group_id_list = [int(g.strip()) for g in group_ids.split(',')]
            normalized = ','.join(str(g) for g in group_id_list)
            updates.append(f"group_ids = '{normalized}'")
        except ValueError:
            print("Error: Group IDs must be comma-separated numbers")
            return False
    if time_limit is not None:
        try:
            time_val = int(time_limit)
            updates.append(f"time_limit_seconds = {time_val}")
        except ValueError:
            print("Error: Time limit must be a number")
            return False
    if trigger_domains is not None:
        updates.append(f"trigger_domains = '{trigger_domains.replace(chr(39), chr(39)+chr(39))}'")
    if block_regex is not None:
        updates.append(f"block_regex = '{block_regex.replace(chr(39), chr(39)+chr(39))}'")
    if enabled is not None:
        updates.append(f"enabled = {1 if enabled else 0}")
        # Clear is_triggered if disabling
        if not enabled:
            updates.append("is_triggered = 0")

    if not updates:
        print("No changes specified")
        return False

    update_query = f"UPDATE triggers SET {', '.join(updates)} WHERE id = {trigger_id}"
    success, _ = run_sqlite(update_query, db_path=TRIGGER_DB)

    if success:
        print(f"Trigger '{current['name']}' (ID: {trigger_id}) updated!")
        if name:
            print(f"  Name: {name}")
        if group_ids:
            print(f"  Groups: {group_ids}")
        if time_limit:
            print(f"  Time limit: {time_limit}s")
        if trigger_domains:
            print(f"  Domains: {trigger_domains}")
        if block_regex:
            print(f"  Regex: {block_regex}")
        if enabled is not None:
            print(f"  Enabled: {enabled}")
        restart_daemon_service()
        return True
    else:
        print(f"Error: Failed to update trigger")
        return False

def set_trigger_active(trigger_id, is_triggered):
    """Set the is_triggered flag for a trigger."""
    query = f"UPDATE triggers SET is_triggered = {1 if is_triggered else 0} WHERE id = {trigger_id}"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)
    return success

def reset_trigger(trigger_id, restart_daemon=True):
    """Reset a trigger: remove active block and clear timer state."""
    # First get the trigger details
    query = f"SELECT id, name, group_ids, time_limit_seconds, trigger_domains, block_regex, is_triggered FROM triggers WHERE id = {trigger_id}"
    success, output = run_sqlite(query, db_path=TRIGGER_DB)

    if not success or not output:
        print(f"Error: Trigger with ID {trigger_id} not found")
        return False

    parts = output.split('␞')
    if len(parts) < 7:
        print(f"Error: Invalid trigger data")
        return False

    trigger = {
        'id': int(parts[0]),
        'name': parts[1],
        'group_ids': [int(g.strip()) for g in parts[2].split(',')],
        'time_limit_seconds': int(parts[3]),
        'trigger_domains': [d.strip() for d in parts[4].split(',')],
        'block_regex': parts[5],
    }
    is_triggered = parts[6] == '1'

    print(f"Resetting trigger '{trigger['name']}' (ID: {trigger_id})...")

    # Check if there's an active block rule in Pi-hole
    block_removed = False
    domain_id = get_existing_block(trigger)
    if domain_id:
        print(f"  Removing block rule (ID: {domain_id})...")
        remove_block(trigger)
        block_removed = True
    elif is_triggered:
        print(f"  No block rule found in Pi-hole, clearing triggered flag...")
        set_trigger_active(trigger_id, False)
    else:
        print(f"  No active block found")

    if block_removed:
        reload_pihole()

    print(f"Trigger '{trigger['name']}' has been reset.")

    # Restart the daemon to clear in-memory state
    if restart_daemon:
        restart_daemon_service()

    return True

def restart_daemon_service():
    """Restart the pihole-trigger daemon to reload state."""
    print("Restarting daemon to reload state...")
    result = subprocess.run(
        ["systemctl", "restart", "pihole-trigger"],
        capture_output=True,
        text=True
    )
    if result.returncode == 0:
        print("Daemon restarted successfully")
    else:
        print(f"Note: Could not restart daemon: {result.stderr.strip()}")
        print("You may need to restart it manually: sudo systemctl restart pihole-trigger")

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
    """Add blocking regex to the database for a trigger's groups."""
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

    # Remove from default group (0) and add to all target groups
    delete_default = f"DELETE FROM domainlist_by_group WHERE domainlist_id = {domain_id} AND group_id = 0"
    run_sqlite(delete_default)

    # Add to each group
    for group_id in trigger['group_ids']:
        add_to_group = f"INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES ({domain_id}, {group_id})"
        success, output = run_sqlite(add_to_group)
        if not success:
            print(f"[{trigger['name']}] Warning: Failed to assign to group {group_id}: {output}")

    group_list = ','.join(str(g) for g in trigger['group_ids'])
    print(f"[{trigger['name']}] Assigned rule to group(s) {group_list}")

    # Mark trigger as active in database
    set_trigger_active(trigger['id'], True)

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
        # No block exists, but ensure is_triggered is false
        set_trigger_active(trigger['id'], False)
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

    # Mark trigger as inactive in database
    set_trigger_active(trigger['id'], False)

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
        # Clear all is_triggered flags just in case
        clear_query = "UPDATE triggers SET is_triggered = 0 WHERE is_triggered = 1"
        run_sqlite(clear_query, db_path=TRIGGER_DB)
        return True

    removed = 0
    trigger_ids_cleared = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 2:
            domain_id = parts[0]
            comment = parts[1]

            # Extract trigger ID from comment (format: "Time trigger [ID] - Name")
            match = re.search(r'Time trigger \[(\d+)\]', comment)
            if match:
                trigger_ids_cleared.append(int(match.group(1)))

            delete_query = f"DELETE FROM domainlist WHERE id = {domain_id}"
            success, _ = run_sqlite(delete_query)
            if success:
                print(f"Removed: {comment}")
                removed += 1

    # Clear is_triggered flags for all removed triggers
    for trigger_id in trigger_ids_cleared:
        set_trigger_active(trigger_id, False)

    if removed > 0:
        reload_pihole()
        print(f"\nRemoved {removed} block(s).")
        # Restart daemon to clear in-memory state
        restart_daemon_service()

    return True

def perform_daily_reset():
    """
    Perform the daily reset: remove all blocks and reset all trigger timers.
    Called automatically at DAILY_RESET_HOUR (default 3AM).
    This runs within the daemon, so it resets in-memory state directly.
    """
    global trigger_states

    print("=" * 70)
    print(f"[Daily Reset] Performing automatic daily reset at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    blocks_removed = 0

    # Remove all blocks and reset in-memory state for each trigger
    for trigger in triggers:
        state = trigger_states.get(trigger['id'])
        if not state:
            continue

        # Check if this trigger has an active block
        if state['is_blocked']:
            domain_id = get_existing_block(trigger)
            if domain_id:
                print(f"[Daily Reset] Removing block for '{trigger['name']}'")
                query = f"DELETE FROM domainlist WHERE id = {domain_id}"
                run_sqlite(query)
                blocks_removed += 1

            # Clear is_triggered in database
            set_trigger_active(trigger['id'], False)

        # Reset in-memory state
        state['first_access'] = None
        state['is_blocked'] = False
        print(f"[Daily Reset] Timer reset for '{trigger['name']}'")

    # Also clear any orphaned is_triggered flags in database
    clear_query = "UPDATE triggers SET is_triggered = 0 WHERE is_triggered = 1"
    run_sqlite(clear_query, db_path=TRIGGER_DB)

    if blocks_removed > 0:
        reload_pihole()

    print(f"[Daily Reset] Complete. Removed {blocks_removed} block(s), reset {len(triggers)} trigger(s).")
    print("=" * 70)

def check_daily_reset():
    """
    Check if it's time for the daily reset and perform it if needed.
    Returns True if a reset was performed.
    """
    global last_reset_date

    now = datetime.now()
    today = now.date()
    reset_hour = get_reset_hour()

    # Check if we're in the reset hour and haven't reset today yet
    if now.hour == reset_hour and last_reset_date != today:
        perform_daily_reset()
        last_reset_date = today
        return True

    return False

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
    last_heartbeat_hour = None  # Track last hour we sent a heartbeat

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

                        # Yield empty line at the top of each hour to trigger reset checks
                        # even when there's no DNS activity
                        current_hour = datetime.now().hour
                        if last_heartbeat_hour != current_hour:
                            last_heartbeat_hour = current_hour
                            yield ""

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
                group_list = ','.join(str(g) for g in trigger['group_ids'])
                print(f"[{trigger['name']}] Domains are now BLOCKED for group(s) {group_list}")
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
                group_list = ','.join(str(g) for g in trigger['group_ids'])
                print(f"[{trigger['name']}] Domains are now BLOCKED for group(s) {group_list}")

def signal_handler(_signum, _frame):
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
        print("Daemon will wait for triggers to be added. Use --add to create one.")

    # Initialize state for each trigger
    for trigger in triggers:
        # Gather clients from all groups
        target_ips = set()
        for group_id in trigger['group_ids']:
            group_ips = get_group_clients(group_id)
            target_ips.update(group_ips)

        if not target_ips:
            group_list = ','.join(str(g) for g in trigger['group_ids'])
            print(f"Warning: No clients found in group(s) {group_list} for trigger '{trigger['name']}'")

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
        group_list = ','.join(str(g) for g in trigger['group_ids'])
        print(f"  [{trigger['id']}] {trigger['name']}")
        print(f"      Groups: {group_list} ({len(state['target_ips'])} clients)")
        print(f"      Time limit: {trigger['time_limit_seconds']} seconds")
        print(f"      Watching: {', '.join(trigger['trigger_domains'][:3])}{'...' if len(trigger['trigger_domains']) > 3 else ''}")
        print()

    reset_hour = get_reset_hour()
    print(f"Log file: {PIHOLE_LOG}")
    print(f"Daily reset: {reset_hour:02d}:00 local time")
    print("=" * 70)

    # Clear any previous blocks on startup
    print("\n[Setup] Clearing any previous blocks...")
    for trigger in triggers:
        remove_block(trigger)

    # Initialize daily reset tracking
    global last_reset_date
    last_reset_date = None  # Will be set on first reset

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

            # Periodically check timers and daily reset
            now = datetime.now()
            if (now - last_timer_check).total_seconds() >= 1:
                check_timers_expired()
                check_daily_reset()
                last_timer_check = now

    except Exception as e:
        print(f"[Error] {e}")
        raise
    finally:
        print("\n[Shutdown] Script ended")
        for trigger in triggers:
            state = trigger_states[trigger['id']]
            print(f"[{trigger['name']}] Blocked: {state['is_blocked']}")

def build_argument_parser():
    """Build the argument parser for CLI commands."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Pi-hole v6 Elapsed Time Trigger - Monitor DNS queries and block domains after time limits.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                          Run the daemon
  %(prog)s --list                                   List all triggers
  %(prog)s --add -n 'YouTube' -g 2,3 -t 3600 -d 'youtube,googlevideo.com' -r 'youtube|googlevideo\\.com'
  %(prog)s --edit 1 -t 7200                         Change time limit for trigger 1
  %(prog)s --edit 1 --disable                       Disable trigger 1
  %(prog)s --edit 1 --enable                        Enable trigger 1
  %(prog)s --remove 1                               Remove trigger 1
  %(prog)s --reset 1                                Reset trigger 1 (remove active block)
  %(prog)s --unblock                                Remove all active blocks
"""
    )

    # Mutually exclusive command group
    cmd_group = parser.add_mutually_exclusive_group()
    cmd_group.add_argument('--list', action='store_true', help='List all triggers')
    cmd_group.add_argument('--add', action='store_true', help='Add a new trigger')
    cmd_group.add_argument('--edit', type=int, metavar='ID', help='Edit trigger with specified ID')
    cmd_group.add_argument('--remove', type=int, metavar='ID', help='Remove trigger with specified ID')
    cmd_group.add_argument('--reset', type=int, metavar='ID', help='Reset trigger (remove active block)')
    cmd_group.add_argument('--unblock', action='store_true', help='Remove all active blocks')

    # Trigger field options (used with --add or --edit)
    field_group = parser.add_argument_group('trigger fields', 'Options for --add and --edit commands')
    field_group.add_argument('-n', '--name', type=str, help='Trigger name')
    field_group.add_argument('-g', '--groups', type=str, help='Pi-hole group IDs (comma-separated, e.g., "2,3")')
    field_group.add_argument('-t', '--time', type=int, help='Time limit in seconds')
    field_group.add_argument('-d', '--domains', type=str, help='Trigger domains (comma-separated)')
    field_group.add_argument('-r', '--regex', type=str, help='Block regex pattern')

    # Enable/disable (used with --edit)
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument('--enable', action='store_true', help='Enable the trigger')
    enable_group.add_argument('--disable', action='store_true', help='Disable the trigger')

    return parser

if __name__ == "__main__":
    parser = build_argument_parser()
    args = parser.parse_args()

    # Check if any command was specified
    is_command = args.list or args.add or args.edit or args.remove or args.reset or args.unblock

    if is_command:
        # Commands need root
        if os.geteuid() != 0:
            print("Error: Must run as root (sudo)")
            sys.exit(1)

        # Initialize DB for all commands
        if not init_trigger_db():
            sys.exit(1)

        if args.list:
            list_triggers()
            sys.exit(0)

        elif args.add:
            # Check if we have all required fields
            if args.name and args.groups and args.time and args.domains and args.regex:
                if add_trigger_cli(args.name, args.groups, str(args.time), args.domains, args.regex):
                    sys.exit(0)
                sys.exit(1)
            else:
                # Interactive mode
                if add_trigger():
                    sys.exit(0)
                sys.exit(1)

        elif args.edit is not None:
            # Determine enabled state
            enabled = None
            if args.enable:
                enabled = True
            elif args.disable:
                enabled = False

            if edit_trigger(
                args.edit,
                name=args.name,
                group_ids=args.groups,
                time_limit=args.time,
                trigger_domains=args.domains,
                block_regex=args.regex,
                enabled=enabled
            ):
                sys.exit(0)
            sys.exit(1)

        elif args.remove is not None:
            if remove_trigger(args.remove):
                sys.exit(0)
            sys.exit(1)

        elif args.reset is not None:
            if reset_trigger(args.reset):
                sys.exit(0)
            sys.exit(1)

        elif args.unblock:
            print("Removing all blocks...")
            remove_all_blocks()
            sys.exit(0)

    else:
        # No command specified - run the daemon
        main()
