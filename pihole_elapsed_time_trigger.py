#!/usr/bin/env python3
"""
Pi-hole v6 Elapsed Time Trigger (Direct Database Version)

Monitors Pi-hole DNS queries and blocks specified domains for a device group
after a configurable time period from first access.

Usage:
    sudo python3 pihole_elapsed_time_trigger.py
    sudo python3 pihole_elapsed_time_trigger.py --unblock

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

# Config file location (same directory as this script)
CONFIG_FILE = Path(__file__).parent / "trigger.conf"

def load_config():
    """
    Load configuration from trigger.conf file.
    Returns a dict with configuration values.
    """
    config = {}

    if not CONFIG_FILE.exists():
        print(f"Error: Config file not found: {CONFIG_FILE}")
        print("Make sure trigger.conf is deployed alongside this script.")
        sys.exit(1)

    with open(CONFIG_FILE, 'r') as f:
        for line in f:
            line = line.strip()
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            # Parse key=value
            if '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()

    # Validate required config values
    required = ['GROUP_ID', 'TIME_LIMIT_SECONDS', 'BLOCK_COMMENT',
                'DOMAINLIST_TYPE_REGEX_DENY', 'TRIGGER_DOMAINS', 'BLOCK_REGEX']
    for key in required:
        if key not in config:
            print(f"Error: Missing required config value: {key}")
            sys.exit(1)

    return config

# Load configuration
_config = load_config()

# Configuration values from config file
GROUP_ID = int(_config['GROUP_ID'])
TIME_LIMIT_SECONDS = int(_config['TIME_LIMIT_SECONDS'])
BLOCK_COMMENT = _config['BLOCK_COMMENT']
DOMAINLIST_TYPE_REGEX_DENY = int(_config['DOMAINLIST_TYPE_REGEX_DENY'])
TRIGGER_DOMAINS = [d.strip() for d in _config['TRIGGER_DOMAINS'].split(',')]
BLOCK_REGEX = _config['BLOCK_REGEX']

# =============================================================================
# GLOBAL STATE
# =============================================================================

first_access_time = None
is_blocked = False
running = True
target_ips = set()  # IPs in the monitored group

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
            ["pihole-FTL", "sqlite3", "-separator", "|", db_path, query],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            # Include stderr in error output for debugging
            error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
            return (False, error_msg)
        return (True, result.stdout.strip())
    except Exception as e:
        print(f"[DB] Error running query: {e}")
        return (False, str(e))

def get_existing_block():
    """
    Check if our block rule already exists.
    Returns the domain ID if found, None otherwise.
    """
    query = f"SELECT id FROM domainlist WHERE comment = '{BLOCK_COMMENT}' AND type = {DOMAINLIST_TYPE_REGEX_DENY}"
    success, output = run_sqlite(query)
    
    if success and output:
        return int(output.split('\n')[0])
    return None

def add_block():
    """
    Add blocking regex to the database for the target group.
    Returns True on success.
    """
    print("[Block] Adding block rule...")

    # Check if it already exists
    existing_id = get_existing_block()
    if existing_id:
        print(f"[Block] Rule already exists (ID: {existing_id}), enabling it...")
        return enable_block(existing_id)

    # Insert the new regex deny rule
    # Note: The trigger will auto-add it to group 0 (default)
    insert_query = f"""
        INSERT INTO domainlist (type, domain, enabled, comment)
        VALUES ({DOMAINLIST_TYPE_REGEX_DENY}, '{BLOCK_REGEX}', 1, '{BLOCK_COMMENT}')
    """

    success, output = run_sqlite(insert_query)

    # Verify the insert by checking if the rule now exists
    # (return code can be unreliable in some environments)
    domain_id = get_existing_block()
    if not domain_id:
        # INSERT truly failed
        print(f"[Block] Failed to insert rule: {output}")
        return False

    if not success:
        # INSERT reported failure but row exists - log for debugging
        print(f"[Block] Note: INSERT reported error but succeeded (ID: {domain_id})")
    else:
        print(f"[Block] Inserted rule (ID: {domain_id})")

    # Remove from default group (0) and add to our target group
    # The trigger auto-added it to group 0, so we need to fix that
    delete_default = f"DELETE FROM domainlist_by_group WHERE domainlist_id = {domain_id} AND group_id = 0"
    success, _ = run_sqlite(delete_default)

    add_to_group = f"INSERT OR IGNORE INTO domainlist_by_group (domainlist_id, group_id) VALUES ({domain_id}, {GROUP_ID})"
    success, output = run_sqlite(add_to_group)

    if not success:
        print(f"[Block] Failed to assign to group: {output}")
        return False

    print(f"[Block] Assigned rule to group {GROUP_ID}")

    # Reload Pi-hole
    reload_pihole()

    return True

def enable_block(domain_id):
    """Enable an existing block rule."""
    query = f"UPDATE domainlist SET enabled = 1 WHERE id = {domain_id}"
    success, output = run_sqlite(query)
    
    if success:
        print(f"[Block] Enabled rule (ID: {domain_id})")
        reload_pihole()
        return True
    else:
        print(f"[Block] Failed to enable rule: {output}")
        return False

def remove_block():
    """
    Remove/disable the blocking rule.
    Returns True if a rule was found and removed.
    """
    domain_id = get_existing_block()

    if not domain_id:
        print("[Unblock] No block rule found")
        return False

    print(f"[Unblock] Removing rule (ID: {domain_id})...")

    # Delete the rule (cascade will remove group links)
    query = f"DELETE FROM domainlist WHERE id = {domain_id}"
    success, output = run_sqlite(query)

    # Verify the delete by checking if the rule is gone
    # (return code can be unreliable in some environments)
    still_exists = get_existing_block()
    if still_exists:
        # DELETE truly failed
        print(f"[Unblock] Failed to remove rule: {output}")
        return False

    if not success:
        # DELETE reported failure but row is gone - log for debugging
        print(f"[Unblock] Note: DELETE reported error but succeeded")

    print("[Unblock] Rule removed")
    reload_pihole()
    return True

def reload_pihole():
    """Restart Pi-hole FTL to apply changes including client-group mappings."""
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

def ensure_ip_clients_in_group(ip_addresses, group_id):
    """
    Ensure IP addresses are added to the client table and assigned to the target group.
    Pi-hole v6 requires IP-based client entries for group rules to apply.
    """
    for ip in ip_addresses:
        # Check if client already exists
        check_query = f"SELECT id FROM client WHERE ip = '{ip}'"
        success, output = run_sqlite(check_query)

        if success and output:
            client_id = int(output.strip())
            print(f"[DB] Client {ip} already exists (ID: {client_id})")
        else:
            # Insert new client
            insert_query = f"INSERT INTO client (ip, comment) VALUES ('{ip}', 'Auto-added for time trigger')"
            success, _ = run_sqlite(insert_query)
            if not success:
                print(f"[DB] Warning: Failed to add client {ip}")
                continue

            # Get the new client ID
            success, output = run_sqlite(check_query)
            if not success or not output:
                print(f"[DB] Warning: Failed to get ID for client {ip}")
                continue
            client_id = int(output.strip())
            print(f"[DB] Added client {ip} (ID: {client_id})")

        # Remove from default group and add to target group
        del_query = f"DELETE FROM client_by_group WHERE client_id = {client_id} AND group_id = 0"
        run_sqlite(del_query)

        add_query = f"INSERT OR IGNORE INTO client_by_group (client_id, group_id) VALUES ({client_id}, {group_id})"
        success, _ = run_sqlite(add_query)
        if success:
            print(f"[DB] Assigned client {ip} to group {group_id}")

def get_group_clients(group_id):
    """
    Get all client IPs that belong to a specific group.
    Returns a set of IP addresses.

    Pi-hole clients can be identified by MAC or IP. This function handles both:
    - If the client entry is a MAC address, look up the IP from pihole-FTL.db
    - If the client entry is already an IP, use it directly
    """
    # Get client identifiers (could be MAC or IP)
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
        # Check if it looks like a MAC address (contains colons)
        if ':' in client_id:
            # Look up IP from pihole-FTL.db using network + network_addresses tables
            # Note: gravity.db stores MACs uppercase, pihole-FTL.db stores lowercase
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
            # Already an IP address
            ip_addresses.add(client_id)

    return ip_addresses

# =============================================================================
# LOG MONITORING
# =============================================================================

def is_trigger_domain(domain):
    """Check if a domain matches any trigger domain."""
    domain_lower = domain.lower()
    return any(yt_domain in domain_lower for yt_domain in TRIGGER_DOMAINS)

def parse_pihole_log_line(line):
    """
    Parse a Pi-hole log line and extract query information.
    Returns (timestamp, client_ip, domain) or None if not a query line.
    
    Example log line:
    Jan 25 10:30:45 dnsmasq[1234]: query[A] youtube.com from 192.168.1.34
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
    """
    Generator that yields new lines from a log file (like 'tail -f').
    Handles log rotation.
    """
    while running:
        try:
            with open(filepath, 'r') as f:
                # Seek to end of file
                f.seek(0, 2)
                
                while running:
                    line = f.readline()
                    if line:
                        yield line.strip()
                    else:
                        time.sleep(0.1)
                        
                        # Check if file was rotated
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

def handle_trigger_access(client_ip):
    """Handle detection of trigger domain access from a target IP."""
    global first_access_time, is_blocked

    if is_blocked:
        return

    now = datetime.now()

    if first_access_time is None:
        first_access_time = now
        block_time = now + timedelta(seconds=TIME_LIMIT_SECONDS)
        print(f"[Monitor] First trigger domain access detected from {client_ip} at {now.strftime('%H:%M:%S')}")
        print(f"[Monitor] Domains will be blocked at {block_time.strftime('%H:%M:%S')}")
    else:
        elapsed = (now - first_access_time).total_seconds()
        remaining = TIME_LIMIT_SECONDS - elapsed

        if remaining > 0:
            print(f"[Monitor] Trigger domain access from {client_ip} - {remaining:.0f}s remaining before block")
        else:
            print(f"[Monitor] Time limit exceeded! Blocking domains...")
            if add_block():
                is_blocked = True
                print(f"[Monitor] Domains are now BLOCKED for group {GROUP_ID}")
            else:
                print("[Monitor] Failed to add block - will retry on next access")

def check_timer_expired():
    """Check if the timer has expired even without new queries."""
    global is_blocked
    
    if is_blocked or first_access_time is None:
        return
    
    elapsed = (datetime.now() - first_access_time).total_seconds()
    if elapsed >= TIME_LIMIT_SECONDS:
        print(f"[Monitor] Time limit expired! Blocking domains...")
        if add_block():
            is_blocked = True
            print(f"[Monitor] Domains are now BLOCKED for group {GROUP_ID}")

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global running
    print("\n[Shutdown] Received signal, shutting down...")
    running = False

def main():
    global running, target_ips

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

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Load target IPs from the group
    target_ips = get_group_clients(GROUP_ID)
    if not target_ips:
        print(f"Error: No clients found in group {GROUP_ID}")
        print("Make sure you have clients assigned to this group in Pi-hole.")
        sys.exit(1)

    print("=" * 60)
    print("Pi-hole v6 Elapsed Time Trigger")
    print("=" * 60)
    print(f"Group ID:     {GROUP_ID}")
    print(f"Monitoring:   {len(target_ips)} client(s)")
    for ip in sorted(target_ips):
        print(f"              - {ip}")
    print(f"Time limit:   {TIME_LIMIT_SECONDS} seconds")
    print(f"Log file:     {PIHOLE_LOG}")
    print(f"Database:     {GRAVITY_DB}")
    print("=" * 60)

    # Clear any previous blocks on startup
    print("\n[Setup] Clearing any previous blocks...")
    remove_block()

    print("\n[Monitor] Starting log monitoring...")
    print(f"[Monitor] Waiting for trigger domain access from group {GROUP_ID} clients")
    print("-" * 60)
    
    last_timer_check = datetime.now()
    
    try:
        for line in tail_log(PIHOLE_LOG):
            if not running:
                break
                
            parsed = parse_pihole_log_line(line)
            if parsed:
                timestamp_str, client_ip, domain = parsed
                
                # Check if this is one of our target IPs accessing a trigger domain
                if client_ip in target_ips and is_trigger_domain(domain):
                    handle_trigger_access(client_ip)
            
            # Periodically check if timer expired
            now = datetime.now()
            if (now - last_timer_check).total_seconds() >= 1:
                check_timer_expired()
                last_timer_check = now
                
    except Exception as e:
        print(f"[Error] {e}")
        raise
    finally:
        print("\n[Shutdown] Script ended")
        print(f"[Status] Domains blocked: {is_blocked}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--unblock":
            if os.geteuid() != 0:
                print("Error: Must run as root (sudo)")
                sys.exit(1)
            print("Removing blocks...")
            if remove_block():
                print("Done!")
            else:
                print("No blocks found to remove")
            sys.exit(0)
        elif sys.argv[1] == "--help":
            print("Usage:")
            print("  sudo python3 pihole_elapsed_time_trigger.py           Run the trigger")
            print("  sudo python3 pihole_elapsed_time_trigger.py --unblock Remove blocks")
            sys.exit(0)
    
    main()
