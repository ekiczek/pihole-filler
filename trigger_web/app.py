#!/usr/bin/env python3
"""
Pi-hole Elapsed Time Trigger - Web Interface

A lightweight Flask web application for managing Pi-hole time triggers.
Runs as a separate service from the main daemon on port 8080.
"""

import os
import re
import subprocess
import secrets
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify
)

# =============================================================================
# CONFIGURATION
# =============================================================================

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Session configuration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Database paths
TRIGGER_DB = Path(__file__).parent.parent / "trigger.db"
GRAVITY_DB = Path("/etc/pihole/gravity.db")

# Daily reset hour (must match the daemon)
DAILY_RESET_HOUR = 3

# =============================================================================
# DATABASE FUNCTIONS
# =============================================================================

def run_sqlite(query, db_path=None):
    """
    Run a SQLite query using pihole-FTL's embedded sqlite3.
    Returns (success, output) tuple.
    """
    if db_path is None:
        db_path = TRIGGER_DB
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
        return (False, str(e))


def init_trigger_db():
    """Initialize the trigger configuration database if it doesn't exist."""
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
    success, output = run_sqlite(create_table)
    return success


def get_all_triggers():
    """Get all triggers from the database."""
    query = """
        SELECT id, name, group_ids, time_limit_seconds, trigger_domains,
               block_regex, enabled, is_triggered, created_at
        FROM triggers ORDER BY id
    """
    success, output = run_sqlite(query)

    if not success or not output:
        return []

    triggers = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 9:
            triggers.append({
                'id': int(parts[0]),
                'name': parts[1],
                'group_ids': parts[2],
                'time_limit_seconds': int(parts[3]),
                'trigger_domains': parts[4],
                'block_regex': parts[5],
                'enabled': parts[6] == '1',
                'is_triggered': parts[7] == '1',
                'created_at': parts[8],
            })
    return triggers


def get_trigger(trigger_id):
    """Get a single trigger by ID."""
    query = f"""
        SELECT id, name, group_ids, time_limit_seconds, trigger_domains,
               block_regex, enabled, is_triggered, created_at
        FROM triggers WHERE id = {trigger_id}
    """
    success, output = run_sqlite(query)

    if not success or not output:
        return None

    parts = output.split('␞')
    if len(parts) >= 9:
        return {
            'id': int(parts[0]),
            'name': parts[1],
            'group_ids': parts[2],
            'time_limit_seconds': int(parts[3]),
            'trigger_domains': parts[4],
            'block_regex': parts[5],
            'enabled': parts[6] == '1',
            'is_triggered': parts[7] == '1',
            'created_at': parts[8],
        }
    return None


def add_trigger(name, group_ids, time_limit, trigger_domains, block_regex):
    """Add a new trigger to the database."""
    # Escape single quotes
    name_esc = name.replace("'", "''")
    domains_esc = trigger_domains.replace("'", "''")
    regex_esc = block_regex.replace("'", "''")

    query = f"""
        INSERT INTO triggers (name, group_ids, time_limit_seconds, trigger_domains, block_regex)
        VALUES ('{name_esc}', '{group_ids}', {time_limit}, '{domains_esc}', '{regex_esc}')
    """
    success, output = run_sqlite(query)
    return success, output


def update_trigger(trigger_id, name=None, group_ids=None, time_limit=None,
                   trigger_domains=None, block_regex=None, enabled=None):
    """Update a trigger's fields."""
    updates = []

    if name is not None:
        updates.append(f"name = '{name.replace(chr(39), chr(39)+chr(39))}'")
    if group_ids is not None:
        updates.append(f"group_ids = '{group_ids}'")
    if time_limit is not None:
        updates.append(f"time_limit_seconds = {time_limit}")
    if trigger_domains is not None:
        updates.append(f"trigger_domains = '{trigger_domains.replace(chr(39), chr(39)+chr(39))}'")
    if block_regex is not None:
        updates.append(f"block_regex = '{block_regex.replace(chr(39), chr(39)+chr(39))}'")
    if enabled is not None:
        updates.append(f"enabled = {1 if enabled else 0}")
        if not enabled:
            updates.append("is_triggered = 0")

    if not updates:
        return False, "No changes specified"

    query = f"UPDATE triggers SET {', '.join(updates)} WHERE id = {trigger_id}"
    return run_sqlite(query)


def delete_trigger(trigger_id):
    """Delete a trigger from the database."""
    query = f"DELETE FROM triggers WHERE id = {trigger_id}"
    return run_sqlite(query)


def set_trigger_active(trigger_id, is_triggered):
    """Set the is_triggered flag for a trigger."""
    query = f"UPDATE triggers SET is_triggered = {1 if is_triggered else 0} WHERE id = {trigger_id}"
    return run_sqlite(query)


def get_pihole_groups():
    """Get all Pi-hole groups for the dropdown."""
    query = "SELECT id, name, description FROM 'group' ORDER BY id"
    success, output = run_sqlite(query, db_path=GRAVITY_DB)

    if not success or not output:
        return []

    groups = []
    for line in output.split('\n'):
        if not line.strip():
            continue
        parts = line.split('␞')
        if len(parts) >= 2:
            groups.append({
                'id': int(parts[0]),
                'name': parts[1],
                'description': parts[2] if len(parts) > 2 else '',
            })
    return groups


# =============================================================================
# AUTHENTICATION
# =============================================================================

def verify_password(password):
    """
    Verify a password against Pi-hole's API (v6+).
    Uses the local Pi-hole API to authenticate.
    """
    import urllib.request
    import json
    import ssl

    try:
        # Pi-hole v6 API authentication endpoint (HTTPS on port 443)
        url = "https://localhost/api/auth"
        data = json.dumps({"password": password}).encode('utf-8')

        req = urllib.request.Request(
            url,
            data=data,
            headers={'Content-Type': 'application/json'},
            method='POST'
        )

        # Create SSL context that doesn't verify (localhost self-signed cert)
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
            result = json.loads(response.read().decode('utf-8'))
            # Pi-hole returns a session object with 'valid' field on success
            return result.get('session', {}).get('valid', False)

    except urllib.error.HTTPError as e:
        # 401 means invalid password
        if e.code == 401:
            return False
        # Other errors - log and deny
        print(f"[Auth] HTTP error: {e.code}")
        return False
    except Exception as e:
        print(f"[Auth] Error verifying password: {e}")
        return False


def login_required(f):
    """Decorator to require authentication for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


# =============================================================================
# DAEMON CONTROL
# =============================================================================

def restart_daemon():
    """Restart the pihole-trigger daemon to reload state."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", "pihole-trigger"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def reload_pihole():
    """Restart Pi-hole FTL to apply changes."""
    try:
        result = subprocess.run(
            ["systemctl", "restart", "pihole-FTL"],
            capture_output=True,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_existing_block(trigger_id, block_regex):
    """Check if the block rule for a trigger already exists in Pi-hole."""
    comment = f"Time trigger [{trigger_id}]"
    query = f"SELECT id FROM domainlist WHERE comment LIKE '{comment}%' AND type = 3"
    success, output = run_sqlite(query, db_path=GRAVITY_DB)

    if success and output:
        return int(output.split('\n')[0])
    return None


def remove_block_rule(trigger_id, block_regex):
    """Remove the blocking rule for a trigger from Pi-hole."""
    domain_id = get_existing_block(trigger_id, block_regex)

    if not domain_id:
        return False

    query = f"DELETE FROM domainlist WHERE id = {domain_id}"
    success, _ = run_sqlite(query, db_path=GRAVITY_DB)
    return success


def reset_trigger(trigger_id):
    """Reset a trigger: remove active block and clear timer state."""
    trigger = get_trigger(trigger_id)
    if not trigger:
        return False, "Trigger not found"

    # Remove block rule if it exists
    if trigger['is_triggered']:
        remove_block_rule(trigger_id, trigger['block_regex'])
        reload_pihole()

    # Clear is_triggered flag
    set_trigger_active(trigger_id, False)

    # Restart daemon to clear in-memory state
    restart_daemon()

    return True, "Trigger reset successfully"


def reset_all_triggers():
    """Reset all triggers."""
    triggers = get_all_triggers()
    removed = 0

    for trigger in triggers:
        if trigger['is_triggered']:
            remove_block_rule(trigger['id'], trigger['block_regex'])
            set_trigger_active(trigger['id'], False)
            removed += 1

    if removed > 0:
        reload_pihole()

    restart_daemon()

    return True, f"Reset {removed} trigger(s)"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def format_time(seconds):
    """Format seconds into a human-readable string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        mins = seconds // 60
        secs = seconds % 60
        return f"{mins}m {secs}s" if secs else f"{mins}m"
    else:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m" if mins else f"{hours}h"


def get_next_reset_time():
    """Calculate time until next daily reset."""
    now = datetime.now()
    reset_today = now.replace(hour=DAILY_RESET_HOUR, minute=0, second=0, microsecond=0)

    if now >= reset_today:
        reset_time = reset_today + timedelta(days=1)
    else:
        reset_time = reset_today

    delta = reset_time - now
    hours, remainder = divmod(int(delta.total_seconds()), 3600)
    minutes, _ = divmod(remainder, 60)

    return f"{hours}h {minutes}m"


def validate_trigger_form(form):
    """Validate trigger form data."""
    errors = []

    name = form.get('name', '').strip()
    if not name:
        errors.append("Name is required")

    group_ids = form.get('group_ids', '').strip()
    if not group_ids:
        errors.append("At least one group must be selected")
    else:
        try:
            [int(g.strip()) for g in group_ids.split(',') if g.strip()]
        except ValueError:
            errors.append("Invalid group IDs")

    time_limit = form.get('time_limit', '').strip()
    if not time_limit:
        errors.append("Time limit is required")
    else:
        try:
            tl = int(time_limit)
            if tl <= 0:
                errors.append("Time limit must be positive")
        except ValueError:
            errors.append("Time limit must be a number")

    trigger_domains = form.get('trigger_domains', '').strip()
    if not trigger_domains:
        errors.append("At least one trigger domain is required")

    block_regex = form.get('block_regex', '').strip()
    if not block_regex:
        errors.append("Block regex is required")
    else:
        try:
            re.compile(block_regex)
        except re.error as e:
            errors.append(f"Invalid regex: {e}")

    return errors


# =============================================================================
# ROUTES - AUTHENTICATION
# =============================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if request.method == 'POST':
        password = request.form.get('password', '')

        if verify_password(password):
            session['authenticated'] = True
            session.permanent = True
            next_url = request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        else:
            flash('Invalid password', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))


# =============================================================================
# ROUTES - DASHBOARD
# =============================================================================

@app.route('/')
@login_required
def dashboard():
    """Main dashboard showing all triggers."""
    triggers = get_all_triggers()
    next_reset = get_next_reset_time()

    # Add formatted time to each trigger
    for trigger in triggers:
        trigger['time_formatted'] = format_time(trigger['time_limit_seconds'])

    return render_template('dashboard.html',
                          triggers=triggers,
                          next_reset=next_reset)


@app.route('/status')
@login_required
def status():
    """JSON endpoint for AJAX status updates."""
    triggers = get_all_triggers()

    return jsonify({
        'triggers': [{
            'id': t['id'],
            'name': t['name'],
            'enabled': t['enabled'],
            'is_triggered': t['is_triggered'],
        } for t in triggers],
        'next_reset': get_next_reset_time(),
    })


# =============================================================================
# ROUTES - ADD TRIGGER
# =============================================================================

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    """Add a new trigger."""
    groups = get_pihole_groups()

    if request.method == 'POST':
        errors = validate_trigger_form(request.form)

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('add.html', groups=groups, form=request.form)

        # Extract form data
        name = request.form['name'].strip()
        group_ids = request.form['group_ids'].strip()
        time_limit = int(request.form['time_limit'])
        trigger_domains = request.form['trigger_domains'].strip()
        block_regex = request.form['block_regex'].strip()

        success, output = add_trigger(name, group_ids, time_limit, trigger_domains, block_regex)

        if success:
            flash(f'Trigger "{name}" created successfully', 'success')
            restart_daemon()
            return redirect(url_for('dashboard'))
        else:
            flash(f'Failed to create trigger: {output}', 'error')
            return render_template('add.html', groups=groups, form=request.form)

    return render_template('add.html', groups=groups, form={})


# =============================================================================
# ROUTES - EDIT TRIGGER
# =============================================================================

@app.route('/edit/<int:trigger_id>', methods=['GET', 'POST'])
@login_required
def edit(trigger_id):
    """Edit an existing trigger."""
    trigger = get_trigger(trigger_id)

    if not trigger:
        flash('Trigger not found', 'error')
        return redirect(url_for('dashboard'))

    groups = get_pihole_groups()

    if request.method == 'POST':
        errors = validate_trigger_form(request.form)

        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('edit.html', trigger=trigger, groups=groups, form=request.form)

        # Check if trigger was active - need to remove block before editing
        if trigger['is_triggered']:
            remove_block_rule(trigger_id, trigger['block_regex'])
            reload_pihole()

        # Extract form data
        name = request.form['name'].strip()
        group_ids = request.form['group_ids'].strip()
        time_limit = int(request.form['time_limit'])
        trigger_domains = request.form['trigger_domains'].strip()
        block_regex = request.form['block_regex'].strip()
        enabled = 'enabled' in request.form

        success, output = update_trigger(
            trigger_id,
            name=name,
            group_ids=group_ids,
            time_limit=time_limit,
            trigger_domains=trigger_domains,
            block_regex=block_regex,
            enabled=enabled
        )

        if success:
            flash(f'Trigger "{name}" updated successfully', 'success')
            restart_daemon()
            return redirect(url_for('dashboard'))
        else:
            flash(f'Failed to update trigger: {output}', 'error')
            return render_template('edit.html', trigger=trigger, groups=groups, form=request.form)

    return render_template('edit.html', trigger=trigger, groups=groups, form=trigger)


# =============================================================================
# ROUTES - ACTIONS
# =============================================================================

@app.route('/delete/<int:trigger_id>', methods=['POST'])
@login_required
def delete(trigger_id):
    """Delete a trigger."""
    trigger = get_trigger(trigger_id)

    if not trigger:
        flash('Trigger not found', 'error')
        return redirect(url_for('dashboard'))

    # Remove any active block
    if trigger['is_triggered']:
        remove_block_rule(trigger_id, trigger['block_regex'])
        reload_pihole()

    success, output = delete_trigger(trigger_id)

    if success:
        flash(f'Trigger "{trigger["name"]}" deleted', 'success')
        restart_daemon()
    else:
        flash(f'Failed to delete trigger: {output}', 'error')

    return redirect(url_for('dashboard'))


@app.route('/toggle/<int:trigger_id>', methods=['POST'])
@login_required
def toggle(trigger_id):
    """Toggle a trigger's enabled state."""
    trigger = get_trigger(trigger_id)

    if not trigger:
        if request.headers.get('HX-Request'):
            return '', 404
        flash('Trigger not found', 'error')
        return redirect(url_for('dashboard'))

    new_state = not trigger['enabled']

    # If disabling and currently triggered, remove the block
    if not new_state and trigger['is_triggered']:
        remove_block_rule(trigger_id, trigger['block_regex'])
        reload_pihole()

    success, _ = update_trigger(trigger_id, enabled=new_state)

    if success:
        restart_daemon()
        status = "enabled" if new_state else "disabled"

        # HTMX request - return partial HTML
        if request.headers.get('HX-Request'):
            return render_template('_trigger_row.html', trigger=get_trigger(trigger_id))

        flash(f'Trigger "{trigger["name"]}" {status}', 'success')
    else:
        flash('Failed to toggle trigger', 'error')

    return redirect(url_for('dashboard'))


@app.route('/reset/<int:trigger_id>', methods=['POST'])
@login_required
def reset(trigger_id):
    """Reset a single trigger."""
    trigger = get_trigger(trigger_id)

    if not trigger:
        if request.headers.get('HX-Request'):
            return '', 404
        flash('Trigger not found', 'error')
        return redirect(url_for('dashboard'))

    success, message = reset_trigger(trigger_id)

    if success:
        # HTMX request - return partial HTML
        if request.headers.get('HX-Request'):
            return render_template('_trigger_row.html', trigger=get_trigger(trigger_id))

        flash(f'Trigger "{trigger["name"]}" has been reset', 'success')
    else:
        flash(f'Failed to reset trigger: {message}', 'error')

    return redirect(url_for('dashboard'))


@app.route('/reset-all', methods=['POST'])
@login_required
def reset_all():
    """Reset all triggers."""
    success, message = reset_all_triggers()

    if success:
        flash(message, 'success')
    else:
        flash(f'Failed to reset triggers: {message}', 'error')

    return redirect(url_for('dashboard'))


# =============================================================================
# TEMPLATE FILTERS
# =============================================================================

@app.template_filter('format_time')
def format_time_filter(seconds):
    """Jinja2 filter for formatting time."""
    return format_time(seconds)


# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    # Initialize database
    init_trigger_db()

    # Run the app
    app.run(
        host='0.0.0.0',
        port=8080,
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )
