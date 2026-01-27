# Pi-hole Elapsed Time Trigger

A daemon for Pi-hole v6 that monitors DNS queries and automatically blocks specified domains for device groups after a configurable time limit. Perfect for implementing screen time limits on services like YouTube.

## How It Works

1. **Monitor**: The daemon watches Pi-hole's DNS query log in real-time
2. **Track**: When a device in a monitored group accesses a trigger domain (e.g., youtube.com), a timer starts
3. **Block**: After the time limit expires, a regex deny rule is added to Pi-hole blocking those domains for the group
4. **Persist**: Block rules are stored in Pi-hole's gravity database and survive reboots

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Device    │────>│   Pi-hole   │────>│   Daemon    │────>│   Block!    │
│ watches YT  │     │  logs DNS   │     │ starts timer│     │ after limit │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

## Features

- **Multiple triggers**: Configure different time limits for different services
- **Group-based**: Apply limits to specific Pi-hole client groups (e.g., "Kids Devices")
- **Flexible matching**: Use simple domain lists for triggering and regex patterns for blocking
- **Automatic daily reset**: All blocks are removed and timers reset daily (configurable time)
- **Persistent blocks**: Blocks survive daemon restarts and reboots (until the daily reset)
- **Systemd integration**: Runs as a system service with auto-start on boot
- **Remote management**: Deploy and manage from your development machine via SSH
- **Web interface**: Browser-based admin UI for managing triggers (port 8080)

## Requirements

- **Pi-hole v6+** running on a Raspberry Pi (or similar Linux system)
- **Python 3.7+** (included with Raspberry Pi OS)
- **SSH access** to the Pi-hole server
- **Root access** on the Pi-hole (for database and log access)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/your-repo/pihole-filler.git
cd pihole-filler
```

### 2. Configure Environment

Copy the example environment file and configure your Pi-hole connection:

```bash
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Pi-hole server IP or hostname
PIHOLE_HOST=<your-pi-hole-ip>

# SSH user (usually 'pi')
PIHOLE_USER=pi

# Path to SSH private key
PIHOLE_SSH_KEY=~/.ssh/id_rsa
```

### 3. Set Up SSH Key Authentication

Ensure you can SSH to your Pi-hole without a password:

```bash
# Generate a key if you don't have one
ssh-keygen -t ed25519 -f ~/.ssh/pihole_key

# Copy the key to your Pi-hole
ssh-copy-id -i ~/.ssh/pihole_key pi@<your-pi-hole-ip>
```

### 4. Deploy to Pi-hole

```bash
./deploy.sh
```

This will:
- Copy the script to your Pi-hole
- Install the systemd service
- Enable auto-start on boot
- Start the daemon

## Configuration

### Pi-hole Groups

Before creating triggers, set up client groups in Pi-hole:

1. Go to Pi-hole Admin > Group Management > Groups
2. Create a group (e.g., "Kids Devices")
3. Go to Group Management > Clients
4. Assign devices to the group

Note the **Group ID** (shown in the Groups list) - you'll need it for triggers.

### Creating Triggers

Add a trigger to limit YouTube to 1 hour for groups 2 and 3:

```bash
./deploy.sh --add \
  -n 'YouTube Limit' \
  -g 2,3 \
  -t 3600 \
  -d 'youtube,youtu.be,googlevideo.com,ytimg.com' \
  -r 'youtube|(^|\.)youtu\.be$|(^|\.)googlevideo\.com$|(^|\.)ytimg\.com$'
```

**Parameters:**
- `-n, --name`: A descriptive name for the trigger
- `-g, --groups`: Pi-hole group ID(s), comma-separated
- `-t, --time`: Time limit in seconds (3600 = 1 hour)
- `-d, --domains`: Domains that start the timer (comma-separated, partial match)
- `-r, --regex`: Regex pattern to block when time expires

### Trigger Domains vs Block Regex

- **Trigger domains** (`-d`): Simple substring matching to detect when a service is being used. When any DNS query contains one of these strings, the timer starts.

- **Block regex** (`-r`): The actual regex pattern added to Pi-hole's deny list when the timer expires. Should be comprehensive to fully block the service.

**Example for YouTube:**
- Trigger: `youtube,youtu.be,googlevideo.com` - Detects YouTube usage
- Regex: `youtube|(^|\.)youtu\.be$|(^|\.)googlevideo\.com$` - Blocks all YouTube domains

### Daily Reset

The daemon automatically resets all triggers at a configurable time each day (default: 3:00 AM):

- All active blocks are removed from Pi-hole
- All timers are reset to zero
- Devices get a fresh time allowance for the new day

This ensures that time limits apply per-day rather than accumulating indefinitely. The reset happens automatically - no manual intervention required.

To change the reset time, go to the **Settings** page in the web interface (`http://<your-pi-hole-ip>:8080/settings`) and select your preferred hour. The setting uses the Pi-hole server's local time zone.

## Web Interface

The web interface provides a browser-based admin UI for managing triggers, accessible at `http://<pi-hole-ip>:8080`.

### Features

- **Dashboard**: View all triggers with status indicators
- **Add/Edit triggers**: Forms with validation and time presets
- **Quick actions**: Enable/disable, reset, and delete triggers
- **Live logs**: Real-time daemon log viewer with auto-refresh
- **Settings page**: Configure the daily reset time
- **Mobile responsive**: Works on phones and tablets
- **Pi-hole authentication**: Uses your existing Pi-hole password

### Accessing the Web Interface

After deployment, access the web interface at:

```
http://<your-pi-hole-ip>:8080
```

Log in using your Pi-hole admin password (the same one you use for the Pi-hole admin interface).

### Live Log Viewer

The web interface includes a live log viewer at `http://<your-pi-hole-ip>:8080/logs` that displays daemon output in real-time.

**Features:**
- **Auto-refresh**: Logs update every 2 seconds via HTMX polling
- **Pause/Resume**: Stop auto-refresh to examine specific log entries
- **Line count**: Choose to display 50, 100, 200, or 500 lines
- **Auto-scroll**: Automatically scrolls to the latest entries
- **Terminal-style display**: Dark background with monospace font for readability

This is useful for monitoring trigger activity, debugging issues, or verifying that time limits are being tracked correctly.

### Web Interface Commands

```bash
# Check web server status
./deploy.sh --web-status

# View web server logs
./deploy.sh --web-logs

# Stop the web server
./deploy.sh --web-stop

# Start the web server
./deploy.sh --web-start
```

## Usage

### Deployment Commands

```bash
# Deploy everything (daemon + web interface) and restart services
./deploy.sh
./deploy.sh --all          # Explicit form of above

# Deploy daemon only (no web interface)
./deploy.sh --cli-only

# Remove previous installation (stop/disable services, remove files)
./deploy.sh --clean

# Check daemon status
./deploy.sh --status

# View live logs
./deploy.sh --logs

# Stop the daemon
./deploy.sh --stop

# Start the daemon
./deploy.sh --start
```

### Trigger Management

```bash
# List all triggers
./deploy.sh --list

# Add a new trigger
./deploy.sh --add -n 'Name' -g 2 -t 3600 -d 'domain.com' -r 'domain\.com'

# Edit a trigger
./deploy.sh --edit 1 -t 7200              # Change time limit
./deploy.sh --edit 1 -n 'New Name'        # Change name
./deploy.sh --edit 1 -g 2,3,4             # Change groups
./deploy.sh --edit 1 --disable            # Disable trigger
./deploy.sh --edit 1 --enable             # Enable trigger

# Remove a trigger
./deploy.sh --remove 1

# Reset a trigger (remove active block, restart timer)
./deploy.sh --reset 1

# Remove all active blocks
./deploy.sh --unblock
```

### Command Reference

| Command | Description |
|---------|-------------|
| *(no args)* | Deploy everything and restart services (same as `--all`) |
| `--all` | Deploy daemon + web interface, restart both services |
| `--cli-only` | Deploy daemon only (no web interface), restart daemon |
| `--clean` | Remove previous installation (stop/disable services, remove files) |
| `--list` | List all configured triggers |
| `--add [OPTIONS]` | Add a new trigger |
| `--edit ID [OPTIONS]` | Edit an existing trigger |
| `--remove ID` | Remove a trigger and its active block |
| `--reset ID` | Remove active block and reset timer |
| `--unblock` | Remove all active blocks |
| `--status` | Show daemon status |
| `--logs` | View live daemon logs |
| `--stop` | Stop the daemon |
| `--start` | Start the daemon |
| `--web-status` | Show web server status |
| `--web-logs` | View live web server logs |
| `--web-stop` | Stop the web server |
| `--web-start` | Start the web server |

### Field Options

| Option | Description |
|--------|-------------|
| `-n, --name` | Trigger name |
| `-g, --groups` | Pi-hole group IDs (comma-separated) |
| `-t, --time` | Time limit in seconds |
| `-d, --domains` | Trigger domains (comma-separated) |
| `-r, --regex` | Block regex pattern |
| `--enable` | Enable the trigger |
| `--disable` | Disable the trigger |

## Examples

### Limit YouTube to 30 minutes for Kids

```bash
./deploy.sh --add \
  -n 'Kids YouTube' \
  -g 2 \
  -t 1800 \
  -d 'youtube,youtu.be,googlevideo.com,ytimg.com' \
  -r 'youtube|(^|\.)youtu\.be$|(^|\.)googlevideo\.com$|(^|\.)ytimg\.com$'
```

### Limit TikTok to 1 hour

```bash
./deploy.sh --add \
  -n 'TikTok Limit' \
  -g 2 \
  -t 3600 \
  -d 'tiktok.com,tiktokcdn.com' \
  -r '(^|\.)tiktok\.com$|(^|\.)tiktokcdn\.com$'
```

### Limit Netflix to 2 hours

```bash
./deploy.sh --add \
  -n 'Netflix Limit' \
  -g 2 \
  -t 7200 \
  -d 'netflix.com,nflxvideo.net' \
  -r '(^|\.)netflix\.com$|(^|\.)nflxvideo\.net$'
```

### Extend time limit temporarily

```bash
# Double the time limit for trigger 1
./deploy.sh --edit 1 -t 7200

# Reset to remove current block and start fresh
./deploy.sh --reset 1
```

## Troubleshooting

### Check daemon status

```bash
./deploy.sh --status
```

### View logs

```bash
# Live logs
./deploy.sh --logs

# Recent logs on Pi-hole
ssh pi@<your-pi-hole-ip> "sudo journalctl -u pihole-trigger -n 50"
```

### Daemon won't start

1. Check if Pi-hole is running: `pihole status`
2. Verify the trigger database exists: `ls -la /home/pi/trigger.db`
3. Check for Python errors in logs: `./deploy.sh --logs`

### Blocks not being applied

1. Verify the client is in the correct Pi-hole group
2. Check that the trigger is enabled: `./deploy.sh --list`
3. Ensure the regex pattern is valid
4. Try manually restarting Pi-hole FTL: `ssh pi@<your-pi-hole-ip> "sudo systemctl restart pihole-FTL"`

### Reset everything

```bash
# Remove all blocks
./deploy.sh --unblock

# Restart daemon
./deploy.sh --stop && ./deploy.sh --start
```

## Architecture

```
Local Machine                    Pi-hole Server
┌──────────────┐                ┌─────────────────────────────────────────────┐
│              │                │                                             │
│  deploy.sh   │<──── SSH ────> │  pihole_elapsed_time_trigger.py (daemon)    │
│              │                │            │                                │
└──────────────┘                │            v                                │
                                │  ┌─────────────────┐                        │
       Browser                  │  │   trigger.db    │<──┐                    │
┌──────────────┐                │  └─────────────────┘   │                    │
│              │                │            │           │                    │
│  Web UI      │<── HTTP:8080 ─>│  trigger_web/app.py ───┘                    │
│              │                │  (Flask web server)                         │
└──────────────┘                │            │                                │
                                │            v                                │
                                │  ┌─────────────────┐                        │
                                │  │  pihole.log     │ (monitor)              │
                                │  └─────────────────┘                        │
                                │            │                                │
                                │            v                                │
                                │  ┌─────────────────┐                        │
                                │  │   gravity.db    │ (Pi-hole block rules)  │
                                │  └─────────────────┘                        │
                                │                                             │
                                └─────────────────────────────────────────────┘
```

## Files

| File | Location | Description |
|------|----------|-------------|
| `deploy.sh` | Local | Deployment and management script |
| `pihole_elapsed_time_trigger.py` | Pi-hole: `/home/pi/` | Main daemon script |
| `pihole-trigger.service` | Pi-hole: `/etc/systemd/system/` | Daemon systemd service |
| `trigger_web/` | Pi-hole: `/home/pi/trigger_web/` | Web interface Flask app |
| `trigger-web.service` | Pi-hole: `/etc/systemd/system/` | Web server systemd service |
| `trigger.db` | Pi-hole: `/home/pi/` | SQLite database for trigger config |
| `.env` | Local | Environment configuration |

## License

MIT License - See LICENSE file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
