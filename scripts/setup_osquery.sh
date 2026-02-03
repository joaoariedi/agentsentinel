#!/bin/bash
# AgentSentinel - OSquery Installation Script
# This script installs and configures OSquery with AgentSentinel monitoring queries

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

log_info "Installing OSquery..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    log_error "Cannot detect OS"
    exit 1
fi

case $OS in
    ubuntu|debian)
        log_info "Detected Debian/Ubuntu"
        
        # Add OSquery repository
        export OSQUERY_KEY=1484120AC4E9F8A1A577AEEE97A80C63C9D8B80B
        apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys $OSQUERY_KEY 2>/dev/null || true
        
        # Alternative method if apt-key fails
        if ! apt-key list 2>/dev/null | grep -q "C9D8B80B"; then
            curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | gpg --dearmor -o /usr/share/keyrings/osquery-archive-keyring.gpg
            echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery-archive-keyring.gpg] https://pkg.osquery.io/deb deb main" | tee /etc/apt/sources.list.d/osquery.list
        else
            echo "deb [arch=amd64] https://pkg.osquery.io/deb deb main" | tee /etc/apt/sources.list.d/osquery.list
        fi
        
        apt-get update
        apt-get install -y osquery
        ;;
        
    centos|rhel|fedora|rocky|alma)
        log_info "Detected RHEL-based system"
        
        curl -L https://pkg.osquery.io/rpm/GPG | tee /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
        
        cat > /etc/yum.repos.d/osquery-s3-rpm.repo << EOF
[osquery-s3-rpm]
name=osquery-s3-rpm
baseurl=https://pkg.osquery.io/rpm
enabled=1
gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-osquery
EOF
        
        yum install -y osquery
        ;;
        
    arch|manjaro)
        log_info "Detected Arch Linux"
        pacman -Sy --noconfirm osquery || {
            log_warn "osquery not in repos, trying AUR..."
            log_warn "Please install manually: yay -S osquery"
            exit 1
        }
        ;;
        
    *)
        log_error "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Create necessary directories
log_info "Creating OSquery directories..."
mkdir -p /etc/osquery
mkdir -p /var/log/osquery
mkdir -p /var/osquery

# Copy configuration
if [ -f "$PROJECT_ROOT/configs/osquery/agentsentinel.conf" ]; then
    cp "$PROJECT_ROOT/configs/osquery/agentsentinel.conf" /etc/osquery/osquery.conf
    log_info "Installed AgentSentinel OSquery configuration"
else
    log_warn "AgentSentinel config not found, using default"
fi

# Set up file event monitoring (requires auditd)
log_info "Setting up auditd for file event monitoring..."

if command -v apt-get &> /dev/null; then
    apt-get install -y auditd
elif command -v yum &> /dev/null; then
    yum install -y audit
elif command -v pacman &> /dev/null; then
    pacman -Sy --noconfirm audit
fi

# Configure audit rules for OSquery file events
AUDIT_RULES="/etc/audit/rules.d/osquery.rules"
cat > "$AUDIT_RULES" << 'EOF'
# OSquery file event monitoring for AgentSentinel
-a always,exit -F arch=b64 -S open -S openat -F success=1 -k osquery_file_events
-a always,exit -F arch=b64 -S unlink -S unlinkat -F success=1 -k osquery_file_delete
-a always,exit -F arch=b64 -S rename -S renameat -F success=1 -k osquery_file_rename

# Monitor sensitive paths
-w /etc/passwd -p wa -k osquery_identity
-w /etc/shadow -p wa -k osquery_identity
-w /etc/sudoers -p wa -k osquery_priv_esc
-w /root/.ssh -p wa -k osquery_ssh
EOF

# Restart auditd
systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || log_warn "Could not restart auditd"

# Enable osquery extensions socket
OSQUERY_FLAGS="/etc/osquery/osquery.flags"
cat > "$OSQUERY_FLAGS" << 'EOF'
--disable_extensions=false
--extensions_socket=/var/osquery/osquery.em
--extensions_autoload=/etc/osquery/extensions.load
--extensions_timeout=3
--extensions_interval=3
--disable_events=false
--enable_file_events=true
--enable_ntfs_event_publisher=false
EOF

# Create empty extensions load file
touch /etc/osquery/extensions.load

# Enable and start OSquery
log_info "Enabling OSquery service..."
systemctl daemon-reload
systemctl enable osqueryd
systemctl start osqueryd

# Check status
sleep 2
if systemctl is-active --quiet osqueryd; then
    log_info "OSquery is running!"
    
    # Test query
    log_info "Testing OSquery..."
    if osqueryi --json "SELECT * FROM system_info LIMIT 1" 2>/dev/null | head -5; then
        log_info "OSquery test successful!"
    else
        log_warn "OSquery interactive test had issues (daemon may still work)"
    fi
else
    log_warn "OSquery installed but not running"
    log_warn "Check logs: journalctl -u osqueryd -f"
fi

log_info "OSquery installation complete!"
echo ""
echo "Useful commands:"
echo "  - Interactive query: osqueryi"
echo "  - Check daemon status: systemctl status osqueryd"
echo "  - View logs: tail -f /var/log/osquery/osqueryd.results.log"
echo "  - Restart: systemctl restart osqueryd"
echo ""
echo "Socket path for AgentSentinel: /var/osquery/osquery.em"
