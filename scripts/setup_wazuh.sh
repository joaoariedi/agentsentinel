#!/bin/bash
# AgentSentinel - Wazuh Agent Installation Script
# This script installs and configures the Wazuh agent with custom AgentSentinel rules

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

# Configuration
WAZUH_MANAGER=${WAZUH_MANAGER:-"localhost"}
WAZUH_VERSION=${WAZUH_VERSION:-"4.x"}

log_info "Installing Wazuh Agent..."
log_info "Wazuh Manager: $WAZUH_MANAGER"

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
        
        # Add Wazuh repository
        curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null || true
        chmod 644 /usr/share/keyrings/wazuh.gpg 2>/dev/null || true
        
        echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/${WAZUH_VERSION}/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
        
        apt-get update
        WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent
        ;;
        
    centos|rhel|fedora|rocky|alma)
        log_info "Detected RHEL-based system"
        
        rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        
        cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-\$releasever - Wazuh
baseurl=https://packages.wazuh.com/${WAZUH_VERSION}/yum/
protect=1
EOF
        
        WAZUH_MANAGER="$WAZUH_MANAGER" yum install -y wazuh-agent
        ;;
        
    arch|manjaro)
        log_info "Detected Arch Linux"
        log_warn "Wazuh is not in official Arch repos. Please install from AUR:"
        log_warn "  yay -S wazuh-agent"
        log_warn "Then run this script again with --skip-install"
        
        if [[ "$1" != "--skip-install" ]]; then
            exit 1
        fi
        ;;
        
    *)
        log_error "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Configure Wazuh agent
OSSEC_CONF="/var/ossec/etc/ossec.conf"

if [ -f "$OSSEC_CONF" ]; then
    log_info "Configuring Wazuh agent..."
    
    # Set manager address
    sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|g" "$OSSEC_CONF"
    
    log_info "Wazuh agent configured to connect to: $WAZUH_MANAGER"
else
    log_warn "ossec.conf not found at $OSSEC_CONF"
fi

# Copy custom rules and decoders
RULES_DIR="/var/ossec/etc/rules"
DECODERS_DIR="/var/ossec/etc/decoders"

if [ -d "$RULES_DIR" ]; then
    if [ -f "$PROJECT_ROOT/configs/wazuh/rules/agentsentinel_rules.xml" ]; then
        cp "$PROJECT_ROOT/configs/wazuh/rules/agentsentinel_rules.xml" "$RULES_DIR/"
        log_info "Installed custom AgentSentinel rules"
    else
        log_warn "Custom rules file not found"
    fi
fi

if [ -d "$DECODERS_DIR" ]; then
    if [ -f "$PROJECT_ROOT/configs/wazuh/decoders/agentsentinel_decoders.xml" ]; then
        cp "$PROJECT_ROOT/configs/wazuh/decoders/agentsentinel_decoders.xml" "$DECODERS_DIR/"
        log_info "Installed custom AgentSentinel decoders"
    else
        log_warn "Custom decoders file not found"
    fi
fi

# Enable and start Wazuh agent
log_info "Enabling Wazuh agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent || log_warn "Could not start wazuh-agent (manager may not be configured)"

# Check status
if systemctl is-active --quiet wazuh-agent; then
    log_info "Wazuh Agent is running!"
else
    log_warn "Wazuh Agent installed but not running"
    log_warn "Ensure the Wazuh Manager is accessible and restart: systemctl start wazuh-agent"
fi

log_info "Wazuh Agent installation complete!"
echo ""
echo "Next steps:"
echo "  1. Ensure Wazuh Manager is running and accessible at: $WAZUH_MANAGER"
echo "  2. Register this agent with the manager"
echo "  3. Restart the agent: systemctl restart wazuh-agent"
echo "  4. Check logs: tail -f /var/ossec/logs/ossec.log"
