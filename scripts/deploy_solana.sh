#!/bin/bash
# Deploy AgentSentinel Solana Registry
#
# Prerequisites:
# - Solana CLI installed and configured
# - Anchor CLI installed
# - Wallet with sufficient SOL for deployment
#
# Usage:
#   ./scripts/deploy_solana.sh [cluster]
#
# Clusters: localnet, devnet, mainnet-beta (default: devnet)

set -e

CLUSTER="${1:-devnet}"
REGISTRY_DIR="solana_registry"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║        AgentSentinel Solana Registry Deployment             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check prerequisites
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "❌ $1 is not installed. Please install it first."
        exit 1
    fi
}

echo "🔍 Checking prerequisites..."
check_command solana
check_command anchor

echo "✅ All prerequisites installed"
echo ""

# Configure cluster
echo "🌐 Configuring cluster: $CLUSTER"
case $CLUSTER in
    localnet)
        solana config set --url localhost
        ;;
    devnet)
        solana config set --url devnet
        ;;
    mainnet-beta)
        solana config set --url mainnet-beta
        echo "⚠️  WARNING: Deploying to mainnet!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            echo "Deployment cancelled."
            exit 0
        fi
        ;;
    *)
        echo "Unknown cluster: $CLUSTER"
        exit 1
        ;;
esac

# Check wallet balance
echo ""
echo "💰 Checking wallet balance..."
BALANCE=$(solana balance | grep -oE '[0-9.]+')
echo "   Balance: $BALANCE SOL"

MIN_BALANCE=2
if (( $(echo "$BALANCE < $MIN_BALANCE" | bc -l) )); then
    echo "❌ Insufficient balance. Need at least $MIN_BALANCE SOL for deployment."
    if [ "$CLUSTER" == "devnet" ]; then
        echo "   Run: solana airdrop 2"
    fi
    exit 1
fi

# Build the program
echo ""
echo "🔧 Building Anchor program..."
cd "$REGISTRY_DIR"

anchor build

# Get program ID from keypair
PROGRAM_KEYPAIR="target/deploy/agent_registry-keypair.json"
if [ -f "$PROGRAM_KEYPAIR" ]; then
    PROGRAM_ID=$(solana address -k "$PROGRAM_KEYPAIR")
else
    echo "❌ Program keypair not found. Build may have failed."
    exit 1
fi

echo "📋 Program ID: $PROGRAM_ID"

# Update program ID in lib.rs and Anchor.toml
echo ""
echo "📝 Updating program ID in source files..."

# Update lib.rs
sed -i "s/declare_id!(\".*\")/declare_id!(\"$PROGRAM_ID\")/" programs/agent_registry/src/lib.rs

# Update Anchor.toml
sed -i "s/agent_registry = \".*\"/agent_registry = \"$PROGRAM_ID\"/" Anchor.toml

# Rebuild with updated ID
echo "🔧 Rebuilding with updated program ID..."
anchor build

# Deploy
echo ""
echo "🚀 Deploying to $CLUSTER..."
anchor deploy --provider.cluster "$CLUSTER"

# Verify deployment
echo ""
echo "✅ Deployment complete!"
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                     Deployment Summary                       ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║ Program ID: $PROGRAM_ID"
echo "║ Cluster:    $CLUSTER"
echo "║ Explorer:   https://explorer.solana.com/address/$PROGRAM_ID?cluster=$CLUSTER"
echo "╚══════════════════════════════════════════════════════════════╝"

# Run tests if on devnet/localnet
if [ "$CLUSTER" != "mainnet-beta" ]; then
    echo ""
    read -p "Run tests? (y/n): " run_tests
    if [ "$run_tests" == "y" ]; then
        echo "🧪 Running tests..."
        anchor test --skip-local-validator --skip-deploy
    fi
fi

echo ""
echo "🎉 Done! Your AgentSentinel registry is live on $CLUSTER."
