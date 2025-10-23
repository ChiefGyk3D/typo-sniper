#!/bin/bash

# Helper script to set up and test API keys for Typo Sniper

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "=============================================="
echo "  Typo Sniper API Key Setup"
echo "=============================================="
echo ""

# Check if .env exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Creating from template..."
    cp .env.example .env
    print_success ".env file created!"
    echo ""
    print_warning "Please edit .env and add your API keys:"
    echo "  nano .env"
    echo "  or"
    echo "  vim .env"
    echo ""
    print_warning "Get your API key from:"
    echo "  URLScan: https://urlscan.io/user/profile"
    echo ""
    exit 1
fi

print_success ".env file found!"
echo ""

# Load .env file
print_step "Loading environment variables from .env..."
export $(grep -v '^#' .env | xargs)

# Check URLScan API key
print_step "Checking URLScan API key..."
if [ -z "$TYPO_SNIPER_URLSCAN_API_KEY" ] && [ -z "$URLSCAN_API_KEY" ]; then
    print_error "URLScan API key not set in .env!"
    echo "  Please add: TYPO_SNIPER_URLSCAN_API_KEY=your-api-key"
else
    KEY="${TYPO_SNIPER_URLSCAN_API_KEY:-$URLSCAN_API_KEY}"
    if [ "$KEY" = "your-urlscan-api-key-here" ]; then
        print_error "URLScan API key is still the placeholder value!"
        echo "  Please edit .env and add your actual API key"
    else
        print_success "URLScan API key is set!"
        echo "  Testing API key..."
        python3 test_urlscan_api.py
    fi
fi

echo ""
echo "=============================================="
print_success "Setup complete!"
echo "=============================================="
echo ""
echo "To use these keys in your current shell:"
echo "  export \$(grep -v '^#' .env | xargs)"
echo ""
echo "Or source the .env file:"
echo "  set -a; source .env; set +a"
echo ""
