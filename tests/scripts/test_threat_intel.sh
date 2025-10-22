#!/bin/bash

# Typo Sniper Threat Intelligence Testing Script
# This script walks you through testing VirusTotal, URLScan.io, and Doppler

set -e

echo "=============================================="
echo "  Typo Sniper Threat Intelligence Test Suite"
echo "=============================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored messages
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

# Check if we're in the right directory
if [ ! -f "src/typo_sniper.py" ]; then
    print_error "Please run this script from the Typo Sniper root directory"
    exit 1
fi

echo ""
print_step "Checking Python environment..."
if [ -d ".venv" ]; then
    print_success "Virtual environment found"
    source .venv/bin/activate
else
    print_warning "No virtual environment found. Creating one..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
fi

echo ""
print_step "Checking required dependencies..."
python -c "import aiohttp, yaml, openpyxl, rich, aiofiles" 2>/dev/null
if [ $? -eq 0 ]; then
    print_success "All required dependencies installed"
else
    print_error "Missing dependencies. Installing..."
    pip install -r requirements.txt
fi

echo ""
echo "=============================================="
echo "  TEST 1: Environment Variables (Local)"
echo "=============================================="
echo ""

print_step "Testing with local environment variables..."
echo ""
echo "Please enter your VirusTotal API key:"
read -p "VirusTotal API Key: " VT_KEY
echo ""
echo "Please enter your URLScan.io API key:"
read -p "URLScan.io API Key: " URLSCAN_KEY

export TYPO_SNIPER_VIRUSTOTAL_API_KEY="$VT_KEY"
export TYPO_SNIPER_URLSCAN_API_KEY="$URLSCAN_KEY"

print_success "Environment variables set!"
echo ""

print_step "Running scan with environment variables..."
python src/typo_sniper.py -i test_domains.txt --config test_config.yaml --format excel json -v

if [ $? -eq 0 ]; then
    print_success "✅ TEST 1 PASSED: Environment variables scan completed"
else
    print_error "❌ TEST 1 FAILED: Environment variables scan failed"
    exit 1
fi

echo ""
echo "=============================================="
echo "  TEST 2: Doppler Secrets Management"
echo "=============================================="
echo ""

print_step "Checking if Doppler CLI is installed..."
if command -v doppler &> /dev/null; then
    print_success "Doppler CLI found"
else
    print_warning "Doppler CLI not found. Installing..."
    curl -Ls https://cli.doppler.com/install.sh | sudo sh
fi

echo ""
print_step "Setting up Doppler..."
echo ""
echo "If you haven't logged in to Doppler yet, you'll be prompted to authenticate."
echo "Press any key to continue..."
read -n 1 -s

doppler login

echo ""
print_step "Creating/selecting Doppler project..."
echo ""
echo "Do you want to:"
echo "  1) Create a new Doppler project for Typo Sniper"
echo "  2) Use an existing project"
read -p "Enter choice (1 or 2): " doppler_choice

if [ "$doppler_choice" = "1" ]; then
    echo ""
    read -p "Enter project name (e.g., typo-sniper): " project_name
    doppler projects create "$project_name" || print_warning "Project may already exist"
    doppler setup --project "$project_name" --config dev
else
    doppler setup
fi

echo ""
print_step "Adding secrets to Doppler..."
doppler secrets set VIRUSTOTAL_API_KEY="$VT_KEY"
doppler secrets set URLSCAN_API_KEY="$URLSCAN_KEY"

print_success "Secrets added to Doppler!"
echo ""

print_step "Verifying secrets in Doppler..."
doppler secrets

echo ""
print_step "Running scan with Doppler..."

# Unset local env vars to test Doppler
unset TYPO_SNIPER_VIRUSTOTAL_API_KEY
unset TYPO_SNIPER_URLSCAN_API_KEY

doppler run -- python src/typo_sniper.py -i test_domains.txt --config test_config.yaml --format excel json -v

if [ $? -eq 0 ]; then
    print_success "✅ TEST 2 PASSED: Doppler secrets scan completed"
else
    print_error "❌ TEST 2 FAILED: Doppler secrets scan failed"
    exit 1
fi

echo ""
echo "=============================================="
echo "  TEST 3: Docker with Environment Variables"
echo "=============================================="
echo ""

print_step "Building Docker image..."
docker build -f docker/Dockerfile -t typo-sniper:test .

if [ $? -ne 0 ]; then
    print_error "Docker build failed"
    exit 1
fi

print_success "Docker image built successfully"
echo ""

print_step "Running scan in Docker with environment variables..."
docker run --rm \
  -v "$(pwd)/test_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -e TYPO_SNIPER_VIRUSTOTAL_API_KEY="$VT_KEY" \
  -e TYPO_SNIPER_URLSCAN_API_KEY="$URLSCAN_KEY" \
  typo-sniper:test \
  -i /app/data/domains.txt \
  --format excel json -v

if [ $? -eq 0 ]; then
    print_success "✅ TEST 3 PASSED: Docker with env vars scan completed"
else
    print_error "❌ TEST 3 FAILED: Docker with env vars scan failed"
    exit 1
fi

echo ""
echo "=============================================="
echo "  TEST 4: Docker with Doppler"
echo "=============================================="
echo ""

print_step "Checking for Doppler-enabled Dockerfile..."
if [ ! -f "docker/Dockerfile.doppler" ]; then
    print_error "docker/Dockerfile.doppler not found"
    exit 1
fi

print_step "Building Doppler-enabled Docker image..."
docker build -f docker/Dockerfile.doppler -t typo-sniper:doppler .

if [ $? -ne 0 ]; then
    print_error "Docker build with Doppler failed"
    exit 1
fi

print_success "Doppler-enabled Docker image built successfully"
echo ""

print_step "Getting Doppler service token..."
echo ""
echo "Creating a service token for Docker..."
DOPPLER_TOKEN=$(doppler configs tokens create docker-test --plain 2>/dev/null || doppler configs tokens create docker-test-$(date +%s) --plain)

if [ -z "$DOPPLER_TOKEN" ]; then
    print_error "Failed to create Doppler service token"
    exit 1
fi

print_success "Service token created"
echo ""

print_step "Running scan in Docker with Doppler..."
docker run --rm \
  -v "$(pwd)/test_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -e DOPPLER_TOKEN="$DOPPLER_TOKEN" \
  typo-sniper:doppler \
  -i /app/data/domains.txt \
  --format excel json -v

if [ $? -eq 0 ]; then
    print_success "✅ TEST 4 PASSED: Docker with Doppler scan completed"
else
    print_error "❌ TEST 4 FAILED: Docker with Doppler scan failed"
    exit 1
fi

echo ""
echo "=============================================="
echo "  TEST RESULTS SUMMARY"
echo "=============================================="
echo ""

print_success "✅ All tests passed!"
echo ""
echo "Results are available in the 'results/' directory:"
ls -lh results/ | tail -n 10

echo ""
echo "Test artifacts created:"
echo "  - test_domains.txt (test domain list)"
echo "  - test_config.yaml (test configuration)"
echo "  - results/ (scan results)"
echo ""
echo "Doppler tokens created:"
doppler configs tokens list

echo ""
print_success "Testing complete! 🎉"
echo ""
echo "Next steps:"
echo "  1. Review results in results/ directory"
echo "  2. Check Excel files for threat intelligence data"
echo "  3. Verify risk scoring is working"
echo "  4. Clean up test tokens: doppler configs tokens revoke <token-name>"
