# Quick Start: Testing with URLScan.io

This is a condensed guide to get you up and running quickly with the threat intelligence features.

## 1. Get Your API Key (2 minutes)

### URLScan.io
1. Go to https://urlscan.io/user/signup
2. Sign up (free)
3. Visit https://urlscan.io/user/profile
4. Click "API" tab
5. Copy your API key (UUID format)

## 2. Configure Typo Sniper (2 minutes)

### Option A: Using Environment Variables (Recommended for Testing)

```bash
cd "/home/chiefgyk3d/src/Typo Sniper"

# Set API key and explicitly enable (manual env vars require explicit enable)
export TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key_here"
export TYPO_SNIPER_ENABLE_URLSCAN=true
```

### Option B: Using Config File

```bash
# Create test config
cat > test_config.yaml << 'EOF'
# Enable threat intelligence
enable_urlscan: true
urlscan_api_key: "YOUR_URLSCAN_KEY_HERE"
urlscan_max_age_days: 7    # Submit new scan if older than 7 days
urlscan_wait_timeout: 90    # Wait up to 90 seconds for scan results

# Enable other features
enable_certificate_transparency: true
enable_http_probe: true
enable_risk_scoring: true

# Enhanced detection (WARNING: These slow down scans significantly!)
# Disabled by default - only enable if you need these specific detections
enable_combosquatting: false   # ~360+ variations per domain
enable_soundalike: false        # Phonetic matching
enable_idn_homograph: false     # Up to 50 variations per domain

# Rate limiting (respect API limits)
max_workers: 4
rate_limit_delay: 15.0  # 15 seconds between batches
EOF

# Replace YOUR_VT_KEY_HERE and YOUR_URLSCAN_KEY_HERE with your actual keys
```

### Option C: Using Doppler (Recommended for Production)

```bash
# Install Doppler CLI
curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh | sudo sh

# Login
doppler login

# Setup project
doppler setup

# Add secrets (URLScan auto-enables with Doppler!)
doppler secrets set URLSCAN_API_KEY="your_urlscan_key"

# Verify
doppler secrets
```

### Option D: Using AWS Secrets Manager (AWS Environments)

```bash
# Install AWS CLI (if not installed)
# See: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Configure AWS credentials
aws configure

# Create secret (URLScan auto-enables with AWS Secrets Manager!)
aws secretsmanager create-secret \
  --name typo-sniper/prod \
  --secret-string '{
    "urlscan_api_key": "your_urlscan_key"
  }'

# Set environment variable
export AWS_SECRET_NAME="typo-sniper/prod"
```

**See [TESTING.md](TESTING.md) for complete setup guides for each option.**

## 3. Run Your First Test (1 minute)

### Create Test Domain List

```bash
cat > test_small.txt << EOF
example.com
EOF
```

### Run with Environment Variables

```bash
python src/typo_sniper.py \
  -i test_small.txt \
  --format excel json \
  -v
```

### Run with Config File

```bash
python src/typo_sniper.py \
  -i test_small.txt \
  --config test_config.yaml \
  --format excel json \
  -v
```

### Run with Doppler

```bash
doppler run -- python src/typo_sniper.py \
  -i test_small.txt \
  --format excel json \
  -v
```

## 4. Check Results

```bash
# List results
ls -lh results/

# View JSON data
cat results/typo_sniper_results_*.json | jq '.results[0].permutations[0]' | head -50

# Open Excel (risk scores are color-coded!)
xdg-open results/typo_sniper_results_*.xlsx
```

## 5. Docker Testing

### Build Image

```bash
docker build -f docker/Dockerfile -t typo-sniper:threat-intel .
```

### Run with Environment Variables

```bash
docker run --rm \
  -e TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key" \
  -v "$(pwd)/test_small.txt:/app/data/test.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:threat-intel \
  -i /app/data/test.txt \
  --format excel json \
  -v
```

### Run with Docker Compose

```bash
# Create .env file
cat > docker/.env << EOF
URLSCAN_API_KEY=your_urlscan_key_here
EOF

# Secure it
chmod 600 docker/.env

# Copy config
cp docs/config.yaml.example docker/config.yaml

# Edit docker/config.yaml to enable features (or use env vars only)

# Run
docker-compose -f docker/docker-compose.threat-intel.yml up
```

### Run with Doppler + Docker

```bash
# Get Doppler service token
export DOPPLER_TOKEN=$(doppler configs tokens create docker-token --plain)

# Build Doppler-enabled image
docker build -f docker/Dockerfile.doppler -t typo-sniper:doppler .

# Run
docker run --rm \
  -e DOPPLER_TOKEN="$DOPPLER_TOKEN" \
  -v "$(pwd)/test_small.txt:/app/data/test.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:doppler \
  -i /app/data/test.txt \
  --format excel \
  -v
```

## 6. Understanding the Results

### Excel Report Columns

Look for these new columns in the Details sheet:
- **Risk Score**: 0-100 (higher = more suspicious)
- **URLScan
- **URLScan Status**: malicious, suspicious, or clean
- **CT Logs**: Number of SSL certificates issued
- **HTTP Status**: HTTP status code (200, 301, 404, etc.)

### Color Coding

- 🔴 **Red (70-100)**: HIGH RISK - Immediate investigation needed
- 🟠 **Orange (50-69)**: MEDIUM RISK - Monitor closely
- 🟡 **Yellow (30-49)**: LOW-MEDIUM RISK - Routine review
- ⚪ **White (0-29)**: LOW RISK - Informational

### JSON Output Example

```json
{
  "domain": "examp1e.com",
  "fuzzer": "homograph",
  "risk_score": 75,
  "threat_intel": {
    "urlscan": {
      "verdict": "malicious",
      "url": "https://urlscan.io/result/..."
    },
    "certificate_transparency": {
      "certificate_count": 3
    },
    "http_probe": {
      "status_code": 200,
      "is_active": true
    }
  }
}
```

## 7. Rate Limit Considerations

### URLScan.io (Free Tier)
- **5,000 scans/month**
- Public submissions (visible to everyone)
- ~30 seconds per scan
- For 100 domains: ~50 minutes scan time

### Recommendations
1. Start with 5-10 domains for testing
2. Enable caching (on by default)
3. Use `--months 3` to filter recent domains only
4. Consider paid plans for production use

## 8. Troubleshooting

### "Rate limit exceeded"
```bash
# Increase delay between batches
# Edit config: rate_limit_delay: 20.0
# Or reduce workers: max_workers: 2
```

### "Invalid API key"
```bash
# Verify key is set correctly
echo $TYPO_SNIPER_URLSCAN_API_KEY

# Check config file
cat test_config.yaml | grep api_key
```

### "No threat intelligence in results"
```bash
# Run with verbose to see what's happening
python src/typo_sniper.py -i test_small.txt -v 2>&1 | grep -i "threat\|urlscan"
```

### "Doppler not working"
```bash
# Verify Doppler is installed
doppler --version

# Check secrets are set
doppler secrets

# Test injection
doppler run -- env | grep -i "URLSCAN"
```

## 9. Security Best Practices

```bash
# Never commit API keys!
cat >> .gitignore << EOF
test_config.yaml
test_*.yaml
.env
*_config.yaml
EOF

# Secure your config files
chmod 600 test_config.yaml
chmod 600 docker/.env

# Use Doppler for production
# - Automatic rotation
# - Audit logs
# - Team access control
# - No keys in code/config
```

## 10. Next Steps

- Read `TESTING.md` for comprehensive testing guide
- Read `ENHANCEMENTS.md` for feature details
- Check `README.md` for full documentation
- Join the discussion: [GitHub Issues](link)

## Quick Command Reference

```bash
# Test with minimal features (fastest)
python src/typo_sniper.py -i test.txt --format excel

# Test with threat intelligence (slower, needs API keys)
python src/typo_sniper.py -i test.txt --config test_config.yaml --format excel -v

# Test with Doppler
doppler run -- python src/typo_sniper.py -i test.txt --format excel -v

# Docker test
docker run --rm \
  -e TYPO_SNIPER_URLSCAN_API_KEY="key" \
  -v "$(pwd)/test.txt:/app/data/test.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  typo-sniper:latest -i /app/data/test.txt --format excel -v

# View results
ls -lh results/
cat results/*.json | jq '.results[0].permutations[] | select(.risk_score > 50)'
xdg-open results/*.xlsx
```

## Support

For issues:
- Check verbose output: `-v` flag
- Review API quotas on provider websites
- Check `TESTING.md` for detailed troubleshooting
- Verify network connectivity
- Test API keys manually with curl

Happy hunting! 🎯
