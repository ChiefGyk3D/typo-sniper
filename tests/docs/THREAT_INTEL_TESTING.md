# Threat Intelligence Testing Guide


## 📋 Prerequisites

1. **API Keys Required:**
   - URLScan.io API key (free): https://urlscan.io/user/signup

2. **Tools Required:**
   - Python 3.8+
   - Docker (for Docker tests)
   - Doppler CLI (auto-installed by test script)

---

## 🚀 Quick Test (Automated)

The easiest way to test everything is to run the automated test script:

```bash
./test_threat_intel.sh
```

This script will:
1. ✅ Test with local environment variables
2. ✅ Set up and test Doppler secrets
3. ✅ Test Docker with environment variables
4. ✅ Test Docker with Doppler integration
5. ✅ Generate comprehensive results

**Follow the prompts** to enter your API keys and set up Doppler.

---

## 📖 Manual Step-by-Step Testing

If you prefer to test manually or understand each step:

### Step 1: Get Your API Keys

2. Create account → Profile → API Key
3. Copy your API key

**URLScan.io:**
1. Go to https://urlscan.io/user/signup
2. Create account → Profile → API Key
3. Copy your API key

---

### Step 2: Test with Environment Variables

This tests the simplest configuration method.

```bash
# Set your API keys as environment variables
export TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key_here"

# Run a test scan
python src/typo_sniper.py \
  -i test_domains.txt \
  --config test_config.yaml \
  --format excel json \
  -v
```

**What to check:**
- ✅ Scan completes without errors
- ✅ Results directory contains Excel and JSON files
- ✅ Excel file has threat intelligence columns
- ✅ Risk scores are calculated

**View results:**
```bash
ls -lh results/
```

---

### Step 3: Set Up Doppler

Now let's test production-grade secrets management.

#### Install Doppler CLI

```bash
curl -Ls https://cli.doppler.com/install.sh | sudo sh
```

#### Login to Doppler

```bash
doppler login
```

This will open your browser for authentication.

#### Create a Project

```bash
# Create a new project for Typo Sniper
doppler projects create typo-sniper

# Set up the project in your directory
doppler setup --project typo-sniper --config dev
```

#### Add Your Secrets

```bash

# Add URLScan.io API key
doppler secrets set URLSCAN_API_KEY="your_urlscan_key_here"

# Verify secrets are stored
doppler secrets
```

#### Test with Doppler

```bash
# Unset local environment variables to test Doppler
unset TYPO_SNIPER_URLSCAN_API_KEY

# Run scan with Doppler
doppler run -- python src/typo_sniper.py \
  -i test_domains.txt \
  --config test_config.yaml \
  --format excel json \
  -v
```

**What to check:**
- ✅ Scan runs without needing local env vars
- ✅ Doppler injects secrets automatically
- ✅ Results are identical to env var test
- ✅ Audit log in Doppler dashboard shows access

---

### Step 4: Test Docker with Environment Variables

Build and test the standard Docker image.

```bash
# Build Docker image
docker build -f docker/Dockerfile -t typo-sniper:test .

# Run scan in Docker
docker run --rm \
  -v "$(pwd)/test_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -e TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key" \
  typo-sniper:test \
  -i /app/data/domains.txt \
  --format excel json \
  -v
```

**What to check:**
- ✅ Docker build succeeds
- ✅ Scan runs in container
- ✅ Results appear in local results/ directory
- ✅ Threat intelligence data is present

---

### Step 5: Test Docker with Doppler

Build and test Doppler-enabled Docker image.

```bash
# Build Doppler-enabled image
docker build -f docker/Dockerfile.doppler -t typo-sniper:doppler .

# Create a service token for Docker
DOPPLER_TOKEN=$(doppler configs tokens create docker-prod --plain)

# Run scan with Doppler in Docker
docker run --rm \
  -v "$(pwd)/test_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -e DOPPLER_TOKEN="$DOPPLER_TOKEN" \
  typo-sniper:doppler \
  -i /app/data/domains.txt \
  --format excel json \
  -v
```

**What to check:**
- ✅ Doppler CLI is installed in container
- ✅ Secrets are fetched at runtime
- ✅ No secrets embedded in image
- ✅ Results identical to other methods

---

## 🔍 Verifying Results

### Check Excel Output

Open the Excel file in `results/` directory:

**Expected Sheets:**
1. **Summary** - Overview of all domains scanned
2. **Details** - Full results with threat intel columns:
   - `urlscan_verdict` - malicious/suspicious/clean
   - `cert_transparency_count` - Number of certificates
   - `http_status` - Active/inactive status
   - `risk_score` - 0-100 calculated risk
3. **Statistics** - Scan metrics and fuzzer distribution

**Color Coding:**
- 🔴 Red cells: High risk (70-100)
- 🟠 Orange cells: Medium risk (50-69)
- 🟡 Yellow cells: Low-medium risk (30-49)
- ⚪ White cells: Low risk (0-29)

### Check JSON Output

```bash
# View JSON results (formatted)
cat results/typo_sniper_results_*.json | jq '.'

# Check threat intelligence fields
cat results/typo_sniper_results_*.json | jq '.results[0].threat_intel'
```

**Expected Fields:**
```json
{
  "threat_intel": {
      "malicious": 0,
      "suspicious": 0,
      "harmless": 70,
      "last_analysis_date": "2025-10-21"
    },
    "urlscan": {
      "verdict": "clean",
      "scan_date": "2025-10-21"
    },
    "certificate_transparency": {
      "count": 5,
      "certificates": [...]
    },
    "http_probe": {
      "status_code": 200,
      "active": true
    },
    "risk_score": 15
  }
}
```

---

## 🧪 Testing Different Scenarios

### Test 1: Known Malicious Domain

```bash
echo "malicious-site.com" > malicious_test.txt
python src/typo_sniper.py -i malicious_test.txt --config test_config.yaml -v
```


### Test 2: Newly Registered Domain

```bash
echo "brand-new-domain-2025.com" > new_domain_test.txt
python src/typo_sniper.py -i new_domain_test.txt --config test_config.yaml -v
```

**Expected:** May have limited threat intel data

### Test 3: Rate Limiting Test

```bash
# Test with many domains to trigger API rate limits
python src/typo_sniper.py -i src/monitored_domains.txt --config test_config.yaml -v
```

**Expected:** Graceful handling of rate limits, retries

---

## 🐛 Troubleshooting

### Problem: "Invalid API key" error

**Solution:**
```bash
# Verify your API keys are set
echo $TYPO_SNIPER_URLSCAN_API_KEY

# Test keys directly
curl -H "API-Key: YOUR_URLSCAN_KEY" https://urlscan.io/api/v1/search/?q=domain:google.com
```

### Problem: Doppler not finding secrets

**Solution:**
```bash
# Check current Doppler config
doppler configure get

# Verify secrets exist
doppler secrets

# Re-setup if needed
doppler setup
```

### Problem: Docker can't find secrets

**Solution:**
```bash
# Verify token is valid
echo $DOPPLER_TOKEN | cut -c1-20

# Test token manually
docker run --rm -e DOPPLER_TOKEN="$DOPPLER_TOKEN" typo-sniper:doppler doppler secrets
```

### Problem: Rate limit errors

**Solution:**
```bash
# Reduce concurrent workers in test_config.yaml
max_workers: 2
rate_limit_delay: 2.0

# Or use rate limit delays
python src/typo_sniper.py --max-workers 2 --rate-limit-delay 2 -i test_domains.txt
```

---

## 📊 Performance Benchmarks

**Expected scan times with threat intelligence:**

| Domains | Workers | With Threat Intel | Without Threat Intel |
|---------|---------|-------------------|---------------------|
| 1       | 5       | ~30 seconds       | ~10 seconds         |
| 10      | 5       | ~3 minutes        | ~1 minute           |
| 50      | 5       | ~15 minutes       | ~5 minutes          |

**Rate Limits (Free Tier):**
- URLScan.io: 5,000 scans/month

---

## 🔐 Security Best Practices

### After Testing:

1. **Revoke test tokens:**
   ```bash
   doppler configs tokens revoke docker-test
   ```

2. **Clear cached API keys:**
   ```bash
   unset TYPO_SNIPER_URLSCAN_API_KEY
   ```

3. **Remove test files with keys:**
   ```bash
   rm -f test_config.yaml
   ```

4. **Check .gitignore:**
   ```bash
   cat .gitignore | grep -E "(config.yaml|.env)"
   ```

---

## ✅ Test Checklist

Use this checklist to verify all features:

- [ ] Environment variables work (local Python)
- [ ] Doppler secrets management works (local Python)
- [ ] Docker with env vars works
- [ ] Docker with Doppler works
- [ ] URLScan.io data appears in results
- [ ] Certificate Transparency data present
- [ ] HTTP probing shows active/inactive status
- [ ] Risk scores calculated (0-100)
- [ ] Excel color coding works (red/orange/yellow)
- [ ] JSON output has threat_intel fields
- [ ] Rate limiting handled gracefully
- [ ] Cache works (subsequent runs faster)
- [ ] Verbose logging shows API calls

---

## 🎉 Success Criteria

Your testing is successful if:

1. ✅ All four test methods complete without errors
2. ✅ Results contain threat intelligence data
3. ✅ Risk scores are calculated and color-coded
4. ✅ Doppler integration works seamlessly
5. ✅ Docker images run identically to local Python
6. ✅ No API keys are hardcoded or leaked

---

## 📞 Getting Help

If you encounter issues:

1. Check verbose logs: `-v` flag
2. Review TESTING.md for detailed troubleshooting
3. Check API key validity in provider dashboards
4. Verify Doppler project/config setup
5. Open an issue on GitHub with logs

---

## 🚀 Next Steps

After successful testing:

1. Set up production Doppler project
2. Configure scheduled scans (cron/systemd)
3. Set up monitoring/alerting
4. Deploy to production environment
5. Review and rotate API keys regularly
