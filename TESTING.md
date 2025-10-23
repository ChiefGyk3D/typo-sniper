# Testing Guide for Threat Intelligence Features

This guide covers how to test Typo Sniper's threat intelligence integrations with URLScan.io and multiple secrets management options.

## Table of Contents

1. [Getting API Keys](#getting-api-keys)
2. [Testing with URLScan.io](#testing-with-urlscanio)
4. [Secrets Management Options](#secrets-management-options)
   - [Using Doppler](#using-doppler-secrets-manager)
   - [Using AWS Secrets Manager](#using-aws-secrets-manager)
   - [Using Environment Variables](#using-environment-variables)
5. [Testing with Docker](#testing-with-docker)
6. [Troubleshooting](#troubleshooting)

---

## Getting API Keys

### URLScan.io API Key

1. **Sign up for URLScan.io:**
   - Visit: https://urlscan.io/user/signup
   - Create a free account

2. **Get your API key:**
   - Go to: https://urlscan.io/user/profile
   - Navigate to "API" section
   - Copy your API key
   - **Free tier limits:** 5,000 scans/month, public submissions

3. **Example API key format:**
   ```
   a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6
   ```

---

## Testing with URLScan.io

### Method 1: Using Configuration File

1. **Create a test config file:**
   ```bash
   cp docs/config.yaml.example test_config_urlscan.yaml
   ```

2. **Edit `test_config_urlscan.yaml`:**
   ```yaml
   # Enable URLScan.io
   enable_urlscan: true
   urlscan_api_key: "YOUR_URLSCAN_API_KEY_HERE"
   
   # Enable risk scoring
   enable_risk_scoring: true
   
   # Optional: Enable HTTP probe to see which domains are active
   enable_http_probe: true
   http_timeout: 10
   
   # Limit workers for rate limiting
   max_workers: 10
   rate_limit_delay: 2.0
   ```

3. **Run the test:**
   ```bash
   python src/typo_sniper.py \
     -i test_domains_vt.txt \
     --config test_config_urlscan.yaml \
     --format excel json \
     -v
   ```

4. **Check results:**
   ```bash
   # View URLScan results
   cat results/typo_sniper_results_*.json | jq '.results[0].permutations[] | select(.threat_intel.urlscan) | {domain, urlscan: .threat_intel.urlscan}'
   ```

### Method 2: Using Environment Variables

```bash
export TYPO_SNIPER_URLSCAN_API_KEY="your_api_key_here"
python src/typo_sniper.py -i test_domains_vt.txt --config test_config_urlscan.yaml --format excel -v
```

---

## Full Threat Intelligence Configuration

### Complete Test Configuration

```yaml
# Enable threat intelligence features
enable_urlscan: true
urlscan_api_key: "YOUR_URLSCAN_KEY"

enable_certificate_transparency: true
enable_http_probe: true
http_timeout: 10

# Enable enhanced detection
enable_combosquatting: true
enable_soundalike: true
enable_idn_homograph: true

# Enable risk scoring
enable_risk_scoring: true

# Rate limiting for API calls
max_workers: 10
rate_limit_delay: 2.0
```

### Run Full Test

```bash
python src/typo_sniper.py \
  -i test_domains_vt.txt \
  --config test_config_full.yaml \
  --format excel json html \
  -v
```

---

## Using Doppler Secrets Manager

Doppler provides secure secrets management without storing API keys in config files.

### Install Doppler CLI

```bash
# macOS
brew install dopplerhq/cli/doppler

# Linux
(curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh || wget -t 3 -qO- https://cli.doppler.com/install.sh) | sudo sh

# Verify installation
doppler --version
```

### Setup Doppler for Typo Sniper

1. **Login to Doppler:**
   ```bash
   doppler login
   ```

2. **Create a Doppler project:**
   ```bash
   doppler projects create typo-sniper
   ```

3. **Setup the project:**
   ```bash
   cd "/home/chiefgyk3d/src/Typo Sniper"
   doppler setup
   # Select: typo-sniper project
   # Select: dev environment (or create one)
   ```

4. **Add your secrets:**
   ```bash
   # Add URLScan.io API key
   doppler secrets set URLSCAN_API_KEY="your_urlscan_key"
   
   # Verify secrets
   doppler secrets
   ```

5. **Run with Doppler:**
   ```bash
   # Doppler will inject secrets as environment variables
   doppler run -- python src/typo_sniper.py \
     -i test_domains_vt.txt \
     --config test_config.yaml \
     --format excel \
     -v
   ```

### Doppler with Docker

1. **Get Doppler service token:**
   ```bash
   doppler configs tokens create docker-token --plain
   # Copy the token output
   ```

2. **Run Docker with Doppler:**
   ```bash
   docker run --rm \
     -e DOPPLER_TOKEN="dp.st.dev.xxxxxxxxxxxx" \
     -v "$(pwd)/test_domains_vt.txt:/app/data/test.txt:ro" \
     -v "$(pwd)/results:/app/results" \
     -v "$(pwd)/test_config.yaml:/app/config.yaml:ro" \
     typo-sniper:enhanced \
     -i /app/data/test.txt \
     --config /app/config.yaml \
     --format excel -v
   ```

3. **Update Dockerfile to support Doppler (optional):**
   ```dockerfile
   # Install Doppler CLI in Docker
   RUN apt-get update && \
       apt-get install -y curl gnupg && \
       curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh | sh && \
       rm -rf /var/lib/apt/lists/*
   
   # Entrypoint with Doppler support
   ENTRYPOINT ["sh", "-c", "if [ -n \"$DOPPLER_TOKEN\" ]; then doppler run -- python typo_sniper.py \"$@\"; else python typo_sniper.py \"$@\"; fi", "sh"]
   ```

### Environment Variables Priority

The system checks for API keys in this order:

1. **Doppler** (if `DOPPLER_TOKEN` is set)
2. **AWS Secrets Manager** (if `AWS_SECRET_NAME` is set)

---

## Using AWS Secrets Manager

AWS Secrets Manager provides secure, centralized secrets management for AWS environments.

### Prerequisites

```bash
# Install AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Configure AWS credentials
aws configure
# Enter your: Access Key ID, Secret Access Key, Region, Output format
```

### Install boto3 (if not already installed)

```bash
# Uncomment boto3 in requirements.txt
sed -i 's/# boto3/boto3/' requirements.txt
sed -i 's/# botocore/botocore/' requirements.txt

# Install
pip install boto3 botocore
```

### Setup AWS Secret

1. **Create a secret in AWS Secrets Manager:**
   ```bash
   # Using AWS CLI
   aws secretsmanager create-secret \
     --name typo-sniper/prod \
     --description "API keys for Typo Sniper" \
     --secret-string '{
       "urlscan_api_key": "your_urlscan_key_here"
     }'
   ```

2. **Or use the AWS Console:**
   - Go to: https://console.aws.amazon.com/secretsmanager/
   - Click "Store a new secret"
   - Select "Other type of secret"
   - Add key-value pairs:
     - `urlscan_api_key` = your key
   - Name it: `typo-sniper/prod`
   - Click "Store"

3. **Verify the secret:**
   ```bash
   aws secretsmanager get-secret-value --secret-id typo-sniper/prod
   ```

### Configure Typo Sniper for AWS

1. **Using environment variable:**
   ```bash
   export AWS_SECRET_NAME="typo-sniper/prod"
   # Or
   export TYPO_SNIPER_USE_AWS_SECRETS=true
   export TYPO_SNIPER_AWS_SECRET_NAME="typo-sniper/prod"
   ```

2. **Using config file:**
   ```yaml
   # Add to config.yaml
   use_aws_secrets: true
   aws_secret_name: "typo-sniper/prod"
   
   # Enable features
   enable_urlscan: true
   enable_risk_scoring: true
   ```

### Run with AWS Secrets Manager

```bash
# Set AWS secret name
export AWS_SECRET_NAME="typo-sniper/prod"

# Run Typo Sniper (API keys loaded automatically)
python src/typo_sniper.py \
  -i test_domains.txt \
  --format excel json \
  -v
```

### AWS with Docker

1. **Pass AWS credentials to Docker:**
   ```bash
   docker run --rm \
     -e AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
     -e AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
     -e AWS_DEFAULT_REGION="$AWS_DEFAULT_REGION" \
     -e AWS_SECRET_NAME="typo-sniper/prod" \
     -v "$(pwd)/test_domains.txt:/app/data/test.txt:ro" \
     -v "$(pwd)/results:/app/results" \
     typo-sniper:threat-intel \
     -i /app/data/test.txt \
     --format excel -v
   ```

2. **Or use IAM roles (recommended for EC2/ECS):**
   ```bash
   # No credentials needed if running on EC2/ECS with IAM role
   docker run --rm \
     -e AWS_SECRET_NAME="typo-sniper/prod" \
     -v "$(pwd)/test_domains.txt:/app/data/test.txt:ro" \
     -v "$(pwd)/results:/app/results" \
     typo-sniper:threat-intel \
     -i /app/data/test.txt \
     --format excel -v
   ```

### AWS Secrets Manager Best Practices

1. **Use IAM roles** instead of access keys when possible
2. **Enable secret rotation** for production
3. **Use resource-based policies** to restrict access
4. **Enable CloudTrail logging** for audit trails
5. **Tag secrets** for organization and billing
6. **Use VPC endpoints** for enhanced security

### AWS Secret Rotation Example

```bash
# Enable automatic rotation (optional)
aws secretsmanager rotate-secret \
  --secret-id typo-sniper/prod \
  --rotation-lambda-arn arn:aws:lambda:region:account:function:rotation-function \
  --rotation-rules AutomaticallyAfterDays=30
```

### AWS Pricing

- **$0.40 per secret per month**
- **$0.05 per 10,000 API calls**
- Free tier: First 30 days
- Estimated cost for 1 secret: ~$0.50/month

---

## Using Environment Variables

For quick testing or simple deployments:

```bash
# Set variables
export TYPO_SNIPER_URLSCAN_API_KEY="your_key"
export TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key"

# Run
python src/typo_sniper.py -i test.txt --format excel -v
```

**Security Note:** Environment variables may be visible in process lists. Use secrets managers for production.

---

## Testing with Docker

### Build Docker Image

```bash
cd "/home/chiefgyk3d/src/Typo Sniper"
docker build -f docker/Dockerfile -t typo-sniper:threat-intel .
```

### Test with Environment Variables

```bash
docker run --rm \
  -e TYPO_SNIPER_URLSCAN_API_KEY="your_key" \
  -e TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key" \
  -v "$(pwd)/test_domains_vt.txt:/app/data/test.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -v "$(pwd)/test_config.yaml:/app/config.yaml:ro" \
  typo-sniper:threat-intel \
  -i /app/data/test.txt \
  --config /app/config.yaml \
  --format excel json \
  -v
```

### Test with Docker Compose

1. **Create `docker-compose.threat-intel.yml`:**
   ```yaml
   version: '3.8'
   
   services:
     typo-sniper:
       build:
         context: .
         dockerfile: docker/Dockerfile
       image: typo-sniper:threat-intel
       volumes:
         - ./test_domains_vt.txt:/app/data/test.txt:ro
         - ./results:/app/results
         - ./test_config.yaml:/app/config.yaml:ro
       environment:
         - TYPO_SNIPER_URLSCAN_API_KEY=${URLSCAN_API_KEY}
       command: ["-i", "/app/data/test.txt", "--config", "/app/config.yaml", "--format", "excel", "json", "-v"]
   ```

2. **Create `.env` file:**
   ```bash
   cat > .env << EOF
   URLSCAN_API_KEY=your_urlscan_key_here
   EOF
   
   # Secure the .env file
   chmod 600 .env
   ```

3. **Run with Docker Compose:**
   ```bash
   docker-compose -f docker-compose.threat-intel.yml up
   ```

---

## Troubleshooting

### URLScan.io Issues

**Problem:** "Submission limit reached"
```
Solution:
- Check your monthly quota (5,000 scans/month on free tier)
- Consider upgrading to paid plan
- Use cached results when re-scanning
```

**Problem:** "Private scans not available"
```
Solution:
- Free tier only allows public submissions
- Your scans will be visible on URLScan.io
- Upgrade to paid plan for private scans
```

**Problem:** "Scan timeout"
```
Solution:
- URLScan.io can take 30+ seconds per domain
- This is normal - the tool will wait automatically
- Consider testing with fewer domains initially
```

### Doppler Issues

**Problem:** "doppler: command not found"
```
Solution:
- Install Doppler CLI: https://docs.doppler.com/docs/install-cli
- Restart your terminal after installation
- Verify: doppler --version
```

**Problem:** "DOPPLER_TOKEN invalid"
```
Solution:
- Generate new service token: doppler configs tokens create
- Ensure token starts with "dp.st."
- Check token hasn't expired
```

**Problem:** "Secrets not being injected"
```
Solution:
- Run with doppler run -- your_command
- Check secrets are set: doppler secrets
- Verify correct project/config: doppler setup
```

### General Issues

**Problem:** "No threat intelligence data in results"
```
Solution:
1. Check if features are enabled in config
2. Verify API keys are set correctly
3. Run with -v flag to see debug logs
4. Check network connectivity
5. Review rate limits and quotas
```

**Problem:** "All API calls failing"
```
Solution:
1. Check internet connectivity
2. Verify firewall isn't blocking API calls
3. Check DNS resolution
4. Try curl/wget to API endpoints manually
5. Review proxy settings if applicable
```

---

## Example Test Workflow

Here's a complete workflow to test all features:

```bash
# 1. Setup
cd "/home/chiefgyk3d/src/Typo Sniper"

# 2. Create test configuration
cat > test_threat_intel.yaml << EOF
enable_urlscan: true
enable_certificate_transparency: true
enable_http_probe: true
enable_risk_scoring: true
enable_combosquatting: true
enable_soundalike: true
enable_idn_homograph: true
max_workers: 4
rate_limit_delay: 15.0
output_dir: results
EOF

# 3. Set environment variables (or use Doppler)
export TYPO_SNIPER_URLSCAN_API_KEY="your_key"
export TYPO_SNIPER_URLSCAN_API_KEY="your_urlscan_key"

# 4. Create test domains
echo "example.com" > test_small.txt

# 5. Run test
python src/typo_sniper.py \
  -i test_small.txt \
  --config test_threat_intel.yaml \
  --format excel json html \
  -v

# 6. Check results
ls -lh results/
cat results/typo_sniper_results_*.json | jq '.results[0].permutations[0]'

# 7. Review Excel with color-coded risk scores
xdg-open results/typo_sniper_results_*.xlsx
```

---

## API Cost Calculator

Estimate API costs for your scans:

- Limit: 4 requests/minute, 500/day
- For 100 domains: ~25 minutes scan time
- For 500 domains: Max daily limit reached

**URLScan.io (Free Tier):**
- Limit: 5,000 scans/month
- For 100 domains: 2% of monthly quota
- For 1,000 domains: 20% of monthly quota

**Recommendations:**
1. Start with small test sets (10-20 domains)
2. Enable caching to avoid repeat API calls
3. Use filters (months_filter) to reduce domain count
4. Consider paid plans for production use

---

## Best Practices

1. **Never commit API keys to git:**
   ```bash
   # Add to .gitignore
   echo "test_config.yaml" >> .gitignore
   echo "test_*.yaml" >> .gitignore
   echo ".env" >> .gitignore
   ```

2. **Use Doppler for production:**
   - Secure secrets storage
   - Automatic rotation
   - Audit logs
   - Team access control

3. **Start small:**
   - Test with 1-5 domains first
   - Verify API keys work
   - Check rate limits
   - Scale up gradually

4. **Monitor usage:**
   - Track API quota usage
   - Set up alerts for limits
   - Review costs regularly

5. **Cache results:**
   - Enable caching (default: on)
   - Set appropriate TTL (default: 24h)
   - Reduces API calls on re-scans

---

## Support

For issues or questions:
- **URLScan.io:** https://urlscan.io/about/
- **Doppler:** https://docs.doppler.com/
- **Typo Sniper:** Check README.md and ENHANCEMENTS.md
