# API Key Setup Guide

## Quick Setup (3 steps)

### 1. Create your .env file
```bash
cp .env.example .env
```

### 2. Edit .env with your API keys
```bash
nano .env
# or
vim .env
```

Replace the placeholder values with your actual API keys:
```bash
TYPO_SNIPER_URLSCAN_API_KEY=YOUR-ACTUAL-URLSCAN-KEY-HERE
```

### 3. Load the environment variables
```bash
# Option A: Source the .env file
set -a; source .env; set +a

# Option B: Export all variables
export $(grep -v '^#' .env | xargs)
```

## Getting Your API Keys

### URLScan.io
1. Sign up at https://urlscan.io/user/signup (free)
2. Go to your profile: https://urlscan.io/user/profile
3. Click the "API" tab
4. Copy your API key (UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)

## Testing Your Keys

### Automated Test
```bash
./setup_api_keys.sh
```

### Manual URLScan Test
```bash
# Load your .env first
set -a; source .env; set +a

# Run test
python3 test_urlscan_api.py
```

## Using API Keys with Typo Sniper

### Option 1: Environment Variables (Recommended)
```bash
# Load .env first (ensure ENABLE_URLSCAN=true is set for manual env vars)
set -a; source .env; set +a

# Then run Typo Sniper
python src/typo_sniper.py -i test_domains.txt --config test_config.yaml
```

### Option 2: Add to ~/.bashrc (Linux/macOS)
```bash
echo "export TYPO_SNIPER_URLSCAN_API_KEY='your-key-here'" >> ~/.bashrc
echo "export TYPO_SNIPER_ENABLE_URLSCAN=true" >> ~/.bashrc
```

Then reload:
```bash
source ~/.bashrc
```

### Option 3: Inline (not recommended for security)
```bash
TYPO_SNIPER_URLSCAN_API_KEY='your-key' \
TYPO_SNIPER_ENABLE_URLSCAN=true \
python src/typo_sniper.py -i test_domains.txt
```

## Verifying Keys are Loaded

Check if environment variables are set:
```bash
echo $TYPO_SNIPER_URLSCAN_API_KEY
echo $TYPO_SNIPER_ENABLE_URLSCAN
```

## Troubleshooting

### "URLScan API error" in logs
1. Check if key is set: `echo $TYPO_SNIPER_URLSCAN_API_KEY`
2. Test the key: `python3 test_urlscan_api.py`
3. Verify key at: https://urlscan.io/user/profile
4. Check rate limits (free tier: ~50 scans/day)

### Keys not loading from .env
Make sure to source the file:
```bash
set -a; source .env; set +a
```

Or export explicitly:
```bash
export $(grep -v '^#' .env | xargs)
```

### Permission denied on .env
```bash
chmod 600 .env  # Restrict to owner only (recommended)
```

## Security Best Practices

1. **Never commit .env to git** (already in .gitignore)
2. **Use restrictive permissions**: `chmod 600 .env`
3. **Rotate keys regularly** if compromised
4. **Use separate keys** for dev/prod environments
5. **Consider using secrets managers** (Doppler, AWS Secrets Manager) for production

## Alternative: Using Doppler (Production)

For production environments, consider using Doppler:
```bash
# Install Doppler CLI
curl -Ls --tlsv1.2 --proto "=https" --retry 3 https://cli.doppler.com/install.sh | sudo sh

# Login and setup
doppler login
doppler setup

# Add secrets (URLScan auto-enables with Doppler!)
doppler secrets set URLSCAN_API_KEY='your-key'

# Run with Doppler
doppler run -- python src/typo_sniper.py -i test_domains.txt
```

See [SECRETS_MANAGEMENT.md](SECRETS_MANAGEMENT.md) for more details.
