## Recommendations by Use Case
### Development / Testing
**Recommended:** Environment Variables or Config Files
```bash
export TYPO_SNIPER_VIRUSTOTAL_API_KEY="test_key"
python src/typo_sniper.py -i test.txt
```
### Production (General)
**Recommended:** Doppler
```bash
doppler run -- python src/typo_sniper.py -i domains.txt
```
### Production (AWS)
**Recommended:** AWS Secrets Manager
```bash
export AWS_SECRET_NAME="typo-sniper/prod"
python src/typo_sniper.py -i domains.txt
```

### CI/CD Pipelines
**Recommended:** Platform-native secrets (GitHub Secrets, GitLab CI/CD Variables, etc.) or Doppler

### Docker Deployments
**Recommended:** Environment variables (injected) or Doppler
```bash
docker run -e TYPO_SNIPER_VIRUSTOTAL_API_KEY="key" ...
# OR
docker run -e DOPPLER_TOKEN="token" ...
```

### Kubernetes
**Recommended:** Kubernetes Secrets + External Secrets Operator
```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: typo-sniper-secrets
spec:
  secretStoreRef:
    name: doppler-secret-store  # or aws-secret-store
    kind: SecretStore
```

## Security Best Practices
### General
1. ✅ Never commit secrets to version control
2. ✅ Rotate secrets regularly
3. ✅ Use principle of least privilege
4. ✅ Enable audit logging
5. ✅ Monitor secret access
6. ✅ Use different secrets per environment
### .gitignore Requirements
```gitignore
# Never commit these files
config.yaml
test_config.yaml
*_config.yaml
.env
.env.*
*.key
*.pem

# Except examples
!config.yaml.example
!.env.example
```

### Environment Variables
```bash
# ✅ DO: Use prefixed variables
export TYPO_SNIPER_VIRUSTOTAL_API_KEY="key"

# ❌ DON'T: Echo secrets
echo $TYPO_SNIPER_VIRUSTOTAL_API_KEY

# ✅ DO: Unset when done
unset TYPO_SNIPER_VIRUSTOTAL_API_KEY
```

### Config Files
```bash
# ✅ DO: Restrict permissions
chmod 600 config.yaml

# ✅ DO: Store outside repo
mkdir ~/.typo_sniper
mv config.yaml ~/.typo_sniper/

# ✅ DO: Encrypt sensitive configs
# Use tools like git-crypt, SOPS, or age
```

## Migration Guide
### From Config Files to Environment Variables
```bash
# Extract from config
VIRUSTOTAL_KEY=$(grep virustotal_api_key config.yaml | cut -d'"' -f2)
URLSCAN_KEY=$(grep urlscan_api_key config.yaml | cut -d'"' -f2)

# Set as env vars
export TYPO_SNIPER_VIRUSTOTAL_API_KEY="$VIRUSTOTAL_KEY"
export TYPO_SNIPER_URLSCAN_API_KEY="$URLSCAN_KEY"

# Remove from config
sed -i '/api_key/d' config.yaml
```

### From Environment Variables to Doppler
```bash
# Get current values
echo $TYPO_SNIPER_VIRUSTOTAL_API_KEY
echo $TYPO_SNIPER_URLSCAN_API_KEY

# Setup Doppler
doppler login
doppler setup

# Import to Doppler
doppler secrets set VIRUSTOTAL_API_KEY="$TYPO_SNIPER_VIRUSTOTAL_API_KEY"
doppler secrets set URLSCAN_API_KEY="$TYPO_SNIPER_URLSCAN_API_KEY"

# Unset env vars
unset TYPO_SNIPER_VIRUSTOTAL_API_KEY
unset TYPO_SNIPER_URLSCAN_API_KEY

# Run with Doppler
doppler run -- python src/typo_sniper.py -i domains.txt
```

### From Doppler to AWS Secrets Manager
```bash
# Export from Doppler
doppler secrets download --format json > secrets.json

# Import to AWS
aws secretsmanager create-secret \
  --name typo-sniper/prod \
  --secret-string file://secrets.json

# Clean up local file
shred -u secrets.json

# Update config
export AWS_SECRET_NAME="typo-sniper/prod"
```

## Troubleshooting
### Secret Not Found
```bash
# Check all possible sources
env | grep -i "VIRUSTOTAL\|URLSCAN\|DOPPLER\|AWS"

# Verify Doppler
doppler secrets

# Verify AWS
aws secretsmanager get-secret-value --secret-id typo-sniper/prod

# Run with verbose logging
python src/typo_sniper.py -i domains.txt -v 2>&1 | grep -i secret
```

### Permission Denied (AWS)
```bash
# Check IAM permissions
aws sts get-caller-identity
aws iam get-user

# Test secret access
aws secretsmanager get-secret-value --secret-id typo-sniper/prod

# If using IAM role, verify it's attached
```

### Doppler Token Invalid
```bash
# Check token
echo $DOPPLER_TOKEN

# Re-login
doppler login
doppler setup

# Create new service token
doppler configs tokens create prod-token --plain
```

## Additional Resources
## Summary
| Use Case | Recommendation | Setup Command |
|----------|----------------|---------------|
| Quick test | Environment Variables | `export TYPO_SNIPER_VIRUSTOTAL_API_KEY="key"` |
| Development | Config File + gitignore | `chmod 600 config.yaml` |
| Production | Doppler | `doppler run -- python src/typo_sniper.py` |
| AWS Production | AWS Secrets Manager | `export AWS_SECRET_NAME="typo-sniper/prod"` |
| Team Collaboration | Doppler | Setup team access in Doppler dashboard |
| CI/CD | Platform secrets + Doppler | Configure in CI/CD settings |
**Remember:** Never commit secrets to version control, always use the most secure option available for your environment, and rotate secrets regularly!
