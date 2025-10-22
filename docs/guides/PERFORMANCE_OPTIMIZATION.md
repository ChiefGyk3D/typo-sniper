# Performance Optimization Guide

## The Problem

The enhanced typosquatting detection features were **enabled by default**, causing scans to take significantly longer than expected. Here's why:

### Enhanced Detection Performance Impact

| Feature | Variations Generated | DNS Lookups | Impact |
|---------|---------------------|-------------|---------|
| **Combo-squatting** | ~360+ per domain | 360+ | 🔴 **SEVERE** |
| **IDN Homograph** | Up to 50 per domain | 50 | 🟡 **MODERATE** |
| **Sound-alike** | Variable | Minimal | 🟢 **LOW** |

**Example:** Scanning 1 domain with both enabled = **410+ extra DNS lookups**
Scanning 5 domains = **2,050+ extra DNS lookups** 😱

## What We Fixed

### 1. Changed Defaults to Disabled

**Before:**
```python
enable_combosquatting: bool = True   # ❌ Always on
enable_soundalike: bool = True       # ❌ Always on
enable_idn_homograph: bool = True    # ❌ Always on
```

**After:**
```python
enable_combosquatting: bool = False  # ✅ Opt-in only
enable_soundalike: bool = False      # ✅ Opt-in only
enable_idn_homograph: bool = False   # ✅ Opt-in only
```

### 2. Made DNS Checks Asynchronous

**Before:** Sequential DNS lookups (blocking)
```python
for domain in enhanced_domains:
    socket.gethostbyname(domain)  # ❌ Blocks for each lookup
```

**After:** Concurrent DNS lookups (async)
```python
tasks = [self._check_dns_async(domain) for domain in enhanced_domains]
results = await asyncio.gather(*tasks)  # ✅ All at once!
```

### 3. Added Early Exit

**New optimization:**
```python
if not any([self.config.enable_combosquatting, self.config.enable_idn_homograph]):
    return []  # ✅ Skip entirely if disabled
```

### 4. Updated Documentation

- Added performance warnings to all config files
- Updated README with optimization tips
- Clarified variation counts in docs

## Performance Comparison

### Basic Scan (Enhanced Detection OFF)
- **1 domain**: ~1-2 minutes
- **5 domains**: ~5-8 minutes
- **Variations checked**: ~50-200 per domain (dnstwist only)

### Full Scan (Enhanced Detection ON)
- **1 domain**: ~5-10 minutes ⚠️
- **5 domains**: ~25-50+ minutes ⚠️⚠️
- **Variations checked**: ~400-600 per domain

## Recommendations

### For Routine Monitoring
Keep enhanced detection **DISABLED** (default):
```yaml
enable_combosquatting: false
enable_soundalike: false
enable_idn_homograph: false
```

### For Deep Investigation
Enable selectively:
```yaml
# Only enable what you need!
enable_combosquatting: true   # If investigating phishing with brand keywords
enable_idn_homograph: true    # If investigating Unicode attacks
enable_soundalike: false      # Usually not needed
```

### For Maximum Speed
```bash
# Increase workers (if you have bandwidth)
python src/typo_sniper.py --max-workers 20 -i domains.txt

# Use cache
python src/typo_sniper.py --cache-ttl 604800 -i domains.txt

# Filter results to reduce noise
python src/typo_sniper.py --months 6 -i domains.txt
```

## When to Enable Enhanced Detection

### ✅ Enable Combo-squatting when:
- Investigating phishing campaigns
- Brand is commonly paired with keywords ("apple-login", "google-secure", etc.)
- High-value brand protection
- You have time for a deeper scan

### ✅ Enable IDN Homograph when:
- Target audience uses internationalized domains
- Investigating sophisticated attacks
- Compliance requires Unicode threat detection
- Previous incidents with IDN attacks

### ✅ Enable Sound-alike when:
- Brand name has common phonetic variants
- Investigating phone-based social engineering
- Verbal brand confusion is a risk

## Configuration Examples

### Fast Routine Scan (Recommended)
```yaml
# config.yaml
max_workers: 10
enable_combosquatting: false
enable_soundalike: false
enable_idn_homograph: false
enable_virustotal: false      # Optional unless you have API key
enable_urlscan: false          # Optional unless you have API key
```

### Deep Investigation Scan
```yaml
# config-deep.yaml
max_workers: 5                 # Lower to respect API limits
rate_limit_delay: 2.0          # Slower but thorough
enable_combosquatting: true    # Full detection
enable_idn_homograph: true     # Full detection
enable_soundalike: false       # Usually adds noise
enable_virustotal: true        # With API key
enable_urlscan: true           # With API key
```

### Testing Scan (Minimal)
```yaml
# config-test.yaml
max_workers: 3
enable_combosquatting: false
enable_soundalike: false
enable_idn_homograph: false
enable_virustotal: false
enable_urlscan: false
dnstwist_mxcheck: false        # Skip MX checks for speed
```

## Migration Guide

If you have an existing config file with enhanced detection enabled:

1. **Backup your config:**
   ```bash
   cp config.yaml config.yaml.backup
   ```

2. **Update settings:**
   ```bash
   # Edit config.yaml and set:
   enable_combosquatting: false
   enable_soundalike: false
   enable_idn_homograph: false
   ```

3. **Test performance:**
   ```bash
   time python src/typo_sniper.py -i test_domains.txt --config config.yaml
   ```

4. **Compare results:**
   - Basic scan should complete in 1-3 minutes per domain
   - If still slow, check thread count and API rate limits

## Troubleshooting

### "Scan is still slow"
1. Check if threat intelligence APIs are causing delays
2. Reduce `max_workers` if hitting rate limits
3. Increase `rate_limit_delay` to space out requests
4. Disable `dnstwist_mxcheck` if you don't need MX records

### "I need enhanced detection but it's too slow"
1. Use enhanced detection for specific high-priority domains only
2. Run enhanced scans during off-hours
3. Consider running basic scan first, then enhanced scan on suspicious results
4. Use caching to speed up re-scans

### "Results look different now"
- This is expected! Enhanced detection finds **additional** variations
- Basic scan still finds all standard typosquatting patterns
- Enable enhanced features only when needed for specific investigations

## Summary

**Default behavior now favors speed over exhaustiveness:**
- ✅ Fast routine scans (1-3 min/domain)
- ✅ Opt-in for deep scanning when needed
- ✅ Clear documentation on performance impact
- ✅ Async optimizations for enabled features

**The enhanced detection features are still available** - they're just not slowing down every scan anymore!
