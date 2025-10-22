# Typo Sniper Testing

This directory contains all testing resources for Typo Sniper.

## Directory Structure

```
tests/
├── README.md                    # This file
├── __init__.py                  # Python package marker
├── scripts/                     # Test scripts
│   ├── test_threat_intel.sh    # Threat intelligence testing (URLScan.io + Doppler)
│   ├── test_debug_mode.py      # Debug mode testing
│   └── test_urlscan_api.py     # URLScan.io API testing
├── test_data/                   # Test input files and configs
│   ├── test_config.yaml        # Test configuration with all features enabled
│   ├── test_domains.txt        # Test domain list (google.com, amazon.com)
│   ├── test_small.txt          # Small test domain list (eff.org)
│   └── test_google.txt         # Single domain test (google.com)
└── docs/                        # Test documentation
    └── THREAT_INTEL_TESTING.md # Comprehensive threat intel testing guide
```

## Quick Test Commands

### Basic Scan Test
```bash
# From project root
python3 src/typo_sniper.py -i tests/test_data/test_small.txt -o test_output --format json excel csv html
```

### With Threat Intelligence (URLScan.io)
```bash
# Make sure TYPO_SNIPER_URLSCAN_API_KEY is set in .env
python3 src/typo_sniper.py \
  -i tests/test_data/test_small.txt \
  -o test_output \
  --config tests/test_data/test_config.yaml \
  --format json excel csv html
```

### Automated Threat Intel Testing
```bash
cd tests/scripts
./test_threat_intel.sh
```

## Test Data Files

- **test_small.txt**: Contains `eff.org` - generates ~70 permutations (good for quick tests)
- **test_domains.txt**: Contains `google.com` and `amazon.com` - generates 100+ permutations each
- **test_google.txt**: Contains only `google.com` - generates 300+ permutations

## Test Configuration

`test_data/test_config.yaml` has:
- ✅ URLScan.io enabled (30 req/min free tier)
- ✅ Certificate Transparency enabled
- ✅ HTTP probing enabled
- ✅ Risk scoring enabled
- ❌ Enhanced detection disabled (for speed)

## Running Tests

See individual test documentation:
- **Threat Intel Testing**: `docs/THREAT_INTEL_TESTING.md`
- **Main Testing Guide**: `../TESTING.md`

## Output

Test outputs are written to `test_output/` directory (gitignored).
