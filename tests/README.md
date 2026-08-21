# Typo Sniper Testing

This directory contains the automated test suite and the manual/integration
scripts.

## Directory Structure

```
tests/
├── README.md                        # This file
├── __init__.py                      # Python package marker
├── conftest.py                      # Shared pytest fixtures and sys.path setup
│
├── unit/                            # Automated unit tests (no network access)
│   ├── test_cache.py                # WHOIS cache: TTL, corruption, stats
│   ├── test_config.py               # Config loading, path expansion, env vars
│   ├── test_enhanced_detection.py   # Combo-squat, soundex, IDN homographs
│   ├── test_exporters.py            # Report generation and output sanitisation
│   ├── test_risk_scoring.py         # Risk model weighting and clamping
│   ├── test_scanner_logic.py        # Dedup, recency, date filter, circuit breaker
│   ├── test_threat_intelligence.py  # CT parsing, title extraction, validation
│   └── test_utils.py                # Domain validation, DNS sentinels, escaping
│
├── scripts/                         # Manual scripts (require network + API keys)
│   ├── test_threat_intel.sh         # Threat intelligence smoke test
│   ├── test_debug_mode.py           # Debug mode walkthrough
│   └── test_urlscan_api.py          # URLScan.io API key check
│
├── test_data/                       # Test input files and configs
│   ├── test_config.yaml             # Config with threat intel enabled
│   ├── test_domains.txt             # google.com, amazon.com
│   ├── test_small.txt               # eff.org (fast: ~70 permutations)
│   └── test_google.txt              # google.com only
│
└── docs/
    └── THREAT_INTEL_TESTING.md      # Threat intel testing guide
```

## Running the Automated Tests

The unit tests make no network calls and run in about a second.

```bash
pip install -r requirements-dev.txt

# Run everything
pytest

# With coverage
pytest --cov=src --cov-report=term-missing

# A single file or test
pytest tests/unit/test_risk_scoring.py
pytest -k "sentinel"
```

Configuration lives in `pyproject.toml` (`[tool.pytest.ini_options]`), which
puts `src/` on the path — there is no need to set `PYTHONPATH` yourself.

## Linting

```bash
ruff check src/ tests/
```

Both commands run in CI on every push and pull request, across Python
3.10 through 3.13.

## Manual / Integration Testing

These need real network access, and some need an URLScan.io API key. They are
not run by CI.

### Basic scan

```bash
python3 src/typo_sniper.py -i tests/test_data/test_small.txt \
  -o test_output --format json excel csv html
```

### With threat intelligence

```bash
# Requires TYPO_SNIPER_URLSCAN_API_KEY in .env or the environment
python3 src/typo_sniper.py \
  -i tests/test_data/test_small.txt \
  -o test_output \
  --config tests/test_data/test_config.yaml \
  --format json excel csv html
```

### Scripted threat intel check

```bash
cd tests/scripts
./test_threat_intel.sh
```

## Test Data

| File | Contents | Scale |
|------|----------|-------|
| `test_small.txt` | `eff.org` | ~70 permutations — good for quick runs |
| `test_domains.txt` | `google.com`, `amazon.com` | 100+ each |
| `test_google.txt` | `google.com` | 300+ permutations |

## Notes on the Environment

WHOIS lookups use TCP port 43, which is blocked on many corporate networks and
in most CI sandboxes. When it is unreachable the scan still completes, but
registration dates and recency scoring are unavailable — the run prints an
explicit warning and the report records the WHOIS success/failure counts rather
than silently showing an empty column.

Output from the manual runs goes to `test_output/`, which is gitignored.
