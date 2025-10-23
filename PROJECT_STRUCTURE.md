# Typo Sniper - Project Structure

```
Typo Sniper/
├── .env.example                    # Environment variables template (copy to .env)
├── .gitignore                      # Git ignore rules
├── LICENSE                         # MIT License
├── README.md                       # Main project documentation
├── TESTING.md                      # Testing guide
├── requirements.txt                # Python dependencies
│
├── src/                            # Source code
│   ├── __init__.py
│   ├── cache.py                   # Caching system
│   ├── config.py                  # Configuration management
│   ├── exporters.py               # Export formats (JSON, Excel, CSV, HTML)
│   ├── scanner.py                 # Core scanning logic
│   ├── threat_intelligence.py     # URLScan.io, CT logs, HTTP probing
│   ├── typo_sniper.py            # Main CLI application
│   └── utils.py                   # Utility functions
│
├── docs/                           # Documentation
│   ├── README.md                  # Documentation index
│   ├── config.yaml.example        # Configuration template
│   └── guides/                    # User guides
│       ├── API_KEYS_SETUP.md
│       ├── DEBUG_IMPLEMENTATION.md
│       ├── DEBUG_MODE.md
│       ├── PERFORMANCE_OPTIMIZATION.md
│       ├── QUICKSTART.md
│       └── SECRETS_MANAGEMENT.md
│
├── tests/                          # Test suite
│   ├── README.md                  # Testing documentation
│   ├── __init__.py
│   ├── scripts/                   # Test scripts
│   │   ├── test_threat_intel.sh
│   │   ├── test_debug_mode.py
│   │   └── test_urlscan_api.py
│   ├── test_data/                 # Test inputs
│   │   ├── test_config.yaml
│   │   ├── test_domains.txt
│   │   ├── test_small.txt
│   │   └── test_google.txt
│   └── docs/                      # Test documentation
│       └── THREAT_INTEL_TESTING.md
│
├── scripts/                        # Utility scripts
│   └── setup_api_keys.sh          # API key setup helper
│
├── docker/                         # Docker configuration
│   ├── Dockerfile                 # Standard Docker image
│   ├── Dockerfile.doppler         # Doppler-enabled image
│   ├── docker-compose.yml         # Docker Compose config
│   └── DOCKER.md                  # Docker documentation
│
└── results/                        # Default output directory (gitignored)
    └── sample.*                   # Example outputs (tracked)
```

## Key Files

### Configuration
- **`.env`** - Your API keys (create from `.env.example`, gitignored)
- **`config.yaml.example`** - Full configuration template

### Entry Points
- **`src/typo_sniper.py`** - Main CLI application
- **`scripts/setup_api_keys.sh`** - Setup wizard for API keys

### Core Modules
- **`src/scanner.py`** - Domain scanning with dnstwist
- **`src/threat_intelligence.py`** - URLScan.io, Certificate Transparency, HTTP probing
- **`src/exporters.py`** - JSON, Excel, CSV, HTML output formats
- **`src/cache.py`** - WHOIS data caching

## Quick Start

```bash
# 1. Setup
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your URLScan.io API key

# 2. Run
python3 src/typo_sniper.py -i domains.txt -o results --format json excel

# 3. Test
cd tests/scripts
./test_threat_intel.sh
```

## Documentation

- **Getting Started**: `docs/guides/QUICKSTART.md`
- **API Keys**: `docs/guides/API_KEYS_SETUP.md`
- **Testing**: `tests/README.md`
- **Docker**: `docker/DOCKER.md`
