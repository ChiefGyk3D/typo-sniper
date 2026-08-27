# Typo Sniper Documentation

Comprehensive documentation for Typo Sniper.

## Quick Links

### Getting Started
- **[README.md](../README.md)** - Main project documentation
- **[QUICKSTART.md](guides/QUICKSTART.md)** - Get up and running in 5 minutes
- **[TESTING.md](../TESTING.md)** - Testing guide
- **[STATUS.md](STATUS.md)** - 🧪 What is verified, what needs your testing, what to report

### Guides
- **[API_KEYS_SETUP.md](guides/API_KEYS_SETUP.md)** - Setting up URLScan.io API keys
- **[SECRETS_MANAGEMENT.md](guides/SECRETS_MANAGEMENT.md)** - Doppler, AWS, Vault, Azure, GCP, 1Password
- **[AI_ANALYSIS.md](guides/AI_ANALYSIS.md)** - AI-assisted triage with Claude, OpenAI, Gemini, or Ollama
- **[ML_TRIAGE.md](guides/ML_TRIAGE.md)** - Learned ranking from your own triage decisions
- **[ALERTING.md](guides/ALERTING.md)** - Slack, Discord, Teams, Matrix, Jira, webhook, email
- **[infra/README.md](../infra/README.md)** - Terraform/OpenTofu for ECS Fargate and EKS
- **[DEBUG_MODE.md](guides/DEBUG_MODE.md)** - Debug mode usage
- **[DEBUG_IMPLEMENTATION.md](guides/DEBUG_IMPLEMENTATION.md)** - Debug system architecture
- **[PERFORMANCE_OPTIMIZATION.md](guides/PERFORMANCE_OPTIMIZATION.md)** - Performance tuning

### Configuration
- **[config.yaml.example](config.yaml.example)** - Full configuration example

## Directory Structure

```
docs/
├── README.md                           # This file
├── STATUS.md                           # Feature status and help wanted
├── config.yaml.example                 # Example configuration
└── guides/                             # User guides
    ├── API_KEYS_SETUP.md              # API key setup
    ├── DEBUG_IMPLEMENTATION.md         # Debug system details
    ├── DEBUG_MODE.md                   # Debug mode guide
    ├── PERFORMANCE_OPTIMIZATION.md     # Performance tuning
    ├── QUICKSTART.md                   # Quick start guide
    ├── SECRETS_MANAGEMENT.md           # Secrets management
    ├── AI_ANALYSIS.md                  # AI-assisted triage
    ├── ML_TRIAGE.md                    # Learned triage ranking
    └── ALERTING.md                     # Alerting, notifications, ticketing
```

## Documentation by Topic

### 🚀 Setup & Installation
1. [Quick Start Guide](guides/QUICKSTART.md)
2. [API Keys Setup](guides/API_KEYS_SETUP.md)
3. [Secrets Management](guides/SECRETS_MANAGEMENT.md)

### ⚙️ Configuration
1. [Configuration File](config.yaml.example)
2. [Performance Optimization](guides/PERFORMANCE_OPTIMIZATION.md)

### 🐛 Debugging & Development
1. [Debug Mode](guides/DEBUG_MODE.md)
2. [Debug Implementation](guides/DEBUG_IMPLEMENTATION.md)

### 🧪 Testing
1. [Main Testing Guide](../TESTING.md)
2. [Test Suite](../tests/README.md)

## Need Help?

Check the [Troubleshooting section](../README.md#-troubleshooting) in the main README.
