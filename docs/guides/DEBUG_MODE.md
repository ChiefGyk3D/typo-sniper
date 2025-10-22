# Debug Mode Documentation

## Overview

Typo Sniper now includes a comprehensive `--debug` flag that provides detailed tracing and logging to help understand what the tool is doing internally.

## Usage

### Basic Usage

```bash
# Normal mode (WARNING level logging)
python3 src/typo_sniper.py -i domains.txt

# Verbose mode (INFO level logging)
python3 src/typo_sniper.py -i domains.txt --verbose

# Debug mode (DEBUG level logging with enhanced tracing)
python3 src/typo_sniper.py -i domains.txt --debug
```

## Logging Levels

1. **Normal Mode** (default)
   - Shows only warnings and errors
   - Minimal output for production use

2. **Verbose Mode** (`-v` or `--verbose`)
   - Shows INFO level messages
   - Displays scan progress and results
   - Good for understanding what's happening

3. **Debug Mode** (`--debug`)
   - Shows DEBUG level messages
   - Displays detailed internal operations
   - Shows why certain decisions are made
   - Traces enhanced detection logic
   - Useful for troubleshooting and development

## Debug Output Examples

### Enhanced Detection Debugging

When using `--debug`, the enhanced detection module will show:

```
DEBUG - Enhanced detection starting for: google.com
DEBUG -   - enable_combosquatting: False
DEBUG -   - enable_idn_homograph: False
DEBUG -   - enable_soundalike: False
DEBUG - Enhanced detection complete: 0 total variations
```

This clearly shows that enhanced detection is running, but all features are disabled in the config.

When features are enabled:

```
DEBUG - Enhanced detection starting for: google.com
DEBUG -   - enable_combosquatting: True
DEBUG -   - enable_idn_homograph: True
DEBUG -   - enable_soundalike: False
DEBUG -   Generated 336 combo-squatting variations
DEBUG -   Generated 32 IDN homograph variations
DEBUG - Enhanced detection complete: 368 total variations
```

### Scanner Debugging

The scanner module also provides debug output:

```
DEBUG - Calling enhanced detection for google.com...
DEBUG - Generating enhanced permutations for google.com...
DEBUG - No enhanced permutations generated for google.com
```

## Common Use Cases

### 1. Verify Enhanced Detection is Running

**Question:** "Is enhanced detection actually checking?"

**Answer:** Use `--debug` to see:
```bash
python3 src/typo_sniper.py -i test_domains.txt --debug 2>&1 | grep "Enhanced detection"
```

You'll see output like:
```
DEBUG - Enhanced detection starting for: example.com
DEBUG - Enhanced detection complete: 0 total variations
```

This confirms it's running, and the "0 total variations" is because features are disabled in config.

### 2. Troubleshoot Why No Results

**Question:** "Why am I getting 0 results from enhanced detection?"

**Answer:** Use `--debug` to see which features are enabled:
```bash
python3 src/typo_sniper.py -i test_domains.txt --debug 2>&1 | grep "enable_"
```

Output:
```
DEBUG -   - enable_combosquatting: False
DEBUG -   - enable_idn_homograph: False
DEBUG -   - enable_soundalike: False
```

All are `False`, so you need to enable them in your config file.

### 3. Monitor Performance

Use debug mode to see timing and performance details:
```bash
python3 src/typo_sniper.py -i test_domains.txt --debug
```

## Configuration

The debug mode is controlled by the `--debug` CLI flag, not by config files. This ensures debug output is only enabled when explicitly requested.

The debug mode flag is stored in `config.debug_mode` and can be accessed by any module to provide additional debug output.

## Implementation Details

### Adding Debug Logging to Your Module

To add debug logging to any module:

```python
import logging

logger = logging.getLogger(__name__)

def my_function(config):
    if hasattr(config, 'debug_mode') and config.debug_mode:
        logger.debug("Debug information here")
    
    # Regular code
    result = do_something()
    
    if hasattr(config, 'debug_mode') and config.debug_mode:
        logger.debug(f"Result: {result}")
    
    return result
```

### Best Practices

1. Use `logger.debug()` for debug-level messages
2. Check `config.debug_mode` before expensive debug operations
3. Provide context in debug messages (what module, what operation)
4. Show configuration values that affect behavior
5. Explain why certain code paths are taken

## Testing Debug Mode

A test script is provided to verify debug mode works correctly:

```bash
python3 test_debug_mode.py
```

This script demonstrates:
- Enhanced detection without debug mode
- Enhanced detection with debug mode (features disabled)
- Enhanced detection with debug mode (features enabled)

## See Also

- [TESTING.md](TESTING.md) - Testing documentation
- [THREAT_INTEL_TESTING.md](THREAT_INTEL_TESTING.md) - Threat intelligence testing
- [QUICKSTART.md](QUICKSTART.md) - Quick start guide
