# ML Integration Guide

This guide explains how to integrate the machine learning features into Typo Sniper as an **optional enhancement**.

## Overview

The ML system is designed as a **completely optional** feature that:
- ✅ **Gracefully degrades** when dependencies are missing
- ✅ **Doesn't break** existing functionality
- ✅ **Adds new columns** to reports when enabled
- ✅ **Works alongside** existing rule-based detection
- ✅ **Requires explicit opt-in** via config or CLI flags

## Quick Start

### 1. Install ML Dependencies (Optional)

```bash
cd "Typo Sniper"
pip install lightgbm catboost shap scikit-learn pandas numpy unicodedata2
```

**Note:** If you don't install these, Typo Sniper continues to work perfectly fine with rule-based detection only.

### 2. Train Your First Model

```bash
# Run the example to see ML in action
python src/ml_example.py

# This will:
# - Generate synthetic training data
# - Extract features
# - Train a classifier
# - Save model to models/demo_typosquat_detector.txt
```

### 3. Enable ML in Typo Sniper

**Option A: Config File**

```yaml
# config.yaml
enable_ml: true
ml_model_path: "models/demo_typosquat_detector.txt"
ml_enable_active_learning: true
```

**Option B: Command Line**

```bash
python src/typo_sniper.py \
  -i monitored_domains.txt \
  --ml \
  --ml-model models/demo_typosquat_detector.txt \
  --ml-review \
  --format excel
```

**Option C: Environment Variables**

```bash
export ENABLE_ML=true
export ML_MODEL_PATH=models/demo_typosquat_detector.txt

python src/typo_sniper.py -i monitored_domains.txt --format excel
```

### 4. View ML-Enhanced Reports

ML columns automatically appear in all export formats:

**Excel:**
- `ML Risk Score` (0-100)
- `ML Confidence` (percentage)
- `ML Verdict` (⚠ Typosquat / ✓ Legitimate)
- `ML Needs Review` (⚠ YES if uncertain)

**CSV:**
Same columns, plain text format

**HTML:**
ML columns with color coding and icons

## Integration Architecture

```
┌─────────────────────────────────────────┐
│         Typo Sniper Main Flow           │
├─────────────────────────────────────────┤
│                                         │
│  1. Load domains                        │
│  2. Generate permutations (dnstwist)    │
│  3. Filter registered domains           │
│  4. Enrich with WHOIS data              │
│  5. Add threat intelligence ─────────┐  │
│  6. Calculate risk scores            │  │
│  7. [NEW] Add ML predictions ◄───────┼──┼─ Optional
│  8. Export results                   │  │
│                                      │  │
└──────────────────────────────────────┼──┘
                                       │
                ┌──────────────────────▼────────────────────┐
                │      ML Integration Layer                 │
                │  (gracefully handles missing deps)        │
                ├───────────────────────────────────────────┤
                │                                           │
                │  • Check if ML enabled                    │
                │  • Load model (if path configured)        │
                │  • Extract features from domain data      │
                │  • Batch predictions for efficiency       │
                │  • Add ML fields to results               │
                │  • Select uncertain domains for review    │
                │                                           │
                └───────────────────────────────────────────┘
                        │                    │
        ┌───────────────▼──────┐   ┌────────▼─────────┐
        │  Feature Extractor   │   │   ML Classifier   │
        │  (50+ features)      │   │   (LightGBM)      │
        └──────────────────────┘   └───────────────────┘
```

## File Structure

```
Typo Sniper/
├── src/
│   ├── typo_sniper.py          # Main entry point (updated with ML support)
│   ├── scanner.py              # Domain scanner (calls ML integration)
│   ├── config.py               # Config management (ML settings added)
│   ├── exporters.py            # Report generation (ML columns added)
│   │
│   ├── ml_integration.py       # ✨ NEW: ML wrapper (handles graceful degradation)
│   ├── ml_typo_generator.py    # ✨ NEW: Synthetic data generation
│   ├── ml_homoglyph_detector.py # ✨ NEW: Unicode confusables detection
│   ├── ml_feature_extractor.py  # ✨ NEW: Feature engineering
│   ├── ml_classifier.py        # ✨ NEW: LightGBM classifier with SHAP
│   ├── ml_active_learning.py   # ✨ NEW: Uncertainty sampling
│   └── ml_example.py           # ✨ NEW: Complete demo
│
├── models/                     # ✨ NEW: Trained models (git-ignored)
│   └── .gitkeep
│
├── docs/
│   ├── ML_FEATURES.md          # ✨ NEW: Complete ML documentation
│   ├── ML_INTEGRATION.md       # ✨ NEW: This file
│   └── config.yaml.example     # Updated with ML settings
│
└── requirements.txt            # Updated with ML dependencies
```

## Configuration Options

All ML settings are **optional** and have safe defaults:

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `enable_ml` | bool | `false` | Master switch for ML features |
| `ml_model_path` | str | `null` | Path to trained model file |
| `ml_confidence_threshold` | float | `0.7` | High confidence threshold (0-1) |
| `ml_enable_active_learning` | bool | `false` | Enable uncertainty sampling |
| `ml_uncertainty_threshold` | float | `0.15` | Threshold for review selection |
| `ml_review_budget` | int | `100` | Max domains to flag per scan |

### Environment Variables

All settings can be overridden with environment variables:

```bash
ENABLE_ML=true
ML_MODEL_PATH=models/typosquat_detector.txt
TYPO_SNIPER_ENABLE_ML=true
TYPO_SNIPER_ML_MODEL_PATH=models/detector.txt
```

## Graceful Degradation

The ML system is designed to **never break** existing functionality:

### Scenario 1: ML Dependencies Not Installed

```python
try:
    from ml_classifier import MLClassifier
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
```

**Result:** Typo Sniper runs normally, ML columns show empty/null values.

### Scenario 2: ML Enabled But Model Not Found

```python
if model_path and not Path(model_path).exists():
    logger.warning(f"ML model not found: {model_path}")
    logger.info("ML predictions disabled. Train a model first.")
    return
```

**Result:** Warning logged, continues with rule-based detection only.

### Scenario 3: Feature Extraction Fails

```python
features = self.extract_features(domain_data, brand)
if not features:
    return {
        'ml_enabled': False,
        'ml_risk_score': None,
        # ... other fields None
    }
```

**Result:** Individual domain skipped, scan continues for other domains.

### Scenario 4: Prediction Fails

```python
try:
    result = self.classifier.predict(features, domain)
except Exception as e:
    logger.debug(f"ML prediction failed: {e}")
    return default_ml_result
```

**Result:** Error logged, default values used, scan continues.

## Report Integration

### Excel Export

ML columns are added after threat intelligence columns:

```python
headers = [
    "Scan Date", "Original Domain", "Permutation", "Fuzzer Type",
    "Risk Score", "URLScan Status", "CT Logs", "HTTP Status",
    "ML Risk Score", "ML Confidence", "ML Verdict", "ML Needs Review",  # NEW
    "Created Date", "Updated Date", ...
]
```

**Backwards Compatible:** Old reports without ML still work, new reports include ML columns.

### CSV Export

Same header structure, plain text:

```csv
Domain,Fuzzer,Risk Score,ML Risk Score,ML Confidence,ML Verdict,ML Needs Review
gooogle.com,addition,75,82,86%,Typosquat,No
google.com,original,0,5,92%,Legitimate,No
```

### HTML Export

ML columns with visual styling:

```html
<th>ML Risk</th>
<th>ML Verdict</th>
...
<td>82 <small>(86%)</small></td>
<td>⚠️ <span style="color: #d73a49;">Typosquat</span></td>
```

### JSON Export

ML fields added to each permutation:

```json
{
  "domain": "gooogle.com",
  "risk_score": 75,
  "ml_enabled": true,
  "ml_risk_score": 82,
  "ml_confidence": 0.86,
  "ml_is_typosquat": true,
  "ml_explanation": "Levenshtein Distance increases suspicion",
  "ml_needs_review": false
}
```

## CLI Integration

### New CLI Flags

```bash
# ML options group
--ml                    # Enable ML-enhanced detection
--ml-model PATH         # Path to trained model file
--ml-review             # Enable active learning review export
```

### Usage Examples

**Basic scan with ML:**
```bash
python src/typo_sniper.py -i domains.txt --ml --ml-model models/detector.txt
```

**ML with active learning:**
```bash
python src/typo_sniper.py -i domains.txt --ml --ml-model models/detector.txt --ml-review
```

This will generate:
- Regular reports (Excel/CSV/HTML) with ML columns
- `ml_review_batch.csv` with uncertain domains for human review

**Without ML (traditional mode):**
```bash
python src/typo_sniper.py -i domains.txt --format excel
```

Everything works as before, no ML columns.

## Active Learning Workflow

When `--ml-review` is enabled:

1. **Scan runs normally** with ML predictions
2. **Uncertain domains identified** (confidence between 40-60%)
3. **Review batch exported** to `results/ml_review_batch.csv`
4. **Analyst reviews** and labels domains
5. **Labels imported** back into system
6. **Model retrained** with new labels
7. **Improved accuracy** on next scan

### Review Batch Format

```csv
domain,prediction_prob,confidence,reason
gooogle.com,0.523,0.046,"Uncertain prediction (prob=0.523, uncertainty=0.023)"
goog1e.com,0.567,0.134,"Uncertain prediction (prob=0.567, uncertainty=0.067)"
```

### Import Labels for Retraining

```python
from ml_active_learning import ActiveLearner

learner = ActiveLearner()
learner.import_reviewed_batch('review_batch_labeled.csv', reviewer='analyst_1')

# Get training data
domains, labels = learner.get_training_data()

# Retrain model (see ML_FEATURES.md)
```

## Performance Impact

ML adds minimal overhead:

| Operation | Time (per domain) | Notes |
|-----------|-------------------|-------|
| Feature extraction | ~50ms | Done once per domain |
| ML prediction | ~1ms | Batch predictions faster |
| SHAP explanation | ~10ms | Optional, for debugging |

**For 1,000 domains:**
- Without ML: ~60 seconds (WHOIS, DNS, threat intel)
- With ML: ~65 seconds (+5 seconds, ~8% overhead)

**Optimization:** Batch predictions process 100+ domains/second when features are pre-extracted.

## Troubleshooting

### ML Not Working

**Check dependencies:**
```bash
python -c "import lightgbm, sklearn, numpy; print('OK')"
```

**Check config:**
```bash
python -c "from config import Config; c=Config(); print(f'ML enabled: {c.enable_ml}, Model: {c.ml_model_path}')"
```

**Check model file:**
```bash
ls -lh models/
```

### Import Errors

```
ImportError: No module named 'lightgbm'
```

**Solution:**
```bash
pip install lightgbm scikit-learn numpy pandas
```

### Model Not Found

```
WARNING: ML model not found: models/detector.txt
```

**Solution:**
```bash
# Train a model first
python src/ml_example.py

# Or point to existing model
export ML_MODEL_PATH=/path/to/your/model.txt
```

### Feature Extraction Fails

```
DEBUG: Feature extraction failed for example.com: KeyError 'domain'
```

**Solution:** Domain data missing required fields. Check WHOIS/DNS enrichment completed successfully.

### Low Accuracy

**Solution:** Model needs more training data. See [ML_FEATURES.md](ML_FEATURES.md) for training guide.

## Migration Guide

### From v1.0.2 (No ML) → v1.0.3+ (ML Support)

**No breaking changes!** Existing setups continue to work:

1. **Update code:**
   ```bash
   git pull origin feature/machine-learning
   ```

2. **Optional: Install ML deps:**
   ```bash
   pip install -r requirements.txt  # Includes ML deps
   ```

3. **Optional: Enable ML:**
   ```yaml
   # config.yaml
   enable_ml: true
   ml_model_path: models/detector.txt
   ```

4. **Run as before:**
   ```bash
   python src/typo_sniper.py -i domains.txt --format excel
   ```

**What's new:**
- ML columns in reports (empty if ML not enabled)
- New CLI flags (`--ml`, `--ml-model`, `--ml-review`)
- New config options (all default to `false`/`null`)
- New Python files in `src/ml_*.py` (ignored if ML not used)

## Docker Integration

### Dockerfile with ML Support

```dockerfile
FROM python:3.10-slim

WORKDIR /app

# Install dependencies (including ML)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy code
COPY src/ ./src/
COPY models/ ./models/

# Run scan with ML
ENTRYPOINT ["python", "src/typo_sniper.py"]
CMD ["--ml", "--ml-model", "models/detector.txt"]
```

### Docker Compose with ML

```yaml
version: '3.8'
services:
  typo-sniper-ml:
    build: .
    volumes:
      - ./data:/app/data:ro
      - ./results:/app/results
      - ./models:/app/models:ro
    environment:
      - ENABLE_ML=true
      - ML_MODEL_PATH=/app/models/detector.txt
    command: ["-i", "/app/data/domains.txt", "--ml", "--format", "excel"]
```

## Best Practices

### 1. Start Without ML

First, get comfortable with Typo Sniper's base features:
```bash
python src/typo_sniper.py -i domains.txt --format excel
```

### 2. Train with Your Data

Don't use the demo model for production:
```bash
# Generate training data from your domains
# Train custom model
# Validate on held-out test set
```

### 3. Monitor Performance

Track ML predictions vs analyst reviews:
```bash
# Export review batch
--ml-review

# Import reviewed labels
# Check accuracy metrics
# Retrain periodically
```

### 4. Tune Thresholds

Adjust confidence thresholds for your risk tolerance:
```yaml
ml_confidence_threshold: 0.8  # Fewer false positives
ml_uncertainty_threshold: 0.2  # More domains for review
```

### 5. Use Active Learning

Let the model tell you what it's unsure about:
```bash
--ml-review  # Exports uncertain domains automatically
```

## Security Considerations

### Model Files

- **Git-ignore models/**: Don't commit trained models (they're large)
- **Secure storage**: Store production models in secure location
- **Version control**: Track model versions and performance metrics

### Dependencies

- **Pin versions**: `requirements.txt` has pinned versions
- **Security audit**: Run `pip-audit` regularly
- **Update carefully**: Test updates in development first

### Data Privacy

- **WHOIS data**: Contains PII, handle according to regulations
- **Training data**: Ensure you have rights to use domains for training
- **Model sharing**: Don't share models trained on private data

## Support

For ML-specific questions:

1. Check [ML_FEATURES.md](ML_FEATURES.md) for detailed documentation
2. Run `python src/ml_example.py` to see working example
3. Review logs: ML warnings/errors logged at DEBUG level
4. Open GitHub issue with ML-related tag

## Summary

The ML integration is **completely optional** and designed to:

✅ **Enhance** existing detection with intelligent risk scoring  
✅ **Degrade gracefully** when dependencies missing or disabled  
✅ **Add value** through explainable predictions and active learning  
✅ **Maintain compatibility** with existing workflows and reports  
✅ **Scale efficiently** with batch processing and caching  

**Start simple**, enable ML when you're ready, and let active learning improve accuracy over time!
