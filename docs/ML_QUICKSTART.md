# ML Quick Start Guide

Get started with ML-enhanced typosquatting detection in 5 minutes!

## Prerequisites

- Typo Sniper installed and working
- Python 3.8+
- Basic understanding of command line

## Step 1: Install ML Dependencies (2 minutes)

```bash
cd "Typo Sniper"
pip install lightgbm scikit-learn numpy pandas shap unicodedata2
```

**Verification:**
```bash
python -c "import lightgbm, sklearn, numpy; print('✓ ML dependencies installed')"
```

## Step 2: Train Demo Model (1 minute)

```bash
python src/ml_example.py
```

**Output:**
```
=== ML-Enhanced Typosquatting Detection - Complete Demo ===

Generating Training Data ===
Generated 255 total domains:
  Legitimate: 5
  Typosquats: 250

=== Extracting Features ===
Extracted 50+ features per domain

=== Training ML Classifier ===
Training set: 204 samples
Validation set: 51 samples

Model Performance:
Accuracy:        0.902
Precision:       0.912
Recall:          0.895
F1 Score:        0.903

Saving model to: models/demo_typosquat_detector.txt
✓ Model saved successfully
```

**Model created:** `models/demo_typosquat_detector.txt`

## Step 3: Run ML-Enhanced Scan (1 minute)

```bash
python src/typo_sniper.py \
  -i src/monitored_domains.txt \
  --ml \
  --ml-model models/demo_typosquat_detector.txt \
  --format excel
```

**Output:**
```
🎯 Typo Sniper 1.0 - Typosquatting Detector

Domains to scan: 1
Output formats: excel
Cache enabled: Yes

ML classifier loaded from: models/demo_typosquat_detector.txt

Scanning domain example.com...
Found 50 registered permutations

Adding ML predictions for 50 domains
ML predictions: 50 processed, 35 flagged as typosquats, 8 need review

Exporting results...
Exported Excel file: results/typo_sniper_2024-10-23_141532.xlsx

✓ Scan completed successfully!
```

## Step 4: View ML Results (30 seconds)

Open the Excel file:

```bash
open results/typo_sniper_*.xlsx  # macOS
xdg-open results/typo_sniper_*.xlsx  # Linux
start results/typo_sniper_*.xlsx  # Windows
```

**New columns:**
- `ML Risk Score` (0-100)
- `ML Confidence` (percentage)
- `ML Verdict` (⚠ Typosquat / ✓ Legitimate)
- `ML Needs Review` (⚠ YES if uncertain)

## Step 5: Enable Active Learning (Optional)

Export uncertain domains for human review:

```bash
python src/typo_sniper.py \
  -i src/monitored_domains.txt \
  --ml \
  --ml-model models/demo_typosquat_detector.txt \
  --ml-review \
  --format excel
```

**Output:**
```
📋 ML review batch exported: results/ml_review_batch.csv
```

**Review file format:**
```csv
domain,ml_risk_score,ml_confidence,reason
gooogle.com,52,4.6%,"Uncertain prediction (prob=0.523)"
goog1e.com,57,13.4%,"Uncertain prediction (prob=0.567)"
```

## Configuration (Persistent Setup)

Instead of CLI flags every time, use config file:

### config.yaml
```yaml
# Enable ML permanently
enable_ml: true
ml_model_path: "models/demo_typosquat_detector.txt"
ml_enable_active_learning: true
ml_confidence_threshold: 0.7
ml_uncertainty_threshold: 0.15
ml_review_budget: 100
```

Now just run:
```bash
python src/typo_sniper.py -i domains.txt --format excel
# ML automatically enabled via config
```

## Environment Variables (CI/CD)

For automation and CI/CD:

```bash
export ENABLE_ML=true
export ML_MODEL_PATH=models/demo_typosquat_detector.txt

python src/typo_sniper.py -i domains.txt --format excel
```

## Docker Integration

### Build with ML Support
```bash
docker build -f docker/Dockerfile -t typo-sniper-ml:latest .
```

### Run with ML
```bash
docker run --rm \
  -v "$(pwd)/src/monitored_domains.txt:/app/data/domains.txt:ro" \
  -v "$(pwd)/results:/app/results" \
  -v "$(pwd)/models:/app/models:ro" \
  -e ENABLE_ML=true \
  -e ML_MODEL_PATH=/app/models/demo_typosquat_detector.txt \
  typo-sniper-ml:latest \
  -i /app/data/domains.txt --ml --format excel
```

## Troubleshooting

### Issue: "ML dependencies not installed"

**Solution:**
```bash
pip install lightgbm scikit-learn numpy pandas shap
```

### Issue: "ML model not found"

**Solution:**
```bash
# Check model exists
ls -lh models/demo_typosquat_detector.txt

# Or train new model
python src/ml_example.py
```

### Issue: "ML predictions all empty"

**Solution:**
Check that ML is actually enabled:

```bash
# Verify config
python -c "from config import Config; c=Config(); print(f'ML: {c.enable_ml}, Model: {c.ml_model_path}')"

# Or explicitly enable
python src/typo_sniper.py -i domains.txt --ml --ml-model models/demo_typosquat_detector.txt
```

### Issue: "Low accuracy / many false positives"

**Solution:**
The demo model is trained on synthetic data. Train a custom model with your real data:

1. Collect labeled examples (typosquats + legitimate domains)
2. Extract features: `ml_feature_extractor.py`
3. Train classifier: `ml_classifier.py`
4. Evaluate on test set
5. Tune thresholds

See [ML_FEATURES.md](ML_FEATURES.md) for detailed training guide.

## What's Next?

### Learn More
- 📖 [Complete ML Guide](ML_FEATURES.md) - Architecture, training, features
- 🔧 [Integration Guide](ML_INTEGRATION.md) - How it works, configuration
- 📊 [Integration Summary](ML_INTEGRATION_SUMMARY.md) - What changed

### Improve Accuracy
1. **Collect real data** - Labeled examples from your domains
2. **Train custom model** - Use your data instead of demo
3. **Tune thresholds** - Adjust for your risk tolerance
4. **Active learning** - Let model identify uncertain cases

### Production Deployment
1. **Version models** - Track performance over time
2. **Monitor metrics** - Precision, recall, false positive rate
3. **Retrain regularly** - Keep model up-to-date
4. **Secure storage** - Store models safely

## Key Takeaways

✅ ML is **optional** - works without it  
✅ ML is **additive** - enhances existing detection  
✅ ML is **explainable** - see why domains flagged  
✅ ML **improves over time** - active learning loop  
✅ ML is **production-ready** - error handling, logging  

## Support

Questions? Check:
1. This quick start guide
2. [ML_FEATURES.md](ML_FEATURES.md) - Detailed docs
3. [ML_INTEGRATION.md](ML_INTEGRATION.md) - How it works
4. `python src/ml_example.py` - Working example
5. GitHub issues - Report problems

---

**Congratulations! 🎉**  
You're now using ML-enhanced typosquatting detection!
