# Machine Learning Features

Typo Sniper includes an optional machine learning enhancement for automated typosquatting detection. This feature provides intelligent risk scoring, uncertainty quantification, and active learning to continuously improve detection accuracy.

## Overview

The ML system uses a hybrid approach combining rule-based heuristics with gradient-boosted decision trees (LightGBM) to identify typosquatting domains with high precision. It's designed to minimize false positives while maintaining good recall on known attack patterns.

### Key Components

1. **Synthetic Typo Generator** (`ml_typo_generator.py`)
   - Generates realistic typosquatting variants for training data augmentation
   - Supports: character insertion/deletion/substitution, homoglyphs, keyboard proximity errors, TLD swaps
   - Configurable probabilities and edit distances

2. **Homoglyph Detector** (`ml_homoglyph_detector.py`)
   - Detects sophisticated Unicode-based typosquatting attacks
   - Maps confusable characters (Cyrillic, Greek, etc.) to ASCII equivalents
   - Calculates visual similarity and Levenshtein distance

3. **Feature Extractor** (`ml_feature_extractor.py`)
   - Extracts 50+ features from domains:
     - **Lexical**: Edit distances, n-gram similarity, entropy, pronounceability
     - **WHOIS**: Domain age, registrar reputation, privacy flags
     - **DNS**: Record types, MX presence, nameserver patterns
     - **Behavioral**: URLScan scores, certificate transparency, HTTP probes
     - **Visual**: Homoglyph presence, confusable character detection

4. **ML Classifier** (`ml_classifier.py`)
   - LightGBM gradient boosting model with SHAP explainability
   - Calibrated probabilities for confidence estimation
   - Tunable thresholds for precision/recall tradeoff
   - Feature importance tracking

5. **Active Learner** (`ml_active_learning.py`)
   - Uncertainty sampling to identify domains needing human review
   - Model disagreement detection across versions
   - Label tracking and retraining workflow

## Installation

Install ML dependencies:

```bash
pip install lightgbm catboost shap scikit-learn pandas numpy unicodedata2
```

Or using the requirements file:

```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Generate Training Data

```python
from src.ml_typo_generator import TypoGenerator, TypoConfig

# Create generator
config = TypoConfig(
    max_edits=2,
    homoglyph_prob=0.3,
    keyboard_error_prob=0.2
)
generator = TypoGenerator(config)

# Generate typos for a brand
brand = "google.com"
typos = generator.generate_typos(brand, count=100)

print(f"Generated {len(typos)} typosquatting variants")
# ['gooogle.com', 'g0ogle.com', 'googlr.com', ...]
```

### 2. Extract Features

```python
from src.ml_feature_extractor import FeatureExtractor

extractor = FeatureExtractor()

# Example domain data (from Typo Sniper scan)
domain_data = {
    'domain': 'gooogle.com',
    'whois_created': ['2024-01-15'],
    'whois_registrar': 'Namecheap',
    'dns_a': ['1.2.3.4'],
    'dns_mx': ['mail.gooogle.com'],
    'threat_intel': {
        'urlscan': {'malicious': False, 'score': 0},
    }
}

brand = 'google.com'
features = extractor.extract_features(domain_data, brand)

print(f"Extracted {len(features)} features")
# {'length': 7, 'levenshtein_distance': 1, 'domain_age_days': 365, ...}
```

### 3. Train Classifier

```python
import numpy as np
from src.ml_classifier import MLClassifier

# Prepare training data (features + labels)
X_train = np.array([...])  # Feature matrix (n_samples, n_features)
y_train = np.array([...])  # Labels: 1 = typosquat, 0 = legitimate

# Train model
classifier = MLClassifier()
metrics = classifier.train(
    X_train, y_train,
    feature_names=list(features.keys()),
    num_rounds=500,
    early_stopping_rounds=50
)

print(f"Model Accuracy: {metrics.accuracy:.3f}")
print(f"Precision: {metrics.precision:.3f}")
print(f"Recall: {metrics.recall:.3f}")

# Save model
classifier.save_model('models/typosquat_detector.txt')
```

### 4. Make Predictions

```python
# Load trained model
classifier = MLClassifier(model_path='models/typosquat_detector.txt')

# Predict on new domain
result = classifier.predict(features, domain='gooogle.com', explain=True)

print(f"Domain: {result.domain}")
print(f"Is Typosquat: {result.is_typosquat}")
print(f"Confidence: {result.confidence:.2%}")
print(f"Risk Score: {result.risk_score}/100")
print(f"Explanation: {result.explanation}")
```

### 5. Active Learning

```python
from src.ml_active_learning import ActiveLearner

# Create learner
learner = ActiveLearner(
    uncertainty_threshold=0.15,  # Select predictions within 0.35-0.65 range
    review_budget=100  # Max domains per batch
)

# Get predictions from classifier
predictions = [
    {
        'domain': 'gooogle.com',
        'probability': 0.52,
        'confidence': 0.04,
        'features': features
    },
    # ... more predictions
]

# Select uncertain domains for human review
candidates = learner.select_for_review(predictions, strategy='uncertainty')

print(f"Selected {len(candidates)} domains for review")
for candidate in candidates[:5]:
    print(f"  {candidate.domain}: {candidate.reason}")

# Add human labels
learner.add_human_label('gooogle.com', is_typosquat=True, reviewer='analyst_1')

# Get labeled data for retraining
domains, labels = learner.get_training_data()
```

## Architecture

### Hybrid Scoring Pipeline

```
Input Domain
    ↓
[Lexical Analysis] → Quick rejection of obvious non-typos
    ↓
[Feature Extraction] → 50+ features (lexical, WHOIS, DNS, behavioral, visual)
    ↓
[ML Classifier] → LightGBM with calibrated probabilities
    ↓
[Confidence Scoring] → High/Medium/Low confidence buckets
    ↓
┌─────────────┬──────────────┬────────────────┐
│ High Conf   │ Medium Conf  │ Low Conf       │
│ Typosquat   │ → Review     │ Legitimate     │
│ (>70%)      │ (30-70%)     │ (<30%)         │
└─────────────┴──────────────┴────────────────┘
         ↓            ↓              ↓
    [Report]  [Active Learning]  [Report]
```

### Feature Engineering

The feature extractor creates 50+ features grouped by category:

**Lexical Features (15)**
- Edit distances (Levenshtein, Jaro-Winkler)
- N-gram similarity (bigrams, trigrams)
- Character composition (vowels, consonants, digits, hyphens)
- Pattern detection (repeated chars, transpositions)
- Entropy and pronounceability

**WHOIS Features (8)**
- Domain age (days, months, years)
- Registrar reputation
- Privacy/proxy detection
- Data completeness

**DNS Features (9)**
- Record presence (A, AAAA, MX, NS)
- IP count and distribution
- Nameserver analysis
- Hosting provider detection

**Behavioral Features (8)**
- URLScan malicious flag and score
- Certificate transparency count
- HTTP/HTTPS activity
- Redirect detection

**Visual Features (7)**
- Homoglyph presence
- Non-ASCII characters
- Visual similarity patterns (rn→m, vv→w, cl→d)

### Model Selection

We use **LightGBM** as the primary model for:
- Fast training and inference
- Native handling of categorical features
- Built-in feature importance
- Excellent calibration for probabilities
- Low memory footprint

**CatBoost** is available as an alternative with:
- Better handling of high-cardinality categoricals
- Ordered boosting (reduces overfitting)
- Built-in categorical encoding

### Explainability

Every prediction includes SHAP values showing feature contributions:

```python
result = classifier.predict(features, domain='gooogle.com', explain=True)

# Top contributing features
for feature, contribution in result.top_features:
    print(f"{feature}: {contribution:+.3f}")

# Output:
# levenshtein_distance: +2.451
# domain_age_days: -1.203
# urlscan_score: +0.987
# pronounceability: -0.654
# has_mx_record: +0.321
```

## Training Your Own Model

### 1. Collect Training Data

You need labeled examples of typosquat and legitimate domains. Start with:

**Positive Examples (Typosquats)**:
- Generate synthetic typos using `ml_typo_generator.py`
- Collect known typosquats from URLScan, PhishTank, or internal incidents
- Use active learning to identify uncertain domains

**Negative Examples (Legitimate)**:
- Alexa/Tranco top domains
- Your organization's legitimate domains
- Partner/vendor domains

Aim for:
- Minimum: 1,000 labeled examples (500 positive, 500 negative)
- Recommended: 10,000+ labeled examples
- Maintain class balance (adjust `scale_pos_weight` if imbalanced)

### 2. Extract Features

```python
from src.ml_feature_extractor import FeatureExtractor
import pandas as pd

extractor = FeatureExtractor()

# Collect features for all domains
features_list = []
labels = []

for domain_data, label in labeled_domains:
    features = extractor.extract_features(domain_data, brand='google.com')
    features_list.append(features)
    labels.append(label)

# Convert to DataFrame
df = pd.DataFrame(features_list)
X = df.values
y = np.array(labels)
```

### 3. Train and Evaluate

```python
from sklearn.model_selection import train_test_split
from src.ml_classifier import MLClassifier

# Split data
X_train, X_val, y_train, y_val = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train classifier
classifier = MLClassifier()

# Custom hyperparameters for your dataset
params = {
    'num_leaves': 31,
    'learning_rate': 0.05,
    'scale_pos_weight': 1.0,  # Adjust for class imbalance
}

metrics = classifier.train(
    X_train, y_train,
    X_val, y_val,
    feature_names=df.columns.tolist(),
    params=params,
    num_rounds=1000,
    early_stopping_rounds=50
)

print(f"Validation Metrics:")
print(f"  Accuracy:  {metrics.accuracy:.3f}")
print(f"  Precision: {metrics.precision:.3f}")
print(f"  Recall:    {metrics.recall:.3f}")
print(f"  F1 Score:  {metrics.f1_score:.3f}")
print(f"  AUC-ROC:   {metrics.auc_roc:.3f}")
```

### 4. Tune Decision Threshold

For production use, optimize the threshold for your requirements:

```python
# Tune for high precision (minimize false positives)
optimal_threshold = classifier.tune_threshold(
    X_val, y_val,
    target_precision=0.95  # 95% precision target
)

print(f"Optimal threshold: {optimal_threshold:.3f}")

# Update classifier
classifier.high_confidence_threshold = optimal_threshold
```

### 5. Save and Deploy

```python
# Save trained model
classifier.save_model('models/typosquat_detector_v1.txt')

# Test loading
loaded_classifier = MLClassifier(model_path='models/typosquat_detector_v1.txt')

# Verify it works
test_result = loaded_classifier.predict(test_features, 'test-domain.com')
print(f"Test prediction: {test_result.risk_score}/100")
```

## Active Learning Workflow

Continuously improve your model with minimal labeling effort:

### 1. Select Uncertain Domains

```python
from src.ml_active_learning import ActiveLearner

learner = ActiveLearner(uncertainty_threshold=0.15, review_budget=100)

# Run classifier on unlabeled domains
predictions = classifier.predict_batch(features_list, domains)

# Convert to active learning format
al_predictions = [
    {
        'domain': pred.domain,
        'probability': pred.risk_score / 100.0,
        'confidence': pred.confidence,
        'features': features
    }
    for pred, features in zip(predictions, features_list)
]

# Select for review
candidates = learner.select_for_review(al_predictions, strategy='uncertainty')
```

### 2. Export for Review

```python
# Export batch for manual review
learner.export_review_batch('review_batch_001.csv', batch_size=50)

# File format: domain,prediction_prob,confidence,reason
```

### 3. Review and Label

Analysts review the exported batch and add labels:

```csv
domain,is_typosquat,notes
gooogle.com,true,Extra 'o' character
googl3.com,true,Digit substitution
google-login.com,true,Phishing attempt
googlecloud.com,false,Legitimate Google service
```

### 4. Import Labels

```python
# Import reviewed batch
learner.import_reviewed_batch('review_batch_001_labeled.csv', reviewer='analyst_1')

# Get stats
stats = learner.get_labeling_stats()
print(f"Total labeled: {stats['total_labeled']}")
print(f"Typosquats: {stats['typosquats']}")
print(f"Legitimate: {stats['legitimate']}")
```

### 5. Retrain Model

```python
# Get labeled data
domains, labels = learner.get_training_data()

# Extract features
new_features = [extractor.extract_features(get_domain_data(d), brand) for d in domains]
X_new = np.array([list(f.values()) for f in new_features])
y_new = np.array(labels)

# Combine with existing training data
X_combined = np.vstack([X_train, X_new])
y_combined = np.hstack([y_train, y_new])

# Retrain classifier
classifier_v2 = MLClassifier()
metrics = classifier_v2.train(X_combined, y_combined, X_val, y_val, feature_names=feature_names)

# Save new version
classifier_v2.save_model('models/typosquat_detector_v2.txt')
```

### 6. Monitor Disagreement

Track when model versions disagree (indicates distribution shift):

```python
# Get predictions from both versions
preds_v1 = classifier_v1.predict_batch(features_list, domains)
preds_v2 = classifier_v2.predict_batch(features_list, domains)

# Format for disagreement detection
al_preds_v1 = [{'domain': p.domain, 'probability': p.risk_score/100.0} for p in preds_v1]
al_preds_v2 = [{'domain': p.domain, 'probability': p.risk_score/100.0} for p in preds_v2]

# Detect disagreement
disagreements = learner.detect_disagreement(al_preds_v1, al_preds_v2, disagreement_threshold=0.3)

print(f"Found {len(disagreements)} domains with model disagreement")
```

## Integration with Typo Sniper

To integrate ML features into the main Typo Sniper workflow:

### 1. Enable ML in Config

Edit `config.yaml`:

```yaml
ml:
  enabled: true
  model_path: "models/typosquat_detector_v1.txt"
  confidence_threshold: 0.7
  active_learning:
    enabled: true
    uncertainty_threshold: 0.15
    review_budget: 100
```

### 2. Modify Scanner

The scanner will automatically use ML features when enabled:

```python
# In typo_sniper.py
if config.get('ml', {}).get('enabled'):
    from ml_classifier import MLClassifier
    classifier = MLClassifier(model_path=config['ml']['model_path'])
    
    # Add ML risk score to results
    for result in results:
        ml_result = classifier.predict(result['features'], result['domain'])
        result['ml_risk_score'] = ml_result.risk_score
        result['ml_confidence'] = ml_result.confidence
        result['ml_explanation'] = ml_result.explanation
```

### 3. Export with ML Scores

ML scores will appear in all export formats:

**Excel/CSV**:
```
Domain          Risk Score  ML Risk Score  ML Confidence  ML Explanation
gooogle.com     75          82             0.86          Levenshtein Distance increases suspicion
```

**HTML**:
Shows ML risk score with color coding and tooltip with explanation.

## Performance Considerations

### Inference Speed

- Feature extraction: ~50ms per domain
- ML prediction: ~1ms per domain (LightGBM)
- SHAP explanation: ~10ms per domain

For 1,000 domains: ~60 seconds total

### Batch Processing

Use batch predictions for better performance:

```python
# Slower: Individual predictions
for domain in domains:
    result = classifier.predict(features[domain], domain)

# Faster: Batch prediction
results = classifier.predict_batch(features_list, domains)
```

### Memory Usage

- Model size: ~5-10 MB (depends on training data)
- Feature storage: ~2 KB per domain
- For 100,000 domains: ~200 MB memory

## Troubleshooting

### Import Errors

```bash
# Install ML dependencies
pip install lightgbm catboost shap scikit-learn pandas numpy

# Verify installation
python -c "import lightgbm, shap; print('ML libraries OK')"
```

### Model Not Found

```python
# Check model path
import os
model_path = 'models/typosquat_detector.txt'
print(f"Model exists: {os.path.exists(model_path)}")

# Train new model if missing
classifier = MLClassifier()
classifier.train(X_train, y_train, feature_names=feature_names)
classifier.save_model(model_path)
```

### Low Precision

If model has too many false positives:

```python
# Tune threshold higher
optimal_threshold = classifier.tune_threshold(X_val, y_val, target_precision=0.98)
classifier.high_confidence_threshold = optimal_threshold

# Or collect more negative (legitimate) examples
```

### Low Recall

If model misses typosquats:

```python
# Tune threshold lower
classifier.high_confidence_threshold = 0.4

# Or collect more positive (typosquat) examples
# Use synthetic generation to augment
```

## Best Practices

1. **Start Simple**: Begin with synthetic typos and top Alexa domains as training data
2. **Iterate Quickly**: Use active learning to identify edge cases
3. **Monitor Drift**: Track model disagreement over time
4. **Explain Predictions**: Always use SHAP values for high-stakes decisions
5. **Balance Classes**: Maintain ~50/50 typosquat/legitimate ratio in training
6. **Validate Regularly**: Test on held-out set every model version
7. **Version Models**: Save each trained model version with metadata
8. **Document Errors**: Track false positives/negatives for next training cycle

## Future Enhancements

Potential improvements for the ML system:

- **Deep Learning**: Use transformer models for character-level embeddings
- **Graph Analysis**: Incorporate DNS/WHOIS relationship graphs
- **Temporal Features**: Track domain lifecycle changes over time
- **Ensemble Methods**: Combine multiple model types
- **Online Learning**: Update model incrementally with new labels
- **Multi-Class**: Classify typosquat types (phishing, malware, parked)
- **Anomaly Detection**: Identify novel attack patterns
- **LLM Integration**: Use GPT-4 for uncertain cases

## References

- LightGBM: https://lightgbm.readthedocs.io/
- SHAP: https://shap.readthedocs.io/
- Active Learning: Settles, B. (2009). "Active Learning Literature Survey"
- Typosquatting Detection: Agten et al. (2015). "Seven Months' Worth of Mistakes"

## Support

For questions or issues with ML features:
1. Check this documentation first
2. Review example code in `ml_*.py` files
3. Open an issue on GitHub with:
   - Model version
   - Training data size and balance
   - Performance metrics
   - Error messages or unexpected behavior
