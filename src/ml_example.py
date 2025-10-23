#!/usr/bin/env python3
"""
Example: ML-Enhanced Typosquatting Detection

Demonstrates the complete ML pipeline for Typo Sniper:
1. Generate synthetic training data
2. Extract features from domains
3. Train ML classifier
4. Make predictions with explanations
5. Active learning workflow

This example can be adapted for production use by connecting to
your actual domain data and threat intelligence sources.
"""

import numpy as np
from pathlib import Path

# Import ML components
from ml_typo_generator import TypoGenerator, TypoConfig
from ml_homoglyph_detector import HomoglyphDetector
from ml_feature_extractor import FeatureExtractor
from ml_classifier import MLClassifier
from ml_active_learning import ActiveLearner


def generate_training_data(brands: list, samples_per_brand: int = 100):
    """
    Generate synthetic training data.
    
    Args:
        brands: List of legitimate brand domains
        samples_per_brand: Number of typosquat variants per brand
        
    Returns:
        Tuple of (domains, labels) where label is 1 for typosquat, 0 for legit
    """
    print("=== Generating Training Data ===\n")
    
    # Create typo generator
    config = TypoConfig(
        max_edits=2,
        homoglyph_prob=0.3,
        keyboard_error_prob=0.2,
        tld_swap_prob=0.1
    )
    generator = TypoGenerator(config)
    
    domains = []
    labels = []
    
    # Add legitimate brands (negative examples)
    for brand in brands:
        domains.append(brand)
        labels.append(0)
    
    # Generate typosquats (positive examples)
    for brand in brands:
        typos = generator.generate_typos(brand, count=samples_per_brand)
        domains.extend(typos)
        labels.extend([1] * len(typos))
    
    print(f"Generated {len(domains)} total domains:")
    print(f"  Legitimate: {sum(1 for l in labels if l == 0)}")
    print(f"  Typosquats: {sum(1 for l in labels if l == 1)}")
    print()
    
    return domains, labels


def create_mock_domain_data(domain: str):
    """
    Create mock domain data for demonstration.
    
    In production, this would come from actual DNS queries,
    WHOIS lookups, and threat intelligence sources.
    """
    # Simulate varying domain characteristics
    is_likely_typosquat = np.random.random() > 0.5
    
    return {
        'domain': domain,
        'whois_created': [f'2024-{np.random.randint(1, 12):02d}-{np.random.randint(1, 28):02d}'],
        'whois_registrar': np.random.choice(['Namecheap', 'GoDaddy', 'MarkMonitor']),
        'dns_a': [f'{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}'],
        'dns_mx': [f'mail.{domain}'] if np.random.random() > 0.3 else [],
        'threat_intel': {
            'urlscan': {
                'malicious': is_likely_typosquat,
                'score': np.random.randint(0, 100) if is_likely_typosquat else 0
            }
        }
    }


def extract_features_batch(domains: list, brand: str):
    """
    Extract features from multiple domains.
    
    Args:
        domains: List of domain names
        brand: Brand to compare against
        
    Returns:
        List of feature dictionaries
    """
    print("=== Extracting Features ===\n")
    
    extractor = FeatureExtractor()
    features_list = []
    
    for i, domain in enumerate(domains):
        if i % 100 == 0:
            print(f"Processing domain {i+1}/{len(domains)}...")
        
        # Get domain data (mock for demo)
        domain_data = create_mock_domain_data(domain)
        
        # Extract features
        features = extractor.extract_features(domain_data, brand)
        features_list.append(features)
    
    print(f"Extracted {len(features_list[0])} features per domain\n")
    
    return features_list


def train_model(features_list: list, labels: list, feature_names: list):
    """
    Train ML classifier.
    
    Args:
        features_list: List of feature dictionaries
        labels: List of labels (1 = typosquat, 0 = legit)
        feature_names: List of feature names
        
    Returns:
        Trained classifier
    """
    print("=== Training ML Classifier ===\n")
    
    # Convert to arrays
    X = np.array([[f[name] for name in feature_names] for f in features_list])
    y = np.array(labels)
    
    # Split train/validation
    from sklearn.model_selection import train_test_split
    X_train, X_val, y_train, y_val = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)} samples")
    print(f"Validation set: {len(X_val)} samples")
    print()
    
    # Train classifier
    classifier = MLClassifier()
    
    # Custom hyperparameters
    params = {
        'num_leaves': 31,
        'learning_rate': 0.05,
        'scale_pos_weight': 1.0,
    }
    
    metrics = classifier.train(
        X_train, y_train,
        X_val, y_val,
        feature_names=feature_names,
        params=params,
        num_rounds=200,
        early_stopping_rounds=30
    )
    
    print(f"\n=== Model Performance ===")
    print(f"Accuracy:        {metrics.accuracy:.3f}")
    print(f"Precision:       {metrics.precision:.3f}")
    print(f"Recall:          {metrics.recall:.3f}")
    print(f"F1 Score:        {metrics.f1_score:.3f}")
    print(f"AUC-ROC:         {metrics.auc_roc:.3f}")
    print(f"Precision@100:   {metrics.precision_at_100:.3f}")
    print()
    
    # Show top features
    print("=== Top 10 Most Important Features ===")
    for feature, importance in classifier.get_feature_importance(10):
        print(f"{feature:30s}: {importance:8.1f}")
    print()
    
    return classifier


def demonstrate_predictions(classifier: MLClassifier, features_list: list, domains: list):
    """
    Demonstrate predictions with explanations.
    """
    print("=== Example Predictions ===\n")
    
    # Select a few interesting examples
    for i in [0, 1, 2, -3, -2, -1]:
        result = classifier.predict(features_list[i], domains[i], explain=False)
        
        status = "🚨 TYPOSQUAT" if result.is_typosquat else "✓ LEGITIMATE"
        confidence_bar = "█" * int(result.confidence * 20)
        
        print(f"{status}: {result.domain}")
        print(f"  Risk Score:   {result.risk_score}/100")
        print(f"  Confidence:   {confidence_bar} {result.confidence:.2%}")
        
        if result.needs_review:
            print(f"  ⚠️  Needs human review (uncertain prediction)")
        
        print()


def demonstrate_active_learning(classifier: MLClassifier, features_list: list, domains: list):
    """
    Demonstrate active learning workflow.
    """
    print("=== Active Learning Workflow ===\n")
    
    # Create learner
    learner = ActiveLearner(
        uncertainty_threshold=0.15,
        review_budget=20
    )
    
    # Get predictions
    print("Getting predictions for active learning...")
    predictions = classifier.predict_batch(features_list, domains, explain=False)
    
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
    
    # Select uncertain domains for review
    candidates = learner.select_for_review(al_predictions, strategy='uncertainty')
    
    print(f"\nSelected {len(candidates)} domains for human review:\n")
    for i, candidate in enumerate(candidates[:10], 1):
        print(f"{i:2d}. {candidate.domain:30s} (prob={candidate.prediction_prob:.3f}, conf={candidate.confidence:.3f})")
        print(f"    Reason: {candidate.reason}")
    
    print(f"\n... and {len(candidates) - 10} more\n" if len(candidates) > 10 else "")
    
    # Simulate human labeling (in production, analyst provides these)
    print("Simulating human labeling...")
    for candidate in candidates[:5]:
        # Randomly assign label for demo
        is_typosquat = candidate.prediction_prob > 0.5
        learner.add_human_label(
            candidate.domain,
            is_typosquat,
            reviewer="analyst_1",
            notes="Reviewed manually"
        )
    
    # Get labeling stats
    stats = learner.get_labeling_stats()
    print(f"\n=== Labeling Statistics ===")
    print(f"Total labeled:   {stats['total_labeled']}")
    print(f"Typosquats:      {stats['typosquats']}")
    print(f"Legitimate:      {stats['legitimate']}")
    print(f"Pending review:  {stats['pending_review']}")
    print()
    
    # Export review batch for analysts
    review_file = 'review_batch_demo.csv'
    learner.export_review_batch(review_file, batch_size=10)
    print(f"Exported review batch to: {review_file}")
    print()


def demonstrate_homoglyph_detection():
    """
    Demonstrate homoglyph detection.
    """
    print("=== Homoglyph Detection ===\n")
    
    detector = HomoglyphDetector()
    
    # Test cases with various homoglyphs
    test_cases = [
        ('google.com', 'gооgle.com'),  # Cyrillic 'о' instead of Latin 'o'
        ('facebook.com', 'fαcebook.com'),  # Greek alpha 'α' instead of 'a'
        ('apple.com', 'αpple.com'),  # Greek alpha
        ('amazon.com', 'amazοn.com'),  # Greek omicron 'ο'
        ('microsoft.com', 'micrοsoft.com'),  # Greek omicron
    ]
    
    for original, suspicious in test_cases:
        match = detector.detect(original, suspicious)
        
        if match:
            print(f"⚠️  Homoglyph detected!")
            print(f"   Original:   {original}")
            print(f"   Suspicious: {suspicious}")
            print(f"   Confusable chars: {', '.join(match.suspicious_chars)}")
            print(f"   Similarity: {match.similarity_score:.2%}")
            print(f"   Visual distance: {match.visual_distance}")
            
            # Show character details
            for char in match.suspicious_chars:
                info = detector.get_unicode_info(char)
                print(f"   '{char}' → {info}")
            
            # Normalize to ASCII
            normalized = detector.normalize_domain(suspicious)
            print(f"   Normalized: {normalized}")
            print()


def save_and_load_model(classifier: MLClassifier):
    """
    Demonstrate model persistence.
    """
    print("=== Model Persistence ===\n")
    
    # Create models directory
    models_dir = Path('models')
    models_dir.mkdir(exist_ok=True)
    
    model_path = 'models/demo_typosquat_detector.txt'
    
    # Save model
    print(f"Saving model to: {model_path}")
    classifier.save_model(model_path)
    print(f"Model saved successfully")
    print()
    
    # Load model
    print(f"Loading model from: {model_path}")
    loaded_classifier = MLClassifier(model_path=model_path)
    print(f"Model loaded successfully")
    print()
    
    return loaded_classifier


def main():
    """Run complete ML pipeline demonstration."""
    
    print("\n" + "="*70)
    print("ML-Enhanced Typosquatting Detection - Complete Demo")
    print("="*70 + "\n")
    
    # Configuration
    brands = [
        'google.com',
        'facebook.com',
        'amazon.com',
        'apple.com',
        'microsoft.com'
    ]
    
    samples_per_brand = 50  # Generate 50 typos per brand
    target_brand = 'google.com'  # Primary brand for feature extraction
    
    # Step 1: Generate training data
    domains, labels = generate_training_data(brands, samples_per_brand)
    
    # Step 2: Extract features
    features_list = extract_features_batch(domains, target_brand)
    feature_names = list(features_list[0].keys())
    
    # Step 3: Train model
    classifier = train_model(features_list, labels, feature_names)
    
    # Step 4: Make predictions
    demonstrate_predictions(classifier, features_list, domains)
    
    # Step 5: Active learning
    demonstrate_active_learning(classifier, features_list, domains)
    
    # Step 6: Homoglyph detection
    demonstrate_homoglyph_detection()
    
    # Step 7: Save and load model
    loaded_classifier = save_and_load_model(classifier)
    
    # Final test with loaded model
    print("=== Testing Loaded Model ===\n")
    test_result = loaded_classifier.predict(
        features_list[0],
        domains[0],
        explain=False
    )
    print(f"Test prediction: {domains[0]} → Risk Score: {test_result.risk_score}/100")
    print()
    
    print("="*70)
    print("Demo completed successfully!")
    print("="*70 + "\n")
    
    print("Next steps:")
    print("  1. Replace mock domain data with real DNS/WHOIS lookups")
    print("  2. Collect more training data (aim for 10,000+ labeled examples)")
    print("  3. Integrate with Typo Sniper main scanner")
    print("  4. Set up active learning workflow with human reviewers")
    print("  5. Monitor model performance and retrain periodically")
    print()


if __name__ == '__main__':
    # Check dependencies
    try:
        import lightgbm
        import sklearn
    except ImportError as e:
        print(f"ERROR: Missing ML dependencies")
        print(f"Install with: pip install lightgbm scikit-learn numpy pandas")
        print(f"\nError: {e}")
        exit(1)
    
    main()
