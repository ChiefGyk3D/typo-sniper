"""
Machine Learning classifier for typosquatting detection.

Uses LightGBM for efficient gradient boosting with SHAP explainability.
Designed for high precision (minimize false positives) while maintaining
reasonable recall on known attack patterns.
"""

import json
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
import numpy as np

try:
    import lightgbm as lgb
    LGBM_AVAILABLE = True
except ImportError:
    LGBM_AVAILABLE = False

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


@dataclass
class PredictionResult:
    """Result of ML prediction."""
    domain: str
    is_typosquat: bool
    confidence: float  # 0.0 to 1.0
    risk_score: int  # 0 to 100
    top_features: List[Tuple[str, float]]  # (feature_name, contribution)
    explanation: str
    needs_review: bool  # For active learning


@dataclass
class ModelMetrics:
    """Model performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    auc_roc: float
    precision_at_100: float  # Precision when detecting top 100 high-confidence domains


class MLClassifier:
    """
    Machine learning classifier for typosquatting detection.
    
    Uses LightGBM for efficient gradient boosting with:
    - Feature importance tracking
    - SHAP explainability
    - Calibrated probabilities
    - Active learning support
    """
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize classifier.
        
        Args:
            model_path: Path to saved model file. If None, creates new model.
        """
        if not LGBM_AVAILABLE:
            raise ImportError("LightGBM not installed. Run: pip install lightgbm")
        
        self.model = None
        self.feature_names = None
        self.model_path = model_path
        self.explainer = None
        
        # Default hyperparameters optimized for precision
        self.default_params = {
            'objective': 'binary',
            'metric': 'binary_logloss',
            'boosting_type': 'gbdt',
            'num_leaves': 31,
            'learning_rate': 0.05,
            'feature_fraction': 0.8,
            'bagging_fraction': 0.8,
            'bagging_freq': 5,
            'max_depth': 7,
            'min_data_in_leaf': 20,
            'lambda_l1': 0.1,
            'lambda_l2': 0.1,
            'verbose': -1,
            'scale_pos_weight': 1.0,  # Adjust based on class imbalance
        }
        
        # Decision thresholds
        self.high_confidence_threshold = 0.7  # Above this = definite typosquat
        self.low_confidence_threshold = 0.3   # Below this = likely legitimate
        # Between thresholds = needs human review (active learning)
        
        if model_path:
            self.load_model(model_path)
    
    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        X_val: Optional[np.ndarray] = None,
        y_val: Optional[np.ndarray] = None,
        feature_names: Optional[List[str]] = None,
        params: Optional[Dict] = None,
        num_rounds: int = 500,
        early_stopping_rounds: int = 50
    ) -> ModelMetrics:
        """
        Train the classifier.
        
        Args:
            X_train: Training features (n_samples, n_features)
            y_train: Training labels (n_samples,)
            X_val: Validation features (optional)
            y_val: Validation labels (optional)
            feature_names: Names of features
            params: Custom hyperparameters (overrides defaults)
            num_rounds: Maximum boosting rounds
            early_stopping_rounds: Stop if no improvement
            
        Returns:
            Model performance metrics
        """
        # Prepare training data
        train_data = lgb.Dataset(X_train, label=y_train, feature_name=feature_names)
        
        valid_sets = [train_data]
        valid_names = ['training']
        
        if X_val is not None and y_val is not None:
            val_data = lgb.Dataset(X_val, label=y_val, reference=train_data)
            valid_sets.append(val_data)
            valid_names.append('validation')
        
        # Merge custom params with defaults
        train_params = self.default_params.copy()
        if params:
            train_params.update(params)
        
        # Train model
        self.model = lgb.train(
            train_params,
            train_data,
            num_boost_round=num_rounds,
            valid_sets=valid_sets,
            valid_names=valid_names,
            callbacks=[
                lgb.early_stopping(early_stopping_rounds),
                lgb.log_evaluation(period=50)
            ]
        )
        
        self.feature_names = feature_names or [f'feature_{i}' for i in range(X_train.shape[1])]
        
        # Initialize SHAP explainer if available
        if SHAP_AVAILABLE:
            self.explainer = shap.TreeExplainer(self.model)
        
        # Calculate metrics
        if X_val is not None and y_val is not None:
            return self._calculate_metrics(X_val, y_val)
        else:
            return self._calculate_metrics(X_train, y_train)
    
    def predict(
        self,
        features: Dict[str, float],
        domain: str,
        explain: bool = True
    ) -> PredictionResult:
        """
        Predict if domain is typosquatting.
        
        Args:
            features: Feature dictionary
            domain: Domain name
            explain: Whether to compute SHAP explanations
            
        Returns:
            Prediction result with confidence and explanation
        """
        if self.model is None:
            raise ValueError("Model not trained. Call train() first or load_model().")
        
        # Convert features dict to array
        feature_array = self._features_dict_to_array(features)
        
        # Predict probability
        prob = self.model.predict(feature_array)[0]
        confidence = abs(prob - 0.5) * 2  # Scale to 0-1 where 0.5 prob = 0 confidence
        
        # Classify
        is_typosquat = prob > 0.5
        risk_score = int(prob * 100)
        
        # Determine if needs review (active learning)
        needs_review = self.low_confidence_threshold < prob < self.high_confidence_threshold
        
        # Get feature contributions
        top_features = []
        explanation = ""
        
        if explain and SHAP_AVAILABLE and self.explainer:
            shap_values = self.explainer.shap_values(feature_array)
            
            # Get top contributing features
            feature_contributions = list(zip(self.feature_names, shap_values[0]))
            feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            top_features = feature_contributions[:5]
            
            # Build explanation
            explanation = self._build_explanation(top_features, prob)
        else:
            # Fallback: use feature importance
            if self.model:
                importance = self.model.feature_importance(importance_type='gain')
                feature_importance = list(zip(self.feature_names, importance))
                feature_importance.sort(key=lambda x: x[1], reverse=True)
                top_features = feature_importance[:5]
                explanation = f"Based on model features (confidence: {confidence:.2%})"
        
        return PredictionResult(
            domain=domain,
            is_typosquat=is_typosquat,
            confidence=confidence,
            risk_score=risk_score,
            top_features=top_features,
            explanation=explanation,
            needs_review=needs_review
        )
    
    def predict_batch(
        self,
        features_list: List[Dict[str, float]],
        domains: List[str],
        explain: bool = False
    ) -> List[PredictionResult]:
        """
        Predict multiple domains efficiently.
        
        Args:
            features_list: List of feature dictionaries
            domains: List of domain names
            explain: Whether to compute explanations (slower)
            
        Returns:
            List of prediction results
        """
        if len(features_list) != len(domains):
            raise ValueError("features_list and domains must have same length")
        
        # Batch predict for efficiency
        feature_array = np.vstack([self._features_dict_to_array(f) for f in features_list])
        probs = self.model.predict(feature_array)
        
        results = []
        for i, (prob, domain, features) in enumerate(zip(probs, domains, features_list)):
            if explain:
                result = self.predict(features, domain, explain=True)
            else:
                confidence = abs(prob - 0.5) * 2
                is_typosquat = prob > 0.5
                risk_score = int(prob * 100)
                needs_review = self.low_confidence_threshold < prob < self.high_confidence_threshold
                
                result = PredictionResult(
                    domain=domain,
                    is_typosquat=is_typosquat,
                    confidence=confidence,
                    risk_score=risk_score,
                    top_features=[],
                    explanation=f"ML Score: {prob:.3f}",
                    needs_review=needs_review
                )
            
            results.append(result)
        
        return results
    
    def get_feature_importance(self, top_n: int = 20) -> List[Tuple[str, float]]:
        """
        Get top N most important features.
        
        Args:
            top_n: Number of features to return
            
        Returns:
            List of (feature_name, importance) tuples
        """
        if self.model is None:
            raise ValueError("Model not trained")
        
        importance = self.model.feature_importance(importance_type='gain')
        feature_importance = list(zip(self.feature_names, importance))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        return feature_importance[:top_n]
    
    def tune_threshold(
        self,
        X_val: np.ndarray,
        y_val: np.ndarray,
        target_precision: float = 0.95
    ) -> float:
        """
        Tune decision threshold to achieve target precision.
        
        Args:
            X_val: Validation features
            y_val: Validation labels
            target_precision: Desired precision (e.g., 0.95 = 95%)
            
        Returns:
            Optimal threshold value
        """
        probs = self.model.predict(X_val)
        
        # Try different thresholds
        best_threshold = 0.5
        best_f1 = 0
        
        for threshold in np.arange(0.3, 0.9, 0.05):
            predictions = (probs >= threshold).astype(int)
            
            # Calculate precision
            tp = np.sum((predictions == 1) & (y_val == 1))
            fp = np.sum((predictions == 1) & (y_val == 0))
            fn = np.sum((predictions == 0) & (y_val == 1))
            
            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            
            # If precision meets target, maximize F1
            if precision >= target_precision and f1 > best_f1:
                best_threshold = threshold
                best_f1 = f1
        
        return best_threshold
    
    def save_model(self, path: str):
        """Save model to disk."""
        if self.model is None:
            raise ValueError("No model to save")
        
        model_dir = Path(path).parent
        model_dir.mkdir(parents=True, exist_ok=True)
        
        # Save LightGBM model
        self.model.save_model(path)
        
        # Save metadata
        metadata = {
            'feature_names': self.feature_names,
            'high_confidence_threshold': self.high_confidence_threshold,
            'low_confidence_threshold': self.low_confidence_threshold,
        }
        
        metadata_path = str(path).replace('.txt', '_metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def load_model(self, path: str):
        """Load model from disk."""
        # Load LightGBM model
        self.model = lgb.Booster(model_file=path)
        
        # Load metadata
        metadata_path = str(path).replace('.txt', '_metadata.json')
        if Path(metadata_path).exists():
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            self.feature_names = metadata.get('feature_names')
            self.high_confidence_threshold = metadata.get('high_confidence_threshold', 0.7)
            self.low_confidence_threshold = metadata.get('low_confidence_threshold', 0.3)
        
        # Reinitialize SHAP explainer
        if SHAP_AVAILABLE:
            self.explainer = shap.TreeExplainer(self.model)
    
    def _features_dict_to_array(self, features: Dict[str, float]) -> np.ndarray:
        """Convert feature dictionary to array matching model's feature order."""
        if self.feature_names is None:
            raise ValueError("Feature names not set")
        
        feature_array = np.array([features.get(name, 0.0) for name in self.feature_names])
        return feature_array.reshape(1, -1)
    
    def _calculate_metrics(self, X: np.ndarray, y: np.ndarray) -> ModelMetrics:
        """Calculate model performance metrics."""
        probs = self.model.predict(X)
        predictions = (probs > 0.5).astype(int)
        
        tp = np.sum((predictions == 1) & (y == 1))
        fp = np.sum((predictions == 1) & (y == 0))
        fn = np.sum((predictions == 0) & (y == 1))
        tn = np.sum((predictions == 0) & (y == 0))
        
        accuracy = (tp + tn) / len(y)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        # AUC-ROC
        try:
            from sklearn.metrics import roc_auc_score
            auc_roc = roc_auc_score(y, probs)
        except:
            auc_roc = 0.0
        
        # Precision at top 100
        if len(probs) >= 100:
            top_100_indices = np.argsort(probs)[-100:]
            top_100_labels = y[top_100_indices]
            precision_at_100 = np.sum(top_100_labels) / 100.0
        else:
            precision_at_100 = precision
        
        return ModelMetrics(
            accuracy=accuracy,
            precision=precision,
            recall=recall,
            f1_score=f1_score,
            auc_roc=auc_roc,
            precision_at_100=precision_at_100
        )
    
    def _build_explanation(self, top_features: List[Tuple[str, float]], prob: float) -> str:
        """Build human-readable explanation from SHAP values."""
        if not top_features:
            return f"Typosquat probability: {prob:.2%}"
        
        explanation_parts = []
        
        for feature_name, contribution in top_features:
            if contribution > 0:
                direction = "increases"
            else:
                direction = "decreases"
            
            # Make feature name more readable
            readable_name = feature_name.replace('_', ' ').title()
            explanation_parts.append(f"{readable_name} {direction} suspicion")
        
        explanation = " | ".join(explanation_parts[:3])  # Top 3 only
        explanation += f" (score: {prob:.2%})"
        
        return explanation


def main():
    """Example usage and testing."""
    if not LGBM_AVAILABLE:
        print("LightGBM not installed. Install with: pip install lightgbm")
        return
    
    print("=== ML Classifier Example ===\n")
    
    # Generate synthetic training data
    np.random.seed(42)
    n_samples = 1000
    n_features = 50
    
    # Simulate features (in real use, these come from FeatureExtractor)
    X_train = np.random.randn(n_samples, n_features)
    X_train[:n_samples//2, :10] += 2  # Typosquats have higher values in first 10 features
    y_train = np.array([1] * (n_samples//2) + [0] * (n_samples//2))
    
    # Shuffle
    indices = np.random.permutation(n_samples)
    X_train = X_train[indices]
    y_train = y_train[indices]
    
    # Split train/val
    split = int(0.8 * n_samples)
    X_val = X_train[split:]
    y_val = y_train[split:]
    X_train = X_train[:split]
    y_train = y_train[:split]
    
    # Create feature names
    feature_names = [f'feature_{i}' for i in range(n_features)]
    
    # Train classifier
    print("Training classifier...")
    classifier = MLClassifier()
    metrics = classifier.train(
        X_train, y_train,
        X_val, y_val,
        feature_names=feature_names,
        num_rounds=100,
        early_stopping_rounds=20
    )
    
    print(f"\n=== Model Metrics ===")
    print(f"Accuracy:        {metrics.accuracy:.3f}")
    print(f"Precision:       {metrics.precision:.3f}")
    print(f"Recall:          {metrics.recall:.3f}")
    print(f"F1 Score:        {metrics.f1_score:.3f}")
    print(f"AUC-ROC:         {metrics.auc_roc:.3f}")
    print(f"Precision@100:   {metrics.precision_at_100:.3f}")
    
    # Show feature importance
    print(f"\n=== Top 10 Features ===")
    for feature, importance in classifier.get_feature_importance(10):
        print(f"{feature:20s}: {importance:8.1f}")
    
    # Test prediction
    print(f"\n=== Example Prediction ===")
    test_features = {name: X_val[0, i] for i, name in enumerate(feature_names)}
    result = classifier.predict(test_features, "example.com", explain=False)
    
    print(f"Domain:          {result.domain}")
    print(f"Is Typosquat:    {result.is_typosquat}")
    print(f"Confidence:      {result.confidence:.2%}")
    print(f"Risk Score:      {result.risk_score}/100")
    print(f"Needs Review:    {result.needs_review}")
    

if __name__ == '__main__':
    main()
