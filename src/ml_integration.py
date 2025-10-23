"""
Machine Learning integration for Typo Sniper.

Provides optional ML-enhanced typosquatting detection with:
- Intelligent risk scoring using LightGBM classifier
- Active learning for continuous improvement
- Feature extraction from domain data
- Explainable predictions with SHAP values

This module gracefully handles missing ML dependencies and provides
fallback to rule-based detection when ML is not available.
"""

import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

# Try to import ML dependencies
try:
    from ml_feature_extractor import FeatureExtractor
    from ml_classifier import MLClassifier, PredictionResult
    from ml_active_learning import ActiveLearner
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    FeatureExtractor = None
    MLClassifier = None
    PredictionResult = None
    ActiveLearner = None


logger = logging.getLogger(__name__)


class MLIntegration:
    """
    Integration wrapper for ML features in Typo Sniper.
    
    Handles:
    - Feature extraction from domain data
    - ML predictions with risk scores
    - Active learning candidate selection
    - Graceful degradation when ML is unavailable
    """
    
    def __init__(
        self,
        model_path: Optional[str] = None,
        confidence_threshold: float = 0.7,
        enable_active_learning: bool = False,
        uncertainty_threshold: float = 0.15,
        review_budget: int = 100
    ):
        """
        Initialize ML integration.
        
        Args:
            model_path: Path to trained model file
            confidence_threshold: High confidence threshold (0-1)
            enable_active_learning: Enable active learning candidate selection
            uncertainty_threshold: Threshold for active learning (0-1)
            review_budget: Max domains to flag for review
        """
        self.enabled = False
        self.classifier = None
        self.feature_extractor = None
        self.active_learner = None
        
        if not ML_AVAILABLE:
            logger.warning(
                "ML dependencies not installed. ML features disabled. "
                "Install with: pip install lightgbm scikit-learn numpy pandas shap"
            )
            return
        
        # Initialize feature extractor (always needed)
        try:
            self.feature_extractor = FeatureExtractor()
        except Exception as e:
            logger.error(f"Failed to initialize feature extractor: {e}")
            return
        
        # Initialize classifier if model path provided
        if model_path:
            model_file = Path(model_path)
            if not model_file.exists():
                logger.warning(f"ML model not found: {model_path}. ML predictions disabled.")
                logger.info("To use ML features, train a model first. See docs/ML_FEATURES.md")
                return
            
            try:
                self.classifier = MLClassifier(model_path=str(model_file))
                self.classifier.high_confidence_threshold = confidence_threshold
                self.enabled = True
                logger.info(f"ML classifier loaded from: {model_path}")
            except Exception as e:
                logger.error(f"Failed to load ML model: {e}")
                return
        else:
            logger.info("No ML model path configured. ML predictions disabled.")
            logger.info("Set ml_model_path in config.yaml or ML_MODEL_PATH env var to enable.")
            return
        
        # Initialize active learner if enabled
        if enable_active_learning and self.enabled:
            try:
                self.active_learner = ActiveLearner(
                    uncertainty_threshold=uncertainty_threshold,
                    review_budget=review_budget
                )
                logger.info("Active learning enabled")
            except Exception as e:
                logger.error(f"Failed to initialize active learner: {e}")
    
    def extract_features(self, domain_data: Dict[str, Any], brand: str) -> Optional[Dict[str, float]]:
        """
        Extract ML features from domain data.
        
        Args:
            domain_data: Domain information (WHOIS, DNS, threat intel, etc.)
            brand: Original brand domain to compare against
            
        Returns:
            Feature dictionary or None if extraction fails
        """
        if not self.feature_extractor:
            return None
        
        try:
            features = self.feature_extractor.extract_features(domain_data, brand)
            return features
        except Exception as e:
            logger.debug(f"Feature extraction failed for {domain_data.get('domain', 'unknown')}: {e}")
            return None
    
    def predict(
        self,
        domain_data: Dict[str, Any],
        brand: str,
        explain: bool = False
    ) -> Optional[Dict[str, Any]]:
        """
        Make ML prediction for domain.
        
        Args:
            domain_data: Domain information
            brand: Original brand domain
            explain: Include SHAP explanations (slower)
            
        Returns:
            Prediction dictionary with:
                - ml_enabled: bool
                - ml_risk_score: int (0-100)
                - ml_confidence: float (0-1)
                - ml_is_typosquat: bool
                - ml_explanation: str
                - ml_needs_review: bool
                - ml_top_features: List[Tuple[str, float]]
            Or None if prediction fails
        """
        if not self.enabled or not self.classifier:
            return {
                'ml_enabled': False,
                'ml_risk_score': None,
                'ml_confidence': None,
                'ml_is_typosquat': None,
                'ml_explanation': 'ML not available',
                'ml_needs_review': False,
                'ml_top_features': []
            }
        
        # Extract features
        features = self.extract_features(domain_data, brand)
        if not features:
            return {
                'ml_enabled': False,
                'ml_risk_score': None,
                'ml_confidence': None,
                'ml_is_typosquat': None,
                'ml_explanation': 'Feature extraction failed',
                'ml_needs_review': False,
                'ml_top_features': []
            }
        
        # Make prediction
        try:
            domain = domain_data.get('domain', 'unknown')
            result = self.classifier.predict(features, domain, explain=explain)
            
            return {
                'ml_enabled': True,
                'ml_risk_score': result.risk_score,
                'ml_confidence': result.confidence,
                'ml_is_typosquat': result.is_typosquat,
                'ml_explanation': result.explanation,
                'ml_needs_review': result.needs_review,
                'ml_top_features': result.top_features[:3]  # Top 3 features
            }
        except Exception as e:
            logger.debug(f"ML prediction failed for {domain_data.get('domain', 'unknown')}: {e}")
            return {
                'ml_enabled': False,
                'ml_risk_score': None,
                'ml_confidence': None,
                'ml_is_typosquat': None,
                'ml_explanation': f'Prediction error: {str(e)[:50]}',
                'ml_needs_review': False,
                'ml_top_features': []
            }
    
    def predict_batch(
        self,
        domains_data: List[Dict[str, Any]],
        brand: str,
        explain: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Make ML predictions for multiple domains efficiently.
        
        Args:
            domains_data: List of domain information dictionaries
            brand: Original brand domain
            explain: Include SHAP explanations (slower)
            
        Returns:
            List of prediction dictionaries
        """
        if not self.enabled or not self.classifier:
            return [self.predict(d, brand, explain=False) for d in domains_data]
        
        # Extract features for all domains
        features_list = []
        valid_indices = []
        
        for i, domain_data in enumerate(domains_data):
            features = self.extract_features(domain_data, brand)
            if features:
                features_list.append(features)
                valid_indices.append(i)
        
        if not features_list:
            return [self.predict(d, brand, explain=False) for d in domains_data]
        
        # Batch predict
        try:
            domains = [domains_data[i]['domain'] for i in valid_indices]
            results = self.classifier.predict_batch(features_list, domains, explain=explain)
            
            # Map results back
            predictions = []
            result_idx = 0
            
            for i, domain_data in enumerate(domains_data):
                if i in valid_indices:
                    result = results[result_idx]
                    predictions.append({
                        'ml_enabled': True,
                        'ml_risk_score': result.risk_score,
                        'ml_confidence': result.confidence,
                        'ml_is_typosquat': result.is_typosquat,
                        'ml_explanation': result.explanation,
                        'ml_needs_review': result.needs_review,
                        'ml_top_features': result.top_features[:3]
                    })
                    result_idx += 1
                else:
                    predictions.append(self.predict(domain_data, brand, explain=False))
            
            return predictions
            
        except Exception as e:
            logger.error(f"Batch prediction failed: {e}")
            return [self.predict(d, brand, explain=False) for d in domains_data]
    
    def select_for_review(self, predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Select domains for active learning review.
        
        Args:
            predictions: List of prediction dictionaries (must include domain info)
            
        Returns:
            List of review candidate dictionaries with:
                - domain: str
                - ml_risk_score: int
                - ml_confidence: float
                - reason: str
        """
        if not self.active_learner or not self.enabled:
            return []
        
        # Convert to active learning format
        al_predictions = []
        for pred in predictions:
            if not pred.get('ml_enabled'):
                continue
            
            al_predictions.append({
                'domain': pred.get('domain', 'unknown'),
                'probability': pred['ml_risk_score'] / 100.0 if pred.get('ml_risk_score') else 0.5,
                'confidence': pred.get('ml_confidence', 0.0),
                'features': {}  # Features already extracted
            })
        
        if not al_predictions:
            return []
        
        try:
            candidates = self.active_learner.select_for_review(
                al_predictions,
                strategy='uncertainty'
            )
            
            # Convert to simple format
            review_list = []
            for candidate in candidates:
                review_list.append({
                    'domain': candidate.domain,
                    'ml_risk_score': int(candidate.prediction_prob * 100),
                    'ml_confidence': candidate.confidence,
                    'reason': candidate.reason
                })
            
            return review_list
            
        except Exception as e:
            logger.error(f"Active learning selection failed: {e}")
            return []
    
    def export_review_batch(self, output_path: str, predictions: List[Dict[str, Any]]) -> bool:
        """
        Export domains for manual review.
        
        Args:
            output_path: Path to export CSV file
            predictions: List of prediction dictionaries
            
        Returns:
            True if export successful
        """
        if not self.active_learner or not self.enabled:
            logger.warning("Active learning not enabled. Cannot export review batch.")
            return False
        
        try:
            candidates = self.select_for_review(predictions)
            if not candidates:
                logger.info("No domains selected for review")
                return False
            
            # Simple CSV export
            with open(output_path, 'w') as f:
                f.write("domain,ml_risk_score,ml_confidence,reason\n")
                for candidate in candidates:
                    f.write(
                        f"{candidate['domain']},"
                        f"{candidate['ml_risk_score']},"
                        f"{candidate['ml_confidence']:.3f},"
                        f'"{candidate["reason"]}"\n'
                    )
            
            logger.info(f"Exported {len(candidates)} domains for review to: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to export review batch: {e}")
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get ML integration statistics.
        
        Returns:
            Dictionary with ML status and stats
        """
        stats = {
            'ml_available': ML_AVAILABLE,
            'ml_enabled': self.enabled,
            'model_loaded': self.classifier is not None,
            'feature_extractor_loaded': self.feature_extractor is not None,
            'active_learning_enabled': self.active_learner is not None
        }
        
        if self.active_learner:
            al_stats = self.active_learner.get_labeling_stats()
            stats.update({
                'domains_labeled': al_stats['total_labeled'],
                'pending_review': al_stats['pending_review']
            })
        
        return stats


# Singleton instance
_ml_integration = None


def get_ml_integration(config=None) -> MLIntegration:
    """
    Get or create ML integration singleton.
    
    Args:
        config: Config object (required on first call)
        
    Returns:
        MLIntegration instance
    """
    global _ml_integration
    
    if _ml_integration is None and config:
        _ml_integration = MLIntegration(
            model_path=config.ml_model_path,
            confidence_threshold=config.ml_confidence_threshold,
            enable_active_learning=config.ml_enable_active_learning,
            uncertainty_threshold=config.ml_uncertainty_threshold,
            review_budget=config.ml_review_budget
        )
    
    return _ml_integration
