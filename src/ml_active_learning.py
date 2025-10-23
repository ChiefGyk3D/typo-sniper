"""
Active learning system for typosquatting detection.

Intelligently selects uncertain predictions for human review to improve
model performance with minimal labeling effort. Implements uncertainty
sampling and tracks model disagreement over versions.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import numpy as np


@dataclass
class ReviewCandidate:
    """Domain selected for human review."""
    domain: str
    confidence: float
    prediction_prob: float
    reason: str  # Why selected for review
    features: Dict[str, float]
    timestamp: str


@dataclass
class HumanLabel:
    """Human-provided label for active learning."""
    domain: str
    is_typosquat: bool
    reviewer: str
    timestamp: str
    notes: Optional[str] = None


class ActiveLearner:
    """
    Active learning selector for typosquatting detection.
    
    Implements uncertainty sampling to identify domains that would
    provide most value if labeled by a human expert.
    
    Strategies:
    1. Uncertainty Sampling: Select predictions near decision boundary (0.5)
    2. Confidence Gap: Select when model is uncertain
    3. Disagreement Tracking: Select when multiple model versions disagree
    """
    
    def __init__(
        self,
        uncertainty_threshold: float = 0.15,
        min_confidence_gap: float = 0.1,
        review_budget: int = 100
    ):
        """
        Initialize active learner.
        
        Args:
            uncertainty_threshold: How close to 0.5 to consider uncertain (0.4-0.6)
            min_confidence_gap: Minimum gap between top predictions for selection
            review_budget: Maximum domains to select per batch
        """
        self.uncertainty_threshold = uncertainty_threshold
        self.min_confidence_gap = min_confidence_gap
        self.review_budget = review_budget
        
        self.review_queue: List[ReviewCandidate] = []
        self.labeled_domains: Dict[str, HumanLabel] = {}
        self.reviewed_domains: Set[str] = set()
    
    def select_for_review(
        self,
        predictions: List[Dict[str, any]],
        strategy: str = 'uncertainty'
    ) -> List[ReviewCandidate]:
        """
        Select domains for human review.
        
        Args:
            predictions: List of prediction dictionaries with:
                - domain: str
                - probability: float (0-1)
                - confidence: float (0-1)
                - features: Dict[str, float]
            strategy: Selection strategy ('uncertainty', 'random', 'high_risk')
            
        Returns:
            List of review candidates
        """
        if strategy == 'uncertainty':
            candidates = self._uncertainty_sampling(predictions)
        elif strategy == 'random':
            candidates = self._random_sampling(predictions)
        elif strategy == 'high_risk':
            candidates = self._high_risk_sampling(predictions)
        else:
            raise ValueError(f"Unknown strategy: {strategy}")
        
        # Limit to budget
        candidates = candidates[:self.review_budget]
        
        # Add to queue
        self.review_queue.extend(candidates)
        
        return candidates
    
    def _uncertainty_sampling(self, predictions: List[Dict]) -> List[ReviewCandidate]:
        """
        Select predictions with highest uncertainty (closest to decision boundary).
        
        Prioritizes domains where model is most uncertain.
        """
        candidates = []
        
        for pred in predictions:
            domain = pred['domain']
            prob = pred['probability']
            confidence = pred['confidence']
            features = pred.get('features', {})
            
            # Skip already reviewed
            if domain in self.reviewed_domains:
                continue
            
            # Calculate uncertainty (distance from 0.5)
            uncertainty = abs(prob - 0.5)
            
            # Select if within uncertainty threshold
            if uncertainty <= self.uncertainty_threshold:
                reason = f"Uncertain prediction (prob={prob:.3f}, uncertainty={uncertainty:.3f})"
                
                candidate = ReviewCandidate(
                    domain=domain,
                    confidence=confidence,
                    prediction_prob=prob,
                    reason=reason,
                    features=features,
                    timestamp=datetime.now().isoformat()
                )
                
                candidates.append(candidate)
        
        # Sort by uncertainty (most uncertain first)
        candidates.sort(key=lambda c: abs(c.prediction_prob - 0.5))
        
        return candidates
    
    def _random_sampling(self, predictions: List[Dict]) -> List[ReviewCandidate]:
        """Random sampling baseline."""
        candidates = []
        
        for pred in predictions:
            domain = pred['domain']
            
            if domain in self.reviewed_domains:
                continue
            
            candidate = ReviewCandidate(
                domain=domain,
                confidence=pred['confidence'],
                prediction_prob=pred['probability'],
                reason="Random selection",
                features=pred.get('features', {}),
                timestamp=datetime.now().isoformat()
            )
            
            candidates.append(candidate)
        
        # Shuffle
        np.random.shuffle(candidates)
        
        return candidates
    
    def _high_risk_sampling(self, predictions: List[Dict]) -> List[ReviewCandidate]:
        """
        Select high-risk predictions for verification.
        
        Focuses on domains classified as typosquats with medium-high confidence.
        """
        candidates = []
        
        for pred in predictions:
            domain = pred['domain']
            prob = pred['probability']
            confidence = pred['confidence']
            
            if domain in self.reviewed_domains:
                continue
            
            # Select if classified as typosquat (prob > 0.5) but not 100% confident
            if prob > 0.5 and confidence < 0.9:
                reason = f"High risk with medium confidence (prob={prob:.3f})"
                
                candidate = ReviewCandidate(
                    domain=domain,
                    confidence=confidence,
                    prediction_prob=prob,
                    reason=reason,
                    features=pred.get('features', {}),
                    timestamp=datetime.now().isoformat()
                )
                
                candidates.append(candidate)
        
        # Sort by probability (highest risk first)
        candidates.sort(key=lambda c: c.prediction_prob, reverse=True)
        
        return candidates
    
    def detect_disagreement(
        self,
        predictions_v1: List[Dict],
        predictions_v2: List[Dict],
        disagreement_threshold: float = 0.3
    ) -> List[ReviewCandidate]:
        """
        Detect domains where two model versions disagree.
        
        Useful for identifying edge cases and distribution shift.
        
        Args:
            predictions_v1: Predictions from model version 1
            predictions_v2: Predictions from model version 2
            disagreement_threshold: Minimum probability difference to consider disagreement
            
        Returns:
            Domains with significant disagreement
        """
        # Create lookup for v2 predictions
        v2_lookup = {p['domain']: p['probability'] for p in predictions_v2}
        
        candidates = []
        
        for pred_v1 in predictions_v1:
            domain = pred_v1['domain']
            prob_v1 = pred_v1['probability']
            
            if domain not in v2_lookup or domain in self.reviewed_domains:
                continue
            
            prob_v2 = v2_lookup[domain]
            
            # Check for disagreement
            disagreement = abs(prob_v1 - prob_v2)
            
            if disagreement >= disagreement_threshold:
                reason = f"Model disagreement (v1={prob_v1:.3f}, v2={prob_v2:.3f}, diff={disagreement:.3f})"
                
                candidate = ReviewCandidate(
                    domain=domain,
                    confidence=min(pred_v1['confidence'], 1.0),
                    prediction_prob=(prob_v1 + prob_v2) / 2,  # Average
                    reason=reason,
                    features=pred_v1.get('features', {}),
                    timestamp=datetime.now().isoformat()
                )
                
                candidates.append(candidate)
        
        # Sort by disagreement magnitude
        candidates.sort(key=lambda c: abs(0.5 - c.prediction_prob), reverse=True)
        
        return candidates
    
    def add_human_label(
        self,
        domain: str,
        is_typosquat: bool,
        reviewer: str,
        notes: Optional[str] = None
    ):
        """
        Add human-provided label.
        
        Args:
            domain: Domain name
            is_typosquat: True if typosquat, False if legitimate
            reviewer: Name/ID of reviewer
            notes: Optional notes about the decision
        """
        label = HumanLabel(
            domain=domain,
            is_typosquat=is_typosquat,
            reviewer=reviewer,
            timestamp=datetime.now().isoformat(),
            notes=notes
        )
        
        self.labeled_domains[domain] = label
        self.reviewed_domains.add(domain)
        
        # Remove from review queue if present
        self.review_queue = [c for c in self.review_queue if c.domain != domain]
    
    def get_training_data(self) -> Tuple[List[str], List[int]]:
        """
        Get labeled domains for retraining.
        
        Returns:
            Tuple of (domain_list, label_list) where label is 1 for typosquat, 0 for legit
        """
        domains = []
        labels = []
        
        for domain, label in self.labeled_domains.items():
            domains.append(domain)
            labels.append(1 if label.is_typosquat else 0)
        
        return domains, labels
    
    def get_review_queue(self, top_n: Optional[int] = None) -> List[ReviewCandidate]:
        """
        Get pending review queue.
        
        Args:
            top_n: Limit to top N candidates
            
        Returns:
            List of review candidates
        """
        if top_n:
            return self.review_queue[:top_n]
        return self.review_queue
    
    def get_labeling_stats(self) -> Dict[str, any]:
        """Get statistics about labeling progress."""
        total_labeled = len(self.labeled_domains)
        typosquats = sum(1 for l in self.labeled_domains.values() if l.is_typosquat)
        legit = total_labeled - typosquats
        
        return {
            'total_labeled': total_labeled,
            'typosquats': typosquats,
            'legitimate': legit,
            'class_ratio': typosquats / max(total_labeled, 1),
            'pending_review': len(self.review_queue),
            'total_reviewed': len(self.reviewed_domains)
        }
    
    def save_state(self, path: str):
        """Save active learning state to disk."""
        state = {
            'review_queue': [asdict(c) for c in self.review_queue],
            'labeled_domains': {k: asdict(v) for k, v in self.labeled_domains.items()},
            'reviewed_domains': list(self.reviewed_domains),
            'config': {
                'uncertainty_threshold': self.uncertainty_threshold,
                'min_confidence_gap': self.min_confidence_gap,
                'review_budget': self.review_budget
            }
        }
        
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self, path: str):
        """Load active learning state from disk."""
        with open(path, 'r') as f:
            state = json.load(f)
        
        self.review_queue = [ReviewCandidate(**c) for c in state['review_queue']]
        self.labeled_domains = {k: HumanLabel(**v) for k, v in state['labeled_domains'].items()}
        self.reviewed_domains = set(state['reviewed_domains'])
        
        config = state.get('config', {})
        self.uncertainty_threshold = config.get('uncertainty_threshold', self.uncertainty_threshold)
        self.min_confidence_gap = config.get('min_confidence_gap', self.min_confidence_gap)
        self.review_budget = config.get('review_budget', self.review_budget)
    
    def export_review_batch(self, path: str, batch_size: int = 50):
        """
        Export a batch of domains for review in simple format.
        
        Creates a CSV-like file for easy manual review.
        """
        candidates = self.get_review_queue(batch_size)
        
        with open(path, 'w') as f:
            f.write("domain,prediction_prob,confidence,reason\n")
            for candidate in candidates:
                f.write(f"{candidate.domain},{candidate.prediction_prob:.3f},{candidate.confidence:.3f},\"{candidate.reason}\"\n")
    
    def import_reviewed_batch(self, path: str, reviewer: str):
        """
        Import reviewed batch with labels.
        
        Expected format: domain,is_typosquat,notes
        """
        with open(path, 'r') as f:
            lines = f.readlines()[1:]  # Skip header
        
        for line in lines:
            parts = line.strip().split(',')
            if len(parts) < 2:
                continue
            
            domain = parts[0]
            is_typosquat = parts[1].lower() in ('true', '1', 'yes')
            notes = parts[2] if len(parts) > 2 else None
            
            self.add_human_label(domain, is_typosquat, reviewer, notes)


def main():
    """Example usage."""
    print("=== Active Learning Example ===\n")
    
    # Create learner
    learner = ActiveLearner(
        uncertainty_threshold=0.15,
        review_budget=10
    )
    
    # Simulate predictions
    np.random.seed(42)
    predictions = []
    
    for i in range(100):
        prob = np.random.random()
        confidence = abs(prob - 0.5) * 2
        
        predictions.append({
            'domain': f'domain{i}.com',
            'probability': prob,
            'confidence': confidence,
            'features': {'feature_1': np.random.randn()}
        })
    
    # Select for review
    print("Selecting uncertain predictions for review...")
    candidates = learner.select_for_review(predictions, strategy='uncertainty')
    
    print(f"\nSelected {len(candidates)} domains for review:\n")
    for i, candidate in enumerate(candidates[:5], 1):
        print(f"{i}. {candidate.domain}")
        print(f"   Probability: {candidate.prediction_prob:.3f}")
        print(f"   Confidence: {candidate.confidence:.3f}")
        print(f"   Reason: {candidate.reason}\n")
    
    # Simulate human labeling
    print("Simulating human labeling...")
    for candidate in candidates[:3]:
        # Randomly assign label (in real use, human provides this)
        is_typosquat = candidate.prediction_prob > 0.5
        learner.add_human_label(
            candidate.domain,
            is_typosquat,
            reviewer="analyst_1",
            notes="Reviewed manually"
        )
    
    # Get stats
    stats = learner.get_labeling_stats()
    print(f"\n=== Labeling Stats ===")
    print(f"Total labeled:   {stats['total_labeled']}")
    print(f"Typosquats:      {stats['typosquats']}")
    print(f"Legitimate:      {stats['legitimate']}")
    print(f"Pending review:  {stats['pending_review']}")
    print(f"Total reviewed:  {stats['total_reviewed']}")
    
    # Get training data
    domains, labels = learner.get_training_data()
    print(f"\nTraining data: {len(domains)} domains with labels")


if __name__ == '__main__':
    main()
