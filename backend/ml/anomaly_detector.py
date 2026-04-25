"""
Software Provenance Tracker — Anomaly Detector

Combined ML + rule-based anomaly detection engine.

Two detection layers:
  1. Isolation Forest (unsupervised ML) — learns normal behavior patterns
     and flags statistical outliers
  2. Rule-based hard flags — deterministic checks for known attack patterns
     that must ALWAYS trigger regardless of ML score

Final score = weighted combination of both layers.
"""

import logging
import pickle
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.training_data import (
    FEATURE_NAMES,
    NUM_FEATURES,
    HISTORICAL_ATTACKS,
    get_training_dataset,
    normalize_feature_vector,
)

logger = logging.getLogger("provenance.ml.anomaly_detector")

# Model persistence path
MODEL_DIR = Path(__file__).parent / "models"
MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"


class AnomalyDetector:
    """
    Combined ML + rule-based anomaly detection engine.

    Usage:
        detector = AnomalyDetector()
        detector.train()  # or detector.load_model()
        result = detector.score(feature_dict)
    """

    # Weights for combining ML and rule scores
    ML_WEIGHT = 0.4
    RULE_WEIGHT = 0.6

    def __init__(self):
        self._model: IsolationForest | None = None
        self._scaler: StandardScaler | None = None
        self._is_trained = False

    # ─── Training ─────────────────────────────────────────────

    def train(self) -> dict:
        """
        Train the Isolation Forest on the historical + synthetic dataset.
        Saves the trained model to disk.

        Returns training stats.
        """
        logger.info("Training anomaly detection model...")

        X, y = get_training_dataset()

        # Fit the scaler on ALL data (normal + attack patterns)
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Train Isolation Forest on NORMAL data only
        # The model learns what "normal" looks like, then flags deviations
        normal_mask = y == 0
        X_normal = X_scaled[normal_mask]

        self._model = IsolationForest(
            n_estimators=200,
            contamination=0.1,  # Expect ~10% anomalies in real data
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_normal)
        self._is_trained = True

        # Evaluate on the full dataset
        predictions = self._model.predict(X_scaled)
        scores = self._model.decision_function(X_scaled)

        # Calculate metrics
        attack_mask = y == 1
        true_positive = np.sum((predictions[attack_mask] == -1))
        false_negative = np.sum((predictions[attack_mask] == 1))
        true_negative = np.sum((predictions[normal_mask] == 1))
        false_positive = np.sum((predictions[normal_mask] == -1))

        total_attacks = np.sum(attack_mask)
        detection_rate = true_positive / total_attacks if total_attacks > 0 else 0

        # Save model
        self._save_model()

        stats = {
            "status": "trained",
            "total_samples": len(X),
            "normal_samples": int(np.sum(normal_mask)),
            "attack_samples": int(np.sum(attack_mask)),
            "detection_rate": round(detection_rate, 3),
            "true_positives": int(true_positive),
            "false_negatives": int(false_negative),
            "true_negatives": int(true_negative),
            "false_positives": int(false_positive),
            "model_path": str(MODEL_PATH),
        }

        logger.info(
            f"Model trained: {stats['detection_rate']*100:.1f}% detection rate, "
            f"TP={true_positive} FN={false_negative} TN={true_negative} FP={false_positive}"
        )

        return stats

    def _save_model(self) -> None:
        """Save trained model and scaler to disk."""
        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self._model, f)
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(self._scaler, f)

        logger.info(f"Model saved to {MODEL_PATH}")

    def load_model(self) -> bool:
        """
        Load a previously trained model from disk.
        Returns True if loaded successfully, False if no model exists.
        """
        if not MODEL_PATH.exists() or not SCALER_PATH.exists():
            logger.warning("No saved model found. Call train() first.")
            return False

        with open(MODEL_PATH, "rb") as f:
            self._model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            self._scaler = pickle.load(f)

        self._is_trained = True
        logger.info("Model loaded from disk")
        return True

    # ─── Scoring ──────────────────────────────────────────────

    def score(self, features: dict) -> dict:
        """
        Score a contributor/package event for anomaly likelihood.

        Args:
            features: Dict with keys matching FEATURE_NAMES

        Returns:
            {
                "anomaly_score": float 0-100 (higher = more suspicious),
                "ml_score": float 0-100,
                "rule_score": float 0-100,
                "is_anomaly": bool,
                "risk_level": "low" | "medium" | "high" | "critical",
                "triggered_rules": [...],
                "similar_attacks": [...],
                "explanation": str,
            }
        """
        if not self._is_trained:
            # Try loading from disk
            if not self.load_model():
                raise RuntimeError(
                    "Model not trained. Call train() or load_model() first."
                )

        # Normalize features
        feature_vector = normalize_feature_vector(features)
        X = np.array([feature_vector])

        # ML score from Isolation Forest
        ml_score = self._get_ml_score(X)

        # Rule-based score
        rule_result = self._apply_rules(features)
        rule_score = rule_result["score"]

        # Combined score (weighted)
        combined_score = (
            ml_score * self.ML_WEIGHT + rule_score * self.RULE_WEIGHT
        )
        combined_score = min(combined_score, 100.0)

        # Determine risk level
        risk_level = self._classify_risk(combined_score, rule_result["triggered"])

        # Find similar historical attacks
        similar = self._find_similar_attacks(feature_vector)

        # Generate explanation
        explanation = self._generate_explanation(
            ml_score, rule_result, risk_level, similar
        )

        return {
            "anomaly_score": round(float(combined_score), 1),
            "ml_score": round(float(ml_score), 1),
            "rule_score": round(float(rule_score), 1),
            "is_anomaly": bool(combined_score >= 50),
            "risk_level": risk_level,
            "triggered_rules": rule_result["triggered"],
            "similar_attacks": similar,
            "explanation": explanation,
            "feature_vector": [float(x) for x in feature_vector],
            "scored_at": datetime.now(timezone.utc).isoformat(),
        }

    def _get_ml_score(self, X: np.ndarray) -> float:
        """
        Get anomaly score from Isolation Forest.
        Converts sklearn's decision_function (negative = anomalous)
        to a 0-100 scale (higher = more anomalous).
        """
        X_scaled = self._scaler.transform(X)

        # decision_function: negative values = anomalous, positive = normal
        raw_score = self._model.decision_function(X_scaled)[0]

        # Convert to 0-100 where higher = more anomalous
        # Typical range is roughly [-0.5, 0.5]
        # Map: -0.5 → 100, 0 → 50, 0.5 → 0
        score = max(0, min(100, 50 - (raw_score * 100)))

        return score

    # ─── Rule-Based Engine ────────────────────────────────────

    def _apply_rules(self, features: dict) -> dict:
        """
        Apply deterministic rules that flag known attack patterns.
        Returns a score (0-100) and list of triggered rules.
        """
        triggered = []
        score = 0.0

        # Rule 1: Brand new account publishing packages
        account_age = features.get("account_age_days", 999)
        if account_age < 30:
            triggered.append({
                "rule": "BRAND_NEW_ACCOUNT",
                "severity": "critical",
                "detail": f"Account is only {account_age} days old",
                "score_contribution": 40,
            })
            score += 40
        elif account_age < 90:
            triggered.append({
                "rule": "YOUNG_ACCOUNT",
                "severity": "high",
                "detail": f"Account is only {account_age} days old",
                "score_contribution": 25,
            })
            score += 25

        # Rule 2: New maintainer on established package
        if features.get("is_new_maintainer", 0) == 1:
            triggered.append({
                "rule": "NEW_MAINTAINER",
                "severity": "high",
                "detail": "First-time maintainer on this package",
                "score_contribution": 30,
            })
            score += 30

        # Rule 3: Install scripts present
        if features.get("has_install_scripts", 0) == 1:
            triggered.append({
                "rule": "INSTALL_SCRIPTS",
                "severity": "low",
                "detail": "Package has preinstall or postinstall scripts",
                "score_contribution": 5,
            })
            score += 5

        # Rule 4: Obfuscated code detected
        obfuscation = features.get("obfuscated_code_score", 0)
        if obfuscation > 0.5:
            severity = "critical" if obfuscation > 0.7 else "high"
            triggered.append({
                "rule": "OBFUSCATED_CODE",
                "severity": severity,
                "detail": f"Code obfuscation score: {obfuscation:.2f}",
                "score_contribution": 35,
            })
            score += 35

        # Rule 5: Typosquatting
        typo_distance = features.get("typosquat_distance", 100)
        if typo_distance <= 2:
            triggered.append({
                "rule": "TYPOSQUAT",
                "severity": "critical",
                "detail": f"Levenshtein distance {typo_distance} to popular package",
                "score_contribution": 45,
            })
            score += 45

        # Rule 6: Binary files added
        binaries = features.get("binary_files_added", 0)
        if binaries > 0:
            triggered.append({
                "rule": "BINARY_ADDED",
                "severity": "high",
                "detail": f"{binaries} binary file(s) added",
                "score_contribution": 20,
            })
            score += 20

        # Rule 7: Large dependency count change
        dep_delta = features.get("dependency_count_delta", 0)
        if dep_delta > 5:
            triggered.append({
                "rule": "DEPENDENCY_EXPLOSION",
                "severity": "high",
                "detail": f"Added {dep_delta} new dependencies",
                "score_contribution": 20,
            })
            score += 20

        # Rule 8: Very low trust score
        trust = features.get("trust_score", 100)
        if trust < 15:
            triggered.append({
                "rule": "EXTREMELY_LOW_TRUST",
                "severity": "critical",
                "detail": f"Trust score {trust}/100",
                "score_contribution": 30,
            })
            score += 30

        # Rule: Known CVE exists for this package
        if features.get("has_known_cve", 0) == 1:
            triggered.append({
                "rule": "KNOWN_CVE",
                "severity": "high",
                "detail": "Package has known CVEs in NVD database",
                "score_contribution": 30,
            })
            score += 30

        # Rule 9: Commit hour deviation (potential timezone change / compromise)
        hour_dev = features.get("commit_hour_deviation", 0)
        if hour_dev > 8:
            triggered.append({
                "rule": "TIMEZONE_SHIFT",
                "severity": "medium",
                "detail": f"Commit hour shifted by {hour_dev}h from baseline",
                "score_contribution": 15,
            })
            score += 15

        # Rule 10: Dormant contributor suddenly active
        days_since = features.get("days_since_last_commit", 0)
        if days_since > 180:
            triggered.append({
                "rule": "DORMANT_REACTIVATION",
                "severity": "medium",
                "detail": f"Contributor was dormant for {days_since} days",
                "score_contribution": 15,
            })
            score += 15

        # Cap at 100
        score = min(score, 100.0)

        return {"score": score, "triggered": triggered}

    # ─── Risk Classification ──────────────────────────────────

    @staticmethod
    def _classify_risk(
        combined_score: float, triggered_rules: list
    ) -> str:
        """
        Classify risk level based on combined score and rule severity.
        Critical rules can escalate the risk level.
        """
        # Check for critical rules
        has_critical = any(r["severity"] == "critical" for r in triggered_rules)
        has_high = any(r["severity"] == "high" for r in triggered_rules)

        if combined_score >= 75 or (has_critical and combined_score >= 40):
            return "critical"
        elif combined_score >= 50 or (has_high and combined_score >= 30):
            return "high"
        elif combined_score >= 25:
            return "medium"
        else:
            return "low"

    # ─── Similar Attack Matching ──────────────────────────────

    @staticmethod
    def _find_similar_attacks(
        feature_vector: list[float], top_n: int = 3
    ) -> list[dict]:
        """
        Find historical attacks most similar to the given feature vector.
        Uses cosine similarity on normalized vectors.
        """
        query = np.array(feature_vector)
        query_norm = np.linalg.norm(query)
        if query_norm == 0:
            return []

        similarities = []
        for attack in HISTORICAL_ATTACKS:
            # Normalize the attack vector the same way
            attack_divisors = [3650, 100, 20, 1000, 12, 1, 365, 2, 10, 1, 5, 1, 100, 100, 10, 1]
            attack_normalized = [
                min(v / d, 1.0) if d > 0 else v
                for v, d in zip(attack.feature_vector, attack_divisors)
            ]
            attack_vec = np.array(attack_normalized)
            attack_norm = np.linalg.norm(attack_vec)

            if attack_norm == 0:
                continue

            cosine_sim = np.dot(query, attack_vec) / (query_norm * attack_norm)
            similarities.append((attack, float(cosine_sim)))

        # Sort by similarity (highest first)
        similarities.sort(key=lambda x: x[1], reverse=True)

        results = []
        for attack, sim in similarities[:top_n]:
            if sim > 0.3:  # Only include if reasonably similar
                results.append({
                    "attack_name": attack.name,
                    "year": attack.year,
                    "attack_type": attack.attack_type,
                    "similarity": round(sim, 3),
                    "description": attack.description,
                })

        return results

    # ─── Explanation Generator ────────────────────────────────

    @staticmethod
    def _generate_explanation(
        ml_score: float,
        rule_result: dict,
        risk_level: str,
        similar_attacks: list,
    ) -> str:
        """Generate a human-readable explanation of the anomaly score."""
        parts = []

        if risk_level == "critical":
            parts.append("⚠️ CRITICAL RISK DETECTED.")
        elif risk_level == "high":
            parts.append("🔴 HIGH RISK flagged.")
        elif risk_level == "medium":
            parts.append("🟡 MEDIUM RISK — warrants investigation.")
        else:
            parts.append("🟢 LOW RISK — appears normal.")

        # ML insight
        if ml_score >= 60:
            parts.append(
                f"ML model flagged this as statistically unusual "
                f"(anomaly score: {ml_score:.0f}/100)."
            )

        # Triggered rules
        triggered = rule_result["triggered"]
        if triggered:
            critical_rules = [r for r in triggered if r["severity"] == "critical"]
            high_rules = [r for r in triggered if r["severity"] == "high"]

            if critical_rules:
                names = ", ".join(r["rule"] for r in critical_rules)
                parts.append(f"Critical rules triggered: {names}.")
            if high_rules:
                names = ", ".join(r["rule"] for r in high_rules)
                parts.append(f"High-severity rules: {names}.")

        # Similar attacks
        if similar_attacks:
            top = similar_attacks[0]
            parts.append(
                f"Most similar to '{top['attack_name']}' ({top['year']}) — "
                f"{top['similarity']*100:.0f}% match."
            )

        return " ".join(parts)

    # ─── Batch Scoring ────────────────────────────────────────

    def score_batch(self, feature_list: list[dict]) -> list[dict]:
        """Score multiple feature dicts at once."""
        return [self.score(features) for features in feature_list]

    # ─── Model Status ─────────────────────────────────────────

    def get_status(self) -> dict:
        """Get current model status."""
        return {
            "is_trained": self._is_trained,
            "model_exists_on_disk": MODEL_PATH.exists(),
            "model_path": str(MODEL_PATH),
            "feature_count": NUM_FEATURES,
            "feature_names": FEATURE_NAMES,
            "historical_attacks_loaded": len(HISTORICAL_ATTACKS),
            "ml_weight": self.ML_WEIGHT,
            "rule_weight": self.RULE_WEIGHT,
        }
