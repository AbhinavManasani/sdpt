"""
Software Provenance Tracker — Anomaly Detection API Router

Exposes REST endpoints for the ML anomaly detection engine:
  - Train the model
  - Score a contributor/package for anomalies
  - Get model status
  - Get historical attack catalog
"""

import logging

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from ml.anomaly_detector import AnomalyDetector
from ml.training_data import FEATURE_NAMES, HISTORICAL_ATTACKS

from auth.api_key import verify_api_key

logger = logging.getLogger("provenance.routers.anomaly")

router = APIRouter(prefix="/api/anomaly", tags=["anomaly"], dependencies=[Depends(verify_api_key)])


# ─── Request Models ───────────────────────────────────────────

class ScoreRequest(BaseModel):
    """Feature dict to score for anomaly detection."""
    account_age_days: float = Field(default=365, ge=0, description="GitHub account age in days")
    repo_count: float = Field(default=10, ge=0)
    avg_commits_per_week: float = Field(default=5, ge=0)
    followers: float = Field(default=10, ge=0)
    commit_hour_deviation: float = Field(default=0, ge=0, le=12)
    is_new_maintainer: float = Field(default=0, ge=0, le=1)
    days_since_last_commit: float = Field(default=7, ge=0)
    version_jump_size: float = Field(default=0, ge=0, le=2)
    dependency_count_delta: float = Field(default=0, ge=0)
    has_install_scripts: float = Field(default=0, ge=0, le=1)
    binary_files_added: float = Field(default=0, ge=0)
    obfuscated_code_score: float = Field(default=0, ge=0, le=1)
    trust_score: float = Field(default=50, ge=0, le=100)
    typosquat_distance: float = Field(default=50, ge=0)
    contributor_count_change: float = Field(default=0, ge=0)


# ─── Detector Instance ───────────────────────────────────────

_detector: AnomalyDetector | None = None


def setup_anomaly_engine() -> None:
    """Initialize the anomaly detector. Called during app startup."""
    global _detector
    _detector = AnomalyDetector()

    # Try to load existing model, train if none exists
    if not _detector.load_model():
        logger.info("No existing model found. Training on startup...")
        _detector.train()

    logger.info("Anomaly detection engine initialized")


def cleanup_anomaly_engine() -> None:
    """Clean up the anomaly detector. Called during app shutdown."""
    global _detector
    _detector = None


def get_anomaly_detector() -> AnomalyDetector | None:
    """Return the shared AnomalyDetector instance."""
    return _detector


def _get_detector() -> AnomalyDetector:
    """Get the detector instance, raising if not initialized."""
    if _detector is None:
        raise HTTPException(
            status_code=503,
            detail="Anomaly detector not initialized. Server may still be starting up.",
        )
    return _detector


# ─── Endpoints ────────────────────────────────────────────────


@router.post("/score")
async def score_anomaly(request: ScoreRequest):
    """
    Score a contributor/package event for anomaly likelihood.

    Accepts a feature vector and returns:
      - Combined anomaly score (0-100)
      - ML score and rule score breakdown
      - Risk level (low/medium/high/critical)
      - Triggered rules with details
      - Similar historical attacks
      - Human-readable explanation
    """
    detector = _get_detector()

    features = request.model_dump()

    try:
        result = detector.score(features)
    except Exception as e:
        logger.error(f"Scoring failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scoring failed: {str(e)}")

    return result


@router.post("/train")
async def train_model():
    """
    Train (or retrain) the Isolation Forest model.

    Uses the pre-loaded historical attack data and synthetic
    normal samples. Returns training statistics including
    detection rate and confusion matrix.
    """
    detector = _get_detector()

    try:
        stats = detector.train()
    except Exception as e:
        logger.error(f"Training failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")

    return stats


@router.get("/status")
async def get_model_status():
    """
    Get current model status.

    Returns whether the model is trained, feature count,
    feature names, and historical attack count.
    """
    detector = _get_detector()
    return detector.get_status()


@router.get("/attacks")
async def get_historical_attacks():
    """
    Get the catalog of historical supply chain attacks
    used for training and pattern matching.
    """
    attacks = []
    for attack in HISTORICAL_ATTACKS:
        attacks.append({
            "name": attack.name,
            "year": attack.year,
            "ecosystem": attack.ecosystem,
            "package": attack.package,
            "attack_type": attack.attack_type,
            "description": attack.description,
            "indicators": attack.indicators,
        })

    return {
        "total_attacks": len(attacks),
        "attacks": attacks,
    }


@router.get("/features")
async def get_feature_schema():
    """
    Get the feature vector schema.
    Lists all features with their index and name.
    """
    return {
        "feature_count": len(FEATURE_NAMES),
        "features": [
            {"index": i, "name": name}
            for i, name in enumerate(FEATURE_NAMES)
        ],
    }
