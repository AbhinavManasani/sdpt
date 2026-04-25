"""
Software Provenance Tracker — ML Training Data

Pre-loaded historical attack data and feature vector definitions
for the anomaly detection engine.

Contains:
  - Feature vector schema (what ML model sees)
  - Historical supply chain attacks (XZ Utils, event-stream, ua-parser-js, etc.)
  - Synthetic training samples derived from real attacks
  - Normal behavior samples for contrast

These are REAL historical incidents — not mock data.
"""

import logging
import numpy as np
from dataclasses import dataclass, field

logger = logging.getLogger("provenance.ml.training_data")


# ─── Feature Vector Schema ────────────────────────────────────

FEATURE_NAMES = [
    "account_age_days",       # 0: GitHub account age in days
    "repo_count",             # 1: Number of public repositories
    "avg_commits_per_week",   # 2: Average commits per week
    "followers",              # 3: Follower count
    "commit_hour_deviation",  # 4: Hours away from typical commit hour
    "is_new_maintainer",      # 5: 1 if first-time maintainer on this package
    "days_since_last_commit", # 6: Days since their last commit to this package
    "version_jump_size",      # 7: Semantic version change magnitude (0=patch, 1=minor, 2=major)
    "dependency_count_delta", # 8: Change in dependency count vs previous version
    "has_install_scripts",    # 9: 1 if package has preinstall/postinstall scripts
    "binary_files_added",     # 10: Number of binary/compiled files added
    "obfuscated_code_score",  # 11: Heuristic score for obfuscated code (0-1)
    "trust_score",            # 12: Composite trust score (0-100 normalized to 0-1)
    "typosquat_distance",     # 13: Levenshtein distance to nearest popular package name
    "contributor_count_change", # 14: Change in contributor count vs previous version
    "has_known_cve",          # 15: 1 if package has known CVEs
]

NUM_FEATURES = len(FEATURE_NAMES)


# ─── Historical Attack Data ──────────────────────────────────

@dataclass
class AttackCase:
    """A documented supply chain attack for training and pattern matching."""
    name: str
    year: int
    ecosystem: str
    package: str
    attack_type: str
    description: str
    indicators: dict = field(default_factory=dict)
    feature_vector: list[float] = field(default_factory=list)


# Real historical supply chain attacks
HISTORICAL_ATTACKS = [
    AttackCase(
        name="event-stream (flatmap-stream)",
        year=2018,
        ecosystem="npm",
        package="event-stream",
        attack_type="maintainer_takeover",
        description=(
            "A new maintainer (right9ctrl) took over the popular event-stream package "
            "from the original author. They added a dependency on flatmap-stream which "
            "contained obfuscated code targeting the Copay Bitcoin wallet, stealing "
            "cryptocurrency from users."
        ),
        indicators={
            "new_maintainer": True,
            "added_suspicious_dependency": "flatmap-stream",
            "obfuscated_payload": True,
            "targeted_specific_app": "Copay wallet",
            "original_author_inactive": True,
        },
        feature_vector=[
            180,   # account_age_days: ~6 months old
            3,     # repo_count: few repos
            1.0,   # avg_commits_per_week: low
            5,     # followers: very few
            6.0,   # commit_hour_deviation: different timezone
            1,     # is_new_maintainer: YES
            0,     # days_since_last_commit: first commit
            1,     # version_jump_size: minor
            1,     # dependency_count_delta: +1 (flatmap-stream)
            1,     # has_install_scripts: yes
            0,     # binary_files_added: 0
            0.8,   # obfuscated_code_score: highly obfuscated
            15.0,  # trust_score: very low
            100,   # typosquat_distance: not a typosquat
            1,     # contributor_count_change: +1 new
            0,     # has_known_cve: 0
        ],
    ),
    AttackCase(
        name="ua-parser-js hijack",
        year=2021,
        ecosystem="npm",
        package="ua-parser-js",
        attack_type="account_compromise",
        description=(
            "The npm account of ua-parser-js maintainer was compromised. "
            "Malicious versions 0.7.29, 0.8.0, 1.0.0 were published containing "
            "crypto miners and password stealers. Package had 7M+ weekly downloads."
        ),
        indicators={
            "account_compromised": True,
            "unusual_publish_time": True,
            "multiple_versions_rapid": True,
            "embedded_binary": True,
            "crypto_miner": True,
        },
        feature_vector=[
            2500,  # account_age_days: established account
            30,    # repo_count: many repos
            5.0,   # avg_commits_per_week: active
            200,   # followers: many (established)
            8.0,   # commit_hour_deviation: unusual hours
            0,     # is_new_maintainer: no (compromised)
            2,     # days_since_last_commit: recent
            2,     # version_jump_size: major jump
            3,     # dependency_count_delta: added deps
            1,     # has_install_scripts: yes
            2,     # binary_files_added: embedded binaries
            0.6,   # obfuscated_code_score: moderate
            70.0,  # trust_score: high (compromised account)
            100,   # typosquat_distance: legitimate package
            0,     # contributor_count_change: same
            0,     # has_known_cve: 0
        ],
    ),
    AttackCase(
        name="XZ Utils backdoor",
        year=2024,
        ecosystem="pypi",
        package="xz",
        attack_type="long_term_infiltration",
        description=(
            "Jia Tan (JiaT75) spent 2+ years contributing to XZ Utils, gradually "
            "building trust. Eventually inserted a sophisticated backdoor targeting "
            "SSH authentication on Linux systems. Discovered by Andres Freund when "
            "SSH logins became suspiciously slow."
        ),
        indicators={
            "long_term_social_engineering": True,
            "gradual_trust_building": True,
            "targeted_build_system": True,
            "binary_test_files": True,
            "complex_obfuscation": True,
            "pressured_original_maintainer": True,
        },
        feature_vector=[
            730,   # account_age_days: 2 years of building trust
            5,     # repo_count: focused repos
            3.0,   # avg_commits_per_week: steady contributor
            15,    # followers: moderate
            2.0,   # commit_hour_deviation: slight shift
            0,     # is_new_maintainer: no (earned trust over 2 years)
            7,     # days_since_last_commit: recent gap
            1,     # version_jump_size: minor
            0,     # dependency_count_delta: no change
            0,     # has_install_scripts: no (build system attack)
            3,     # binary_files_added: test files with hidden payload
            0.3,   # obfuscated_code_score: subtly hidden
            55.0,  # trust_score: moderate-high (earned over time)
            100,   # typosquat_distance: legitimate package
            0,     # contributor_count_change: same
            0,     # has_known_cve: 0
        ],
    ),
    AttackCase(
        name="colors.js / faker.js sabotage",
        year=2022,
        ecosystem="npm",
        package="colors",
        attack_type="maintainer_sabotage",
        description=(
            "The original maintainer Marak Squires deliberately sabotaged "
            "colors.js and faker.js by adding an infinite loop printing "
            "'LIBERTY LIBERTY LIBERTY'. Affected thousands of downstream projects "
            "including aws-cdk."
        ),
        indicators={
            "original_maintainer": True,
            "deliberate_sabotage": True,
            "infinite_loop": True,
            "protest_motivation": True,
        },
        feature_vector=[
            3650,  # account_age_days: 10+ years
            50,    # repo_count: many repos
            2.0,   # avg_commits_per_week: moderate
            500,   # followers: very popular
            1.0,   # commit_hour_deviation: normal
            0,     # is_new_maintainer: no (original author)
            30,    # days_since_last_commit: gap before sabotage
            2,     # version_jump_size: major
            0,     # dependency_count_delta: no change
            0,     # has_install_scripts: no
            0,     # binary_files_added: none
            0.1,   # obfuscated_code_score: not obfuscated
            90.0,  # trust_score: very high (trusted author)
            100,   # typosquat_distance: legitimate
            0,     # contributor_count_change: same
            0,     # has_known_cve: 0
        ],
    ),
    AttackCase(
        name="coa / rc npm hijack",
        year=2021,
        ecosystem="npm",
        package="coa",
        attack_type="account_compromise",
        description=(
            "Popular npm packages 'coa' and 'rc' were compromised via stolen "
            "maintainer credentials. Malicious versions deployed password-stealing "
            "malware. Affected React, Vue, and Angular CLI toolchains."
        ),
        indicators={
            "account_compromised": True,
            "rapid_version_publish": True,
            "preinstall_script": True,
            "downloads_malware": True,
        },
        feature_vector=[
            3000,  # account_age_days: established
            20,    # repo_count: moderate
            1.0,   # avg_commits_per_week: low recent activity
            100,   # followers: established
            10.0,  # commit_hour_deviation: very different timezone
            0,     # is_new_maintainer: no (compromised)
            180,   # days_since_last_commit: long gap
            1,     # version_jump_size: minor
            2,     # dependency_count_delta: added deps
            1,     # has_install_scripts: preinstall
            0,     # binary_files_added: downloads at runtime
            0.7,   # obfuscated_code_score: obfuscated
            65.0,  # trust_score: moderate-high
            100,   # typosquat_distance: legitimate
            0,     # contributor_count_change: same
            0,     # has_known_cve: 0
        ],
    ),
    AttackCase(
        name="crossenv typosquat",
        year=2017,
        ecosystem="npm",
        package="crossenv",
        attack_type="typosquatting",
        description=(
            "Malicious package 'crossenv' published to npm, typosquatting the "
            "popular 'cross-env' package. Contained a postinstall script that "
            "stole npm credentials and environment variables."
        ),
        indicators={
            "typosquat": True,
            "target_package": "cross-env",
            "postinstall_script": True,
            "credential_theft": True,
        },
        feature_vector=[
            30,    # account_age_days: brand new account
            1,     # repo_count: single repo
            0.5,   # avg_commits_per_week: minimal
            0,     # followers: zero
            0.0,   # commit_hour_deviation: N/A
            1,     # is_new_maintainer: yes (new account)
            0,     # days_since_last_commit: first publish
            0,     # version_jump_size: initial
            0,     # dependency_count_delta: N/A
            1,     # has_install_scripts: postinstall
            0,     # binary_files_added: 0
            0.5,   # obfuscated_code_score: moderate
            5.0,   # trust_score: very low
            1,     # typosquat_distance: distance=1 from cross-env
            0,     # contributor_count_change: N/A
            0,     # has_known_cve: 0
        ],
    ),
]


# ─── Normal Behavior Samples ─────────────────────────────────

def generate_normal_samples(count: int = 200, seed: int = 42) -> np.ndarray:
    """
    Generate synthetic normal contributor behavior samples
    based on distributions observed in legitimate open-source projects.

    Returns a (count, NUM_FEATURES) numpy array.
    """
    rng = np.random.RandomState(seed)

    samples = np.zeros((count, NUM_FEATURES))

    # account_age_days: mostly established accounts (1-10 years)
    samples[:, 0] = rng.lognormal(mean=6.5, sigma=1.0, size=count).clip(90, 5000)

    # repo_count: 5-100 repos
    samples[:, 1] = rng.lognormal(mean=2.5, sigma=0.8, size=count).clip(3, 200)

    # avg_commits_per_week: 1-20
    samples[:, 2] = rng.lognormal(mean=1.5, sigma=0.7, size=count).clip(0.5, 50)

    # followers: 5-500
    samples[:, 3] = rng.lognormal(mean=3.0, sigma=1.2, size=count).clip(1, 5000)

    # commit_hour_deviation: mostly close to typical (0-3 hours)
    samples[:, 4] = rng.exponential(scale=1.5, size=count).clip(0, 12)

    # is_new_maintainer: rarely (5% of normal)
    samples[:, 5] = (rng.random(count) < 0.05).astype(float)

    # days_since_last_commit: 0-60 for active contributors
    samples[:, 6] = rng.exponential(scale=10, size=count).clip(0, 365)

    # version_jump_size: mostly patch (0), sometimes minor (1)
    samples[:, 7] = rng.choice([0, 0, 0, 0, 1, 1, 2], size=count).astype(float)

    # dependency_count_delta: usually 0-2
    samples[:, 8] = rng.poisson(lam=0.5, size=count).clip(0, 10).astype(float)

    # has_install_scripts: 20% of packages
    samples[:, 9] = (rng.random(count) < 0.2).astype(float)

    # binary_files_added: rarely (mostly 0)
    samples[:, 10] = rng.poisson(lam=0.1, size=count).clip(0, 5).astype(float)

    # obfuscated_code_score: very low for normal packages
    samples[:, 11] = rng.beta(a=1, b=10, size=count)

    # trust_score: mostly high (50-100)
    samples[:, 12] = rng.normal(loc=65, scale=15, size=count).clip(20, 100)

    # typosquat_distance: high for legitimate packages (>5)
    samples[:, 13] = rng.normal(loc=50, scale=20, size=count).clip(3, 100)

    # contributor_count_change: usually 0-2
    samples[:, 14] = rng.poisson(lam=0.3, size=count).clip(0, 5).astype(float)

    # has_known_cve: rarely (maybe 2% of normal packages have active unpatched CVEs)
    samples[:, 15] = (rng.random(count) < 0.02).astype(float)

    return samples


def get_attack_vectors() -> np.ndarray:
    """
    Return feature vectors from all historical attacks as a numpy array.
    Shape: (num_attacks, NUM_FEATURES)
    """
    vectors = [attack.feature_vector for attack in HISTORICAL_ATTACKS]
    return np.array(vectors, dtype=float)


def get_training_dataset() -> tuple[np.ndarray, np.ndarray]:
    """
    Generate the full training dataset:
      - Normal samples (label=0)
      - Attack samples (label=1) — augmented from historical data

    Returns:
      (X, y) where X is (n_samples, NUM_FEATURES) and y is (n_samples,)
    """
    # Generate normal samples
    normal = generate_normal_samples(count=200)
    normal_labels = np.zeros(len(normal))

    # Get historical attack vectors
    attack_base = get_attack_vectors()

    # Augment attacks with slight variations (10 variants per attack)
    rng = np.random.RandomState(123)
    augmented_attacks = []
    for base_vector in attack_base:
        for _ in range(10):
            noise = rng.normal(0, 0.05, size=NUM_FEATURES) * base_vector
            variant = base_vector + noise
            variant = np.clip(variant, 0, None)  # No negative values
            augmented_attacks.append(variant)

    attack_samples = np.array(augmented_attacks)
    attack_labels = np.ones(len(attack_samples))

    # Combine
    X = np.vstack([normal, attack_samples])
    y = np.concatenate([normal_labels, attack_labels])

    logger.info(
        f"Training dataset: {len(normal)} normal + "
        f"{len(attack_samples)} attack samples = {len(X)} total"
    )

    return X, y


def normalize_feature_vector(raw: dict) -> list[float]:
    """
    Convert a raw feature dict into a normalized feature vector
    ready for the ML model.

    Normalization ranges (approximate):
      - account_age_days: /3650 (10 years max)
      - repo_count: /100
      - avg_commits_per_week: /20
      - followers: /1000
      - commit_hour_deviation: /12
      - is_new_maintainer: already 0/1
      - days_since_last_commit: /365
      - version_jump_size: /2
      - dependency_count_delta: /10
      - has_install_scripts: already 0/1
      - binary_files_added: /5
      - obfuscated_code_score: already 0-1
      - trust_score: /100
      - typosquat_distance: /100
      - contributor_count_change: /10
      - has_known_cve: already 0/1
    """
    divisors = [3650, 100, 20, 1000, 12, 1, 365, 2, 10, 1, 5, 1, 100, 100, 10, 1]

    vector = []
    for i, name in enumerate(FEATURE_NAMES):
        value = float(raw.get(name, 0))
        normalized = min(value / divisors[i], 1.0) if divisors[i] > 0 else value
        vector.append(normalized)

    return vector
