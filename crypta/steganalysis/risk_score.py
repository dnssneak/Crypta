"""
Risk Scoring Engine for Crypta Steganalysis.
Computes a normalized, explainable 0–100 steganography risk score based on weighted statistical indicators.
"""

import math
from typing import Dict, List, Any
from crypta.utils.constants import (
    RISK_LEVEL_LOW,
    RISK_LEVEL_MODERATE,
    RISK_LEVEL_HIGH,
    RISK_LEVEL_VERY_HIGH,
    RISK_THRESHOLD_LOW_MAX,
    RISK_THRESHOLD_MODERATE_MAX,
    RISK_THRESHOLD_HIGH_MAX,
    RISK_WEIGHT_LSB,
    RISK_WEIGHT_CHI_SQUARE,
    RISK_WEIGHT_HISTOGRAM,
    RISK_WEIGHT_ENTROPY,
    RISK_WEIGHT_PIXEL_STATS,
)
from crypta.steganalysis.results import (
    AnalysisResult,
    EntropyResult,
    LSBResult,
    ChiSquareResult,
    HistogramResult,
    PixelStatsResult,
    RiskAssessment,
)
from crypta.steganalysis.assessment import (
    generate_observations,
    generate_assessment_summary,
)


def clamp(val: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Clamp a floating point value to the range [min_val, max_val]. Handles NaN/Inf safely."""
    if math.isnan(val) or math.isinf(val):
        return min_val
    return max(min_val, min(max_val, val))


def normalize_range(val: float, minimum: float, maximum: float) -> float:
    """Normalize a value within [minimum, maximum] to a 0–100 scale."""
    if math.isnan(val) or math.isinf(val):
        return 0.0
    if minimum >= maximum:
        return 0.0
    clamped_val = max(minimum, min(maximum, val))
    return ((clamped_val - minimum) / (maximum - minimum)) * 100.0


def get_risk_level(score: float) -> str:
    """Map a 0–100 numerical risk score to a risk level classification string.

    Scale:
      0–29    : LOW
      30–59   : MODERATE
      60–79   : HIGH
      80–100  : VERY HIGH
    """
    s = clamp(score, 0.0, 100.0)
    if s <= RISK_THRESHOLD_LOW_MAX:
        return RISK_LEVEL_LOW
    elif s <= RISK_THRESHOLD_MODERATE_MAX:
        return RISK_LEVEL_MODERATE
    elif s <= RISK_THRESHOLD_HIGH_MAX:
        return RISK_LEVEL_HIGH
    else:
        return RISK_LEVEL_VERY_HIGH


def score_entropy(entropy_result: EntropyResult, analyzed_channels: List[str]) -> float:
    """Calculate 0–100 risk score for Shannon entropy.

    Alpha channel is excluded. Near-maximum entropy (~7.95-8.00) indicates high randomness.
    """
    channels = [c for c in analyzed_channels if c.upper() != "A"]
    if not channels or not entropy_result.per_channel_entropy:
        return 0.0

    scores = []
    for ch in channels:
        ent = entropy_result.per_channel_entropy.get(ch, 0.0)
        # Scale entropy in range 5.0 to 7.98 -> 0 to 100
        sc = normalize_range(ent, 5.0, 7.98)
        scores.append(sc)

    return clamp(sum(scores) / len(scores)) if scores else 0.0


def score_lsb(lsb_result: LSBResult, analyzed_channels: List[str]) -> float:
    """Calculate 0–100 risk score for LSB 0/1 distribution.

    Alpha channel is excluded. Lower deviation from 50% (near 0%) indicates high LSB equalization.
    """
    channels = [c for c in analyzed_channels if c.upper() != "A"]
    if not channels or not lsb_result.deviations:
        return 0.0

    scores = []
    for ch in channels:
        dev = lsb_result.deviations.get(ch, 10.0)
        # Deviation 0.0% -> 100 score, Deviation >= 12.0% -> 0 score
        if dev <= 0.2:
            sc = 100.0
        elif dev >= 12.0:
            sc = 0.0
        else:
            sc = ((12.0 - dev) / 11.8) * 100.0
        scores.append(sc)

    return clamp(sum(scores) / len(scores)) if scores else 0.0


def score_chi_square(chi_result: ChiSquareResult, analyzed_channels: List[str]) -> float:
    """Calculate 0–100 risk score for Chi-Square Pairs-of-Values test.

    Alpha channel is excluded. Low p-value (p < 0.05) indicates PoV flattening.
    """
    channels = [c for c in analyzed_channels if c.upper() != "A"]
    if not channels or not chi_result.p_values:
        return 0.0

    scores = []
    for ch in channels:
        pval = chi_result.p_values.get(ch)
        if pval is None or math.isnan(pval):
            sc = 0.0
        else:
            sc = (1.0 - clamp(pval, 0.0, 1.0)) * 100.0
        scores.append(sc)

    return clamp(sum(scores) / len(scores)) if scores else 0.0


def score_histogram(histogram_result: HistogramResult, analyzed_channels: List[str]) -> float:
    """Calculate 0–100 risk score for adjacent histogram pair ratios.

    Alpha channel is excluded. Pair ratio near 1.0 (difference near 0.0) indicates PoV flattening.
    """
    channels = [c for c in analyzed_channels if c.upper() != "A"]
    if not channels or not histogram_result.adjacent_pair_ratios:
        return 0.0

    scores = []
    for ch in channels:
        ratio = histogram_result.adjacent_pair_ratios.get(ch, 0.0)
        diff = abs(ratio - 1.0)
        # Diff <= 0.02 -> 100 score, Diff >= 0.25 -> 0 score
        if diff <= 0.02:
            sc = 100.0
        elif diff >= 0.25:
            sc = 0.0
        else:
            sc = ((0.25 - diff) / 0.23) * 100.0
        scores.append(sc)

    return clamp(sum(scores) / len(scores)) if scores else 0.0


def score_pixel_stats(pixel_result: PixelStatsResult, analyzed_channels: List[str]) -> float:
    """Calculate 0–100 risk score for pixel LSB transition frequencies.

    Alpha channel is excluded. Transition frequency near 0.50 indicates randomized LSBs.
    """
    channels = [c for c in analyzed_channels if c.upper() != "A"]
    if not channels or not pixel_result.lsb_transition_frequencies:
        return 0.0

    scores = []
    for ch in channels:
        freq = pixel_result.lsb_transition_frequencies.get(ch, 0.0)
        diff = abs(freq - 0.50)
        # Diff <= 0.02 -> 100 score, Diff >= 0.25 -> 0 score
        if diff <= 0.02:
            sc = 100.0
        elif diff >= 0.25:
            sc = 0.0
        else:
            sc = ((0.25 - diff) / 0.23) * 100.0
        scores.append(sc)

    return clamp(sum(scores) / len(scores)) if scores else 0.0


def calculate_risk_score(analysis_result: AnalysisResult) -> RiskAssessment:
    """Calculate a 0–100 steganography risk score and build a complete RiskAssessment object.

    Excluded channels: Alpha channel ("A") is strictly excluded from all indicator scoring.

    Args:
        analysis_result: Master AnalysisResult object from Feature 6.

    Returns:
        RiskAssessment containing score, level, indicator breakdown, weights, observations, and summary.
    """
    analyzed_channels = [
        ch for ch in analysis_result.image_info.analyzed_channels if ch.upper() != "A"
    ]

    # 1. Compute individual 0-100 indicator scores
    ent_s = score_entropy(analysis_result.entropy, analyzed_channels)
    lsb_s = score_lsb(analysis_result.lsb_analysis, analyzed_channels)
    chi_s = score_chi_square(analysis_result.chi_square, analyzed_channels)
    hist_s = score_histogram(analysis_result.histogram, analyzed_channels)
    pix_s = score_pixel_stats(analysis_result.pixel_statistics, analyzed_channels)

    indicator_scores: Dict[str, float] = {
        "entropy": round(ent_s, 1),
        "lsb": round(lsb_s, 1),
        "chi_square": round(chi_s, 1),
        "histogram": round(hist_s, 1),
        "pixel_statistics": round(pix_s, 1),
    }

    weights: Dict[str, float] = {
        "entropy": RISK_WEIGHT_ENTROPY,
        "lsb": RISK_WEIGHT_LSB,
        "chi_square": RISK_WEIGHT_CHI_SQUARE,
        "histogram": RISK_WEIGHT_HISTOGRAM,
        "pixel_statistics": RISK_WEIGHT_PIXEL_STATS,
    }

    # 2. Compute weighted total score
    weighted_total = (
        ent_s * RISK_WEIGHT_ENTROPY
        + lsb_s * RISK_WEIGHT_LSB
        + chi_s * RISK_WEIGHT_CHI_SQUARE
        + hist_s * RISK_WEIGHT_HISTOGRAM
        + pix_s * RISK_WEIGHT_PIXEL_STATS
    )

    final_score = int(round(clamp(weighted_total, 0.0, 100.0)))
    level = get_risk_level(final_score)

    # 3. Generate observations and assessment summary
    observations = generate_observations(indicator_scores)
    assessment_text = generate_assessment_summary(final_score, level, observations)

    return RiskAssessment(
        score=final_score,
        level=level,
        indicator_scores=indicator_scores,
        weights=weights,
        observations=observations,
        assessment=assessment_text,
    )
