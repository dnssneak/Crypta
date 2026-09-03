"""
Evidence and Explanation Assessment Generator for Crypta Steganalysis.
Generates human-readable observations and summary assessments based on normalized indicator scores.
"""

from typing import Dict, List


def get_severity_label(score: float) -> str:
    """Classify a 0-100 indicator score into a severity tier string."""
    if math_isnan(score):
        return "Normal"
    if score >= 80:
        return "Strong"
    elif score >= 60:
        return "Elevated"
    elif score >= 40:
        return "Moderate"
    elif score >= 20:
        return "Slight"
    else:
        return "Minimal"


def math_isnan(val: float) -> bool:
    """Helper to check for NaN floats safely."""
    return val != val


def generate_observations(indicator_scores: Dict[str, float]) -> List[str]:
    """Generate explainable observation statements based on individual indicator scores.

    Severity Tiers:
    - 0-19: Minimal / Normal
    - 20-39: Slight
    - 40-59: Moderate
    - 60-79: Elevated
    - 80-100: Strong
    """
    observations: List[str] = []

    # 1. LSB Distribution Observation
    lsb_s = indicator_scores.get("lsb", 0.0)
    if lsb_s >= 80:
        observations.append("[!] Strong LSB 50/50 equalization observed across all channels (high-entropy payload signature).")
    elif lsb_s >= 60:
        observations.append("[!] Elevated LSB equalization detected; 0/1 bit balance closely aligns with randomized data.")
    elif lsb_s >= 40:
        observations.append("Moderate LSB 50/50 balance observed across analyzed channels.")
    elif lsb_s >= 20:
        observations.append("Slight LSB balance observed; minor deviation from natural expectation.")
    else:
        observations.append("LSB 0/1 distribution appears normal with expected natural channel bias.")

    # 2. Chi-Square Observation
    chi_s = indicator_scores.get("chi_square", 0.0)
    if chi_s >= 80:
        observations.append("[!] Strong chi-square statistical anomaly (low p-value), highly characteristic of LSB steganography.")
    elif chi_s >= 60:
        observations.append("[!] Elevated chi-square test statistic indicating probable LSB replacement.")
    elif chi_s >= 40:
        observations.append("Moderate chi-square statistical deviation observed.")
    elif chi_s >= 20:
        observations.append("Slight chi-square anomaly detected in one or more color channels.")
    else:
        observations.append("Chi-square p-values show no statistically significant Pairs-of-Values (PoV) flattening.")

    # 3. Histogram Observation
    hist_s = indicator_scores.get("histogram", 0.0)
    if hist_s >= 80:
        observations.append("[!] Strong histogram pair-flattening signature (Pairs-of-Values equalization).")
    elif hist_s >= 60:
        observations.append("[!] Elevated histogram pair-flattening detected across color channels.")
    elif hist_s >= 40:
        observations.append("Moderate histogram irregularity in adjacent intensity pairs.")
    elif hist_s >= 20:
        observations.append("Slight histogram pair-flattening observed.")
    else:
        observations.append("Histogram adjacent pixel pair ratios show normal natural variation.")

    # 4. Entropy Observation
    ent_s = indicator_scores.get("entropy", 0.0)
    if ent_s >= 80:
        observations.append("Near-maximum Shannon entropy (~8.0 bits/byte) observed in all color channels.")
    elif ent_s >= 60:
        observations.append("Elevated Shannon entropy observed across analyzed color channels.")
    elif ent_s >= 40:
        observations.append("Moderate entropy levels across color channels.")
    elif ent_s >= 20:
        observations.append("Slightly elevated entropy levels observed.")
    else:
        observations.append("Shannon entropy is within expected range for natural image content.")

    # 5. Pixel Statistics Observation
    pix_s = indicator_scores.get("pixel_statistics", 0.0)
    if pix_s >= 80:
        observations.append("Strong LSB transition frequency alignment near 0.50 (randomized bitstream signature).")
    elif pix_s >= 60:
        observations.append("Elevated LSB bit-flip transition frequency.")
    elif pix_s >= 40:
        observations.append("Moderate LSB transition frequency alignment near 0.50.")
    elif pix_s >= 20:
        observations.append("Slight LSB transition frequency deviation.")
    else:
        observations.append("Pixel transition frequencies and spatial statistics show normal distribution.")

    return observations


def generate_assessment_summary(score: int, level: str, observations: List[str]) -> str:
    """Generate a cohesive summary assessment paragraph based on score and risk level."""
    disclaimer = "[!] This assessment is a heuristic statistical evaluation and does not confirm the presence of hidden information."

    if level == "VERY HIGH":
        summary = (
            "Strong statistical anomalies observed across multiple independent tests "
            "(LSB distribution, Chi-Square, and Histogram). High probability of LSB steganographic payload."
        )
    elif level == "HIGH":
        summary = (
            "Multiple statistical indicators show elevated characteristics "
            "potentially associated with steganographic modification."
        )
    elif level == "MODERATE":
        summary = (
            "Statistical analysis shows slight to moderate anomalies across some color channels. "
            "While these characteristics can occur naturally in complex or noisy images, they may warrant further inspection."
        )
    else:
        summary = (
            "Statistical analysis shows minimal indicators of steganographic modification. "
            "Observed metrics are consistent with uncompressed natural image data."
        )

    return f"{summary}\n\n{disclaimer}"
