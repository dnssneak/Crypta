"""
Chi-Square Statistical Analysis Module for Crypta Steganalysis Engine.
Implements Pairs of Values (PoVs) Chi-Square analysis for LSB replacement detection.
"""

import math
import numpy as np
from typing import List, Tuple, Optional, Dict
from crypta.steganalysis.results import ChiSquareResult


def calculate_chi2_p_value(chi2_stat: float, df: int) -> float:
    """Calculate upper-tail probability (p-value) for Chi-Square distribution using pure math/NumPy.

    Uses Wilson-Hilferty transformation converting Chi-Square statistic to standard normal distribution.

    Args:
        chi2_stat: Chi-Square test statistic (X^2 >= 0).
        df: Degrees of freedom (df > 0).

    Returns:
        float: Calculated p-value in range [0.0, 1.0].
    """
    if chi2_stat <= 0.0 or df <= 0:
        return 1.0

    try:
        # Wilson-Hilferty transformation to standard normal
        # Z = ((X/df)^(1/3) - (1 - 2/(9*df))) / sqrt(2/(9*df))
        term1 = (chi2_stat / float(df)) ** (1.0 / 3.0)
        term2 = 1.0 - (2.0 / (9.0 * float(df)))
        denom = math.sqrt(2.0 / (9.0 * float(df)))
        z_score = (term1 - term2) / denom

        # Upper-tail normal survival probability Q(z) = 0.5 * erfc(z / sqrt(2))
        p_val = 0.5 * math.erfc(z_score / math.sqrt(2.0))
        return float(np.clip(p_val, 0.0, 1.0))
    except (ValueError, OverflowError, ZeroDivisionError):
        return 1.0


def calculate_chi_square_pov(channel_data: np.ndarray) -> Tuple[float, int, Optional[float]]:
    """Calculate PoV (Pairs of Values 2k vs 2k+1) Chi-Square test statistic for a channel.

    Args:
        channel_data: 1D NumPy array of uint8 pixel values.

    Returns:
        Tuple[float, int, Optional[float]]: (chi2_stat, degrees_of_freedom, p_value)
    """
    if channel_data.size == 0:
        return 0.0, 0, 1.0

    counts = np.bincount(channel_data, minlength=256)

    # Reshape counts into (128, 2) where each row is (y_2k, y_2k+1)
    pairs = counts.reshape(128, 2)
    y_2k = pairs[:, 0].astype(np.float64)
    y_2k1 = pairs[:, 1].astype(np.float64)

    sum_pairs = y_2k + y_2k1
    # Active pairs are those with at least one observation
    mask = sum_pairs > 0
    active_pairs = int(np.count_nonzero(mask))

    if active_pairs <= 1:
        return 0.0, 0, 1.0

    diff = y_2k[mask] - y_2k1[mask]
    chi2_stat = float(np.sum((diff ** 2) / (2.0 * sum_pairs[mask])))
    df = active_pairs - 1

    if df <= 0:
        return round(chi2_stat, 4), 0, 1.0

    p_val = calculate_chi2_p_value(chi2_stat, df)
    return round(chi2_stat, 4), df, round(p_val, 6)


def analyze_chi_square(image_array: np.ndarray, channel_names: List[str]) -> ChiSquareResult:
    """Perform Chi-Square PoV analysis on image channels.

    Args:
        image_array: NumPy array of shape (H, W, C) containing uint8 pixel values.
        channel_names: List of channel names to analyze (e.g. ['R', 'G', 'B']).

    Returns:
        ChiSquareResult: Structured Chi-Square analysis result object.
    """
    statistics: Dict[str, float] = {}
    dof: Dict[str, int] = {}
    p_values: Dict[str, Optional[float]] = {}

    anomalous_channels = []

    for idx, ch_name in enumerate(channel_names):
        channel_data = image_array[:, :, idx].ravel()
        stat, df, p_val = calculate_chi_square_pov(channel_data)

        statistics[ch_name] = stat
        dof[ch_name] = df
        p_values[ch_name] = p_val

        # p < 0.01 suggests low probability of natural PoV variation under random model assumption
        if p_val is not None and p_val < 0.01 and stat > 0:
            anomalous_channels.append(ch_name)

    if anomalous_channels:
        ch_str = ", ".join(anomalous_channels)
        obs = f"Statistical PoV deviation detected in channel(s): {ch_str}. This may warrant further investigation."
    else:
        obs = "No significant PoV statistical anomaly detected across analyzed channels."

    return ChiSquareResult(
        statistics=statistics,
        degrees_of_freedom=dof,
        p_values=p_values,
        observation=obs,
    )
