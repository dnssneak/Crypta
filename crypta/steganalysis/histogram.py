"""
Histogram & Intensity Distribution Analysis Module for Crypta Steganalysis Engine.
Computes channel statistics, 256-bin frequency distributions, and adjacent value pair ratios.
"""

import numpy as np
from typing import List, Dict, Any
from crypta.steganalysis.results import HistogramResult


def analyze_histogram(image_array: np.ndarray, channel_names: List[str]) -> HistogramResult:
    """Analyze histogram statistics and adjacent value relationships across channels.

    Args:
        image_array: NumPy array of shape (H, W, C) containing uint8 pixel values.
        channel_names: List of channel names to analyze (e.g. ['R', 'G', 'B']).

    Returns:
        HistogramResult: Structured histogram analysis result object.
    """
    channel_stats: Dict[str, Dict[str, float]] = {}
    adjacent_pair_ratios: Dict[str, float] = {}

    for idx, ch_name in enumerate(channel_names):
        channel_data = image_array[:, :, idx].ravel()

        if channel_data.size == 0:
            c_min, c_max, c_mean, c_median, c_std = 0, 0, 0.0, 0.0, 0.0
            pair_ratio = 0.0
        else:
            c_min = int(np.min(channel_data))
            c_max = int(np.max(channel_data))
            c_mean = float(np.mean(channel_data))
            c_median = float(np.median(channel_data))
            c_std = float(np.std(channel_data))

            # 256-bin histogram
            counts = np.bincount(channel_data, minlength=256)
            pairs = counts.reshape(128, 2).astype(np.float64)
            y_2k = pairs[:, 0]
            y_2k1 = pairs[:, 1]
            sum_pairs = y_2k + y_2k1
            mask = sum_pairs > 0

            if np.any(mask):
                # Calculate average relative difference between adjacent pairs |y_2k - y_2k+1| / (y_2k + y_2k+1)
                rel_diffs = np.abs(y_2k[mask] - y_2k1[mask]) / sum_pairs[mask]
                pair_ratio = round(float(np.mean(rel_diffs)), 4)
            else:
                pair_ratio = 0.0

        channel_stats[ch_name] = {
            "min": float(c_min),
            "max": float(c_max),
            "mean": round(c_mean, 2),
            "median": round(c_median, 2),
            "std_dev": round(c_std, 2),
        }
        adjacent_pair_ratios[ch_name] = pair_ratio

    # Observation
    avg_pair_ratio = float(np.mean(list(adjacent_pair_ratios.values()))) if adjacent_pair_ratios else 0.0

    if avg_pair_ratio <= 0.05:
        obs = "Adjacent-value histogram pairs (2k, 2k+1) exhibit high flattening/equalization across channels."
    elif avg_pair_ratio <= 0.20:
        obs = "Adjacent-value histogram pairs display moderate similarity."
    else:
        obs = "Histogram shows typical natural variability between adjacent intensity values."

    return HistogramResult(
        channel_stats=channel_stats,
        adjacent_pair_ratios=adjacent_pair_ratios,
        observation=obs,
    )
