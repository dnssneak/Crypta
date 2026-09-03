"""
Pixel-Level & Spatial Statistics Analysis Module for Crypta Steganalysis Engine.
Computes pixel metrics, channel intensity bounds, unique byte counts, and spatial LSB transition frequencies.
"""

import numpy as np
from typing import List, Dict
from crypta.steganalysis.results import PixelStatsResult


def calculate_lsb_transition_frequency(channel_data: np.ndarray) -> float:
    """Calculate the frequency of LSB transitions between adjacent pixels along raster order.

    LSB[i] != LSB[i+1] transition rate.
    For random bit sequences, transition rate approaches 0.50.

    Args:
        channel_data: 1D NumPy array of pixel bytes.

    Returns:
        float: LSB transition frequency in range [0.0, 1.0].
    """
    if channel_data.size <= 1:
        return 0.0

    lsb_bits = channel_data & 1
    diffs = lsb_bits[:-1] != lsb_bits[1:]
    transitions = float(np.count_nonzero(diffs))
    rate = transitions / float(len(diffs))
    return round(rate, 4)


def analyze_pixels(image_array: np.ndarray, channel_names: List[str]) -> PixelStatsResult:
    """Analyze pixel-level statistics and spatial LSB transition frequencies.

    Args:
        image_array: NumPy array of shape (H, W, C) containing uint8 pixel values.
        channel_names: List of channel names to analyze (e.g. ['R', 'G', 'B']).

    Returns:
        PixelStatsResult: Structured pixel statistics result object.
    """
    height, width = image_array.shape[:2]
    total_pixels = height * width

    channel_means: Dict[str, float] = {}
    channel_stds: Dict[str, float] = {}
    channel_mins: Dict[str, int] = {}
    channel_maxs: Dict[str, int] = {}
    unique_values: Dict[str, int] = {}
    lsb_transition_frequencies: Dict[str, float] = {}

    for idx, ch_name in enumerate(channel_names):
        channel_data = image_array[:, :, idx].ravel()

        if channel_data.size == 0:
            c_min, c_max, c_mean, c_std = 0, 0, 0.0, 0.0
            u_vals = 0
            trans_freq = 0.0
        else:
            c_min = int(np.min(channel_data))
            c_max = int(np.max(channel_data))
            c_mean = float(np.mean(channel_data))
            c_std = float(np.std(channel_data))
            u_vals = int(len(np.unique(channel_data)))
            trans_freq = calculate_lsb_transition_frequency(channel_data)

        channel_mins[ch_name] = c_min
        channel_maxs[ch_name] = c_max
        channel_means[ch_name] = round(c_mean, 2)
        channel_stds[ch_name] = round(c_std, 2)
        unique_values[ch_name] = u_vals
        lsb_transition_frequencies[ch_name] = trans_freq

    avg_trans_freq = float(np.mean(list(lsb_transition_frequencies.values()))) if lsb_transition_frequencies else 0.0

    if abs(avg_trans_freq - 0.50) <= 0.02:
        obs = f"Average LSB transition frequency ({avg_trans_freq:.2%}) is near 50%, characteristic of high-entropy bitstreams."
    elif avg_trans_freq < 0.40:
        obs = f"Average LSB transition frequency ({avg_trans_freq:.2%}) is low, consistent with smooth natural image gradients."
    else:
        obs = f"Average LSB transition frequency across channels is {avg_trans_freq:.2%}."

    return PixelStatsResult(
        total_pixels=total_pixels,
        channel_means=channel_means,
        channel_stds=channel_stds,
        channel_mins=channel_mins,
        channel_maxs=channel_maxs,
        unique_values=unique_values,
        lsb_transition_frequencies=lsb_transition_frequencies,
        observation=obs,
    )
