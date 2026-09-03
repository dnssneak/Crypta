"""
LSB Distribution Analysis Module for Crypta Steganalysis Engine.
Analyzes 0-bit vs 1-bit balance in the Least Significant Bits of image color channels.
"""

import numpy as np
from typing import List
from crypta.steganalysis.results import LSBResult


def analyze_lsb(image_array: np.ndarray, channel_names: List[str]) -> LSBResult:
    """Analyze LSB bit distributions across specified channels.

    Args:
        image_array: NumPy array of shape (H, W, C) containing uint8 pixel values.
        channel_names: List of channel names to analyze (e.g. ['R', 'G', 'B']).

    Returns:
        LSBResult: Structured LSB distribution analysis result object.
    """
    zero_counts = {}
    one_counts = {}
    zero_percentages = {}
    one_percentages = {}
    deviations = {}

    max_deviation = 0.0

    for idx, ch_name in enumerate(channel_names):
        channel_data = image_array[:, :, idx].ravel()
        lsb_bits = channel_data & 1
        c1 = int(np.count_nonzero(lsb_bits))
        c0 = int(len(lsb_bits) - c1)
        total = len(lsb_bits)

        if total > 0:
            p0 = round((c0 / total) * 100.0, 2)
            p1 = round((c1 / total) * 100.0, 2)
            dev = round(abs(p1 - 50.0), 2)
        else:
            p0, p1, dev = 0.0, 0.0, 0.0

        zero_counts[ch_name] = c0
        one_counts[ch_name] = c1
        zero_percentages[ch_name] = p0
        one_percentages[ch_name] = p1
        deviations[ch_name] = dev

        if dev > max_deviation:
            max_deviation = dev

    if max_deviation <= 1.0:
        obs = "LSB distribution across analyzed channels is highly balanced (~50/50)."
    elif max_deviation <= 5.0:
        obs = "LSB distribution displays slight variance from ideal 50/50 balance."
    else:
        obs = f"LSB distribution exhibits noticeable bit bias (max deviation {max_deviation:.1f}%)."

    return LSBResult(
        zero_counts=zero_counts,
        one_counts=one_counts,
        zero_percentages=zero_percentages,
        one_percentages=one_percentages,
        deviations=deviations,
        observation=obs,
    )
