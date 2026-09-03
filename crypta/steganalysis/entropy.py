"""
Shannon Entropy Analysis Module for Crypta Steganalysis Engine.
Calculates global and per-channel Shannon entropy for image pixel data.
"""

import math
import numpy as np
from typing import List, Tuple
from crypta.steganalysis.results import EntropyResult


# Entropy Classification Thresholds (Heuristic)
ENTROPY_THRESHOLD_HIGH = 7.2
ENTROPY_THRESHOLD_MODERATE = 5.0


def calculate_shannon_entropy(data: np.ndarray) -> float:
    """Calculate Shannon entropy H(X) = -sum p(x) log2(p(x)) for an 8-bit array.

    Args:
        data: 1D or ND NumPy array of byte values (0..255).

    Returns:
        float: Entropy value in range [0.0, 8.0]. Returns 0.0 if array is empty.
    """
    if data.size == 0:
        return 0.0

    counts = np.bincount(data.ravel(), minlength=256)
    probabilities = counts / counts.sum()
    # Filter non-zero probabilities to avoid log2(0)
    nz_probs = probabilities[probabilities > 0]
    if len(nz_probs) == 0:
        return 0.0

    entropy = float(-np.sum(nz_probs * np.log2(nz_probs)))
    if abs(entropy) < 1e-9:
        entropy = 0.0
    return float(np.clip(entropy, 0.0, 8.0))



def analyze_entropy(image_array: np.ndarray, channel_names: List[str]) -> EntropyResult:
    """Perform Shannon entropy analysis on image channels.

    Args:
        image_array: NumPy array of shape (H, W, C) containing uint8 pixel data.
        channel_names: List of channel names to analyze (e.g. ['R', 'G', 'B']).

    Returns:
        EntropyResult: Structured entropy analysis result object.
    """
    per_channel_entropy = {}
    combined_bytes = []

    for idx, ch_name in enumerate(channel_names):
        channel_data = image_array[:, :, idx].ravel()
        ch_entropy = calculate_shannon_entropy(channel_data)
        per_channel_entropy[ch_name] = round(ch_entropy, 4)
        combined_bytes.append(channel_data)

    if combined_bytes:
        all_rgb_data = np.concatenate(combined_bytes)
        overall_entropy = round(calculate_shannon_entropy(all_rgb_data), 4)
    else:
        overall_entropy = 0.0

    # Formulate observation
    if overall_entropy >= ENTROPY_THRESHOLD_HIGH:
        obs = (
            f"High pixel entropy observed ({overall_entropy:.2f} / 8.00). "
            "High entropy is common in complex textures or uncompressed photos, "
            "and alone does not constitute proof of steganography."
        )
    elif overall_entropy >= ENTROPY_THRESHOLD_MODERATE:
        obs = f"Moderate pixel entropy observed ({overall_entropy:.2f} / 8.00)."
    else:
        obs = f"Low pixel entropy observed ({overall_entropy:.2f} / 8.00). Characteristic of simple images or flat graphics."

    return EntropyResult(
        overall_entropy=overall_entropy,
        per_channel_entropy=per_channel_entropy,
        observation=obs,
        channel_details={
            "analyzed_channels": channel_names,
            "high_threshold": ENTROPY_THRESHOLD_HIGH,
        },
    )
