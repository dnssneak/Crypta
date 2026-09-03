"""
Optional Steganalysis Visualization Generator for Crypta.
Plots RGB histograms, LSB distributions, and Chi-Square statistics using Matplotlib in headless mode.
"""

from pathlib import Path
from typing import Union, Optional
import numpy as np

from crypta.steganalysis.results import AnalysisResult

# Configure Matplotlib backend for headless environments
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def generate_analysis_charts(
    analysis_result: AnalysisResult,
    image_array: np.ndarray,
    output_path: Optional[Union[str, Path]] = None,
) -> Path:
    """Generate visual steganalysis charts and save to a PNG file.

    Args:
        analysis_result: Populated AnalysisResult instance.
        image_array: NumPy array of shape (H, W, C) uint8 pixel data.
        output_path: Path to output PNG. If None, saves adjacent to original image.

    Returns:
        Path: Path to saved output image file.
    """
    info = analysis_result.image_info
    if output_path is None:
        save_path = info.file_path.parent / f"{info.file_path.stem}_steganalysis.png"
    else:
        save_path = Path(output_path)

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))
    fig.suptitle(f"Crypta Steganalysis Report — {info.file_name}", fontsize=14, fontweight="bold")

    channels = info.analyzed_channels
    colors = {"R": "red", "G": "green", "B": "blue"}

    # 1. RGB Histograms
    ax_hist = axes[0, 0]
    ax_hist.set_title("Color Channel Histograms", fontsize=11)
    ax_hist.set_xlabel("Pixel Value (0-255)")
    ax_hist.set_ylabel("Pixel Frequency")

    for idx, ch in enumerate(channels):
        c_color = colors.get(ch, "black")
        ch_data = image_array[:, :, idx].ravel()
        counts = np.bincount(ch_data, minlength=256)
        ax_hist.plot(counts, color=c_color, alpha=0.7, label=f"Channel {ch}")

    ax_hist.legend(loc="upper right")
    ax_hist.grid(True, linestyle="--", alpha=0.5)

    # 2. LSB Distribution Bar Chart
    ax_lsb = axes[0, 1]
    ax_lsb.set_title("LSB Distribution (0-bit vs 1-bit)", fontsize=11)
    x = np.arange(len(channels))
    width = 0.35

    z_pcts = [analysis_result.lsb_analysis.zero_percentages.get(ch, 0.0) for ch in channels]
    o_pcts = [analysis_result.lsb_analysis.one_percentages.get(ch, 0.0) for ch in channels]

    ax_lsb.bar(x - width / 2, z_pcts, width, label="0-bit %", color="skyblue")
    ax_lsb.bar(x + width / 2, o_pcts, width, label="1-bit %", color="salmon")
    ax_lsb.axhline(50.0, color="gray", linestyle="--", alpha=0.7, label="Ideal 50%")
    ax_lsb.set_xticks(x)
    ax_lsb.set_xticklabels(channels)
    ax_lsb.set_ylabel("Percentage (%)")
    ax_lsb.set_ylim(0, 100)
    ax_lsb.legend(loc="upper right")
    ax_lsb.grid(True, linestyle="--", alpha=0.5)

    # 3. Chi-Square PoV Statistics
    ax_chi = axes[1, 0]
    ax_chi.set_title("Chi-Square PoV Statistics", fontsize=11)
    chi_stats = [analysis_result.chi_square.statistics.get(ch, 0.0) for ch in channels]
    bar_colors = [colors.get(ch, "gray") for ch in channels]

    ax_chi.bar(channels, chi_stats, color=bar_colors, alpha=0.7, width=0.5)
    ax_chi.set_xlabel("Channel")
    ax_chi.set_ylabel("Chi-Square Statistic")
    ax_chi.grid(True, linestyle="--", alpha=0.5)

    # 4. Summary & Observations Text Box
    ax_obs = axes[1, 1]
    ax_obs.axis("off")
    ax_obs.set_title("Analytical Observations", fontsize=11, fontweight="bold")

    obs_text = [
        f"Dimensions: {info.dimensions_str} | Mode: {info.mode}",
        f"Overall Entropy: {analysis_result.entropy.overall_entropy:.2f} / 8.00",
        "",
        f"• Entropy: {analysis_result.entropy.observation}",
        f"• LSB: {analysis_result.lsb_analysis.observation}",
        f"• Chi-Sq: {analysis_result.chi_square.observation}",
        f"• Histogram: {analysis_result.histogram.observation}",
        f"• Spatial: {analysis_result.pixel_statistics.observation}",
    ]

    wrapped_text = "\n".join(obs_text)
    ax_obs.text(
        0.05,
        0.95,
        wrapped_text,
        transform=ax_obs.transAxes,
        fontsize=9,
        verticalalignment="top",
        bbox=dict(boxstyle="round,pad=0.5", facecolor="lightyellow", alpha=0.8),
    )

    plt.tight_layout()
    plt.savefig(save_path, dpi=150)
    plt.close(fig)

    return save_path
