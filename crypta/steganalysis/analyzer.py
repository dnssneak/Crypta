"""
High-Level Steganalysis Orchestrator for Crypta.
Coordinates carrier validation, channel extraction, analytical engine execution, and visualization.
"""

from pathlib import Path
from typing import Union, Optional, List
from PIL import Image
import numpy as np

from crypta.steganography.validators import validate_carrier_image
from crypta.steganalysis.results import ImageInfo, AnalysisResult
from crypta.steganalysis.entropy import analyze_entropy
from crypta.steganalysis.lsb_analysis import analyze_lsb
from crypta.steganalysis.chi_square import analyze_chi_square
from crypta.steganalysis.histogram import analyze_histogram
from crypta.steganalysis.pixel_analysis import analyze_pixels
from crypta.steganalysis.visualizer import generate_analysis_charts
from crypta.steganalysis.risk_score import calculate_risk_score


def analyze_image(
    image_path: Union[str, Path],
    visualize: bool = False,
    visualization_output: Optional[Union[str, Path]] = None,
) -> AnalysisResult:
    """Analyze a PNG carrier image using Crypta steganalysis statistical engines.

    Args:
        image_path: Path to PNG image file.
        visualize: If True, generate and save steganalysis visualization chart.
        visualization_output: Destination path for chart PNG (optional).

    Returns:
        AnalysisResult: Comprehensive structured analysis result.

    Raises:
        FileNotFoundError: If image file does not exist.
        ValueError: If file format is not PNG or image data is invalid/corrupt.
    """
    # 1. Image Validation using Feature 2 Validator
    carrier = validate_carrier_image(image_path)

    # 2. Open Pillow Image and extract NumPy pixel array
    with Image.open(carrier.path) as img:
        img_mode = img.mode
        img_array = np.array(img, dtype=np.uint8)

    # 3. Channel selection: R, G, B analyzed; Alpha excluded if present
    if img_mode == "RGBA":
        analyzed_channels = ["R", "G", "B"]
        alpha_excluded = True
    elif img_mode == "RGB":
        analyzed_channels = ["R", "G", "B"]
        alpha_excluded = False
    else:
        # Fallback if validator passed custom mode
        analyzed_channels = [f"Ch{i}" for i in range(carrier.channels)]
        alpha_excluded = False

    image_info = ImageInfo(
        file_path=carrier.path,
        file_name=carrier.path.name,
        format=carrier.format,
        width=carrier.width,
        height=carrier.height,
        mode=carrier.mode,
        channels=carrier.channels,
        file_size_bytes=carrier.file_size_bytes,
        analyzed_channels=analyzed_channels,
        alpha_excluded=alpha_excluded,
    )

    # 4. Run Analytical Sub-Engines
    entropy_res = analyze_entropy(img_array, analyzed_channels)
    lsb_res = analyze_lsb(img_array, analyzed_channels)
    chi_res = analyze_chi_square(img_array, analyzed_channels)
    hist_res = analyze_histogram(img_array, analyzed_channels)
    pixel_res = analyze_pixels(img_array, analyzed_channels)

    # 5. Aggregate Observations
    observations: List[str] = [
        entropy_res.observation,
        lsb_res.observation,
        chi_res.observation,
        hist_res.observation,
        pixel_res.observation,
    ]

    analysis_result = AnalysisResult(
        image_info=image_info,
        entropy=entropy_res,
        lsb_analysis=lsb_res,
        chi_square=chi_res,
        histogram=hist_res,
        pixel_statistics=pixel_res,
        observations=observations,
    )

    # 6. Calculate Risk Score & Assessment (Feature 8)
    risk_assessment = calculate_risk_score(analysis_result)
    analysis_result.risk_assessment = risk_assessment

    # 7. Generate Visualization if requested
    if visualize:
        chart_path = generate_analysis_charts(analysis_result, img_array, visualization_output)
        analysis_result.observations.append(f"Analysis chart generated and saved to: {chart_path.name}")

    return analysis_result

