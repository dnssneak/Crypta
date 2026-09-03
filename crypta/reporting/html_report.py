"""
HTML Report Generator for Crypta Reporting Engine.
Generates standalone, professional HTML cybersecurity assessment reports with XSS protection.
"""

import html
from pathlib import Path
from typing import Union, Dict, Any
from crypta.reporting.results import CryptaReport


def get_template_path() -> Path:
    """Locate the HTML report template file."""
    return Path(__file__).parent / "templates" / "report.html"


def generate_html_report(
    report_data: CryptaReport,
    output_path: Union[str, Path],
) -> Path:
    """Generate a standalone HTML report from a CryptaReport object with full XSS escaping.

    Args:
        report_data: Master CryptaReport data object.
        output_path: Target destination file path.

    Returns:
        Path: Resolved output file path.
    """
    out_path = Path(output_path).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    template_path = get_template_path()
    with open(template_path, "r", encoding="utf-8") as tf:
        template = tf.read()

    data = report_data.to_dict()
    meta = data.get("report_metadata", {})
    target = data.get("target", {})
    forensics = data.get("forensics", {})
    steg = data.get("steganalysis", {})
    risk = data.get("risk_assessment", {})

    # Extract & Escape Basic Metadata
    tool_name = html.escape(str(meta.get("tool", "Crypta")))
    tool_version = html.escape(str(meta.get("version", "1.0.0")))
    report_version = html.escape(str(meta.get("report_version", "1.0")))
    generated_at = html.escape(str(meta.get("generated_at", "")))

    # Target Info
    filename = html.escape(str(target.get("filename", "")))
    file_format = html.escape(str(target.get("format", "")))
    file_size_human = html.escape(str(target.get("size_human", "")))
    file_size_bytes = html.escape(str(target.get("size_bytes", "")))
    sha256 = html.escape(str(target.get("sha256", "")))

    fmt_info = forensics.get("format", {})
    ext_match = "YES" if fmt_info.get("extension_match", True) else "NO (MISMATCH DETECTED)"
    ext_match_esc = html.escape(ext_match)

    # Risk Assessment
    risk_score = risk.get("score", 0)
    risk_level = str(risk.get("level", "LOW")).upper()
    risk_level_esc = html.escape(risk_level)

    level_class = "level-low"
    if risk_level == "MODERATE":
        level_class = "level-moderate"
    elif risk_level == "HIGH":
        level_class = "level-high"
    elif risk_level == "VERY HIGH":
        level_class = "level-very-high"

    ind_scores = risk.get("indicator_scores", {})
    score_lsb = f"{ind_scores.get('lsb', 0.0):.1f}"
    score_chi = f"{ind_scores.get('chi_square', 0.0):.1f}"
    score_hist = f"{ind_scores.get('histogram', 0.0):.1f}"
    score_entropy = f"{ind_scores.get('entropy', 0.0):.1f}"
    score_pixel = f"{ind_scores.get('pixel_statistics', 0.0):.1f}"

    assessment_raw = risk.get("assessment", "")
    assessment_esc = html.escape(assessment_raw).replace("\n", "<br>")

    # Observations HTML
    obs_list = risk.get("observations", [])
    obs_items = []
    for obs in obs_list:
        is_warn = obs.startswith("[!]")
        clean_obs = obs[3:].strip() if is_warn else obs
        esc_obs = html.escape(clean_obs)
        if is_warn:
            obs_items.append(f'<li class="warning"><strong>{esc_obs}</strong></li>')
        else:
            obs_items.append(f"<li>{esc_obs}</li>")
    observations_html = "\n".join(obs_items) if obs_items else "<li>No specific observations recorded.</li>"

    # Forensic Details
    img_info = forensics.get("image", {})
    dimensions = html.escape(str(img_info.get("dimensions_str", "N/A")))
    color_mode = html.escape(str(img_info.get("mode", "N/A")))
    channels = html.escape(str(img_info.get("channels", "N/A")))

    png_struct = forensics.get("png_structure") or {}
    png_sig = "Valid" if png_struct.get("signature_valid", True) else "Invalid"
    png_sig_esc = html.escape(png_sig)
    png_color_type = html.escape(str(png_struct.get("color_type_desc", "N/A")))

    meta_details = forensics.get("metadata", {})
    exif_status = "Present" if meta_details.get("exif_present", False) else "Not present"
    exif_status_esc = html.escape(exif_status)
    text_meta_count = html.escape(str(meta_details.get("text_entry_count", 0)))

    # Steganalysis Table Rows
    steg_info = steg.get("image_info", {})
    analyzed_channels = steg_info.get("analyzed_channels", ["R", "G", "B"])
    entropy_dict = steg.get("entropy", {}).get("per_channel_entropy", {})
    lsb_zeros = steg.get("lsb_analysis", {}).get("zero_percentages", {})
    lsb_ones = steg.get("lsb_analysis", {}).get("one_percentages", {})
    lsb_devs = steg.get("lsb_analysis", {}).get("deviations", {})
    chi_pvals = steg.get("chi_square", {}).get("p_values", {})
    pixel_trans = steg.get("pixel_statistics", {}).get("lsb_transition_frequencies", {})

    steg_rows = []
    for ch in analyzed_channels:
        e_val = f"{entropy_dict.get(ch, 0.0):.2f}"
        p0 = f"{lsb_zeros.get(ch, 0.0):.1f}%"
        p1 = f"{lsb_ones.get(ch, 0.0):.1f}%"
        dev = f"{lsb_devs.get(ch, 0.0):.1f}%"
        pv = chi_pvals.get(ch)
        pv_str = f"{pv:.6f}" if pv is not None else "N/A"
        trans = f"{pixel_trans.get(ch, 0.0) * 100:.1f}%"

        steg_rows.append(
            f"<tr>"
            f"<td><strong>{html.escape(ch)}</strong></td>"
            f"<td>{html.escape(e_val)}</td>"
            f"<td>{html.escape(p0)}</td>"
            f"<td>{html.escape(p1)}</td>"
            f"<td>{html.escape(dev)}</td>"
            f"<td>{html.escape(pv_str)}</td>"
            f"<td>{html.escape(trans)}</td>"
            f"</tr>"
        )
    steganysis_rows_html = "\n".join(steg_rows)

    # Perform Template Substitutions
    rendered = template.replace("{{TOOL_NAME}}", tool_name)
    rendered = rendered.replace("{{TOOL_VERSION}}", tool_version)
    rendered = rendered.replace("{{REPORT_VERSION}}", report_version)
    rendered = rendered.replace("{{GENERATED_AT}}", generated_at)
    rendered = rendered.replace("{{FILENAME}}", filename)
    rendered = rendered.replace("{{FORMAT}}", file_format)
    rendered = rendered.replace("{{FILE_SIZE_HUMAN}}", file_size_human)
    rendered = rendered.replace("{{FILE_SIZE_BYTES}}", file_size_bytes)
    rendered = rendered.replace("{{SHA256}}", sha256)
    rendered = rendered.replace("{{EXTENSION_MATCH}}", ext_match_esc)
    rendered = rendered.replace("{{RISK_SCORE}}", str(risk_score))
    rendered = rendered.replace("{{RISK_LEVEL}}", risk_level_esc)
    rendered = rendered.replace("{{LEVEL_CLASS}}", level_class)
    rendered = rendered.replace("{{SCORE_LSB}}", score_lsb)
    rendered = rendered.replace("{{SCORE_CHI}}", score_chi)
    rendered = rendered.replace("{{SCORE_HIST}}", score_hist)
    rendered = rendered.replace("{{SCORE_ENTROPY}}", score_entropy)
    rendered = rendered.replace("{{SCORE_PIXEL}}", score_pixel)
    rendered = rendered.replace("--w-lsb: 0%;", f"--w-lsb: {score_lsb}%;")
    rendered = rendered.replace("--w-chi: 0%;", f"--w-chi: {score_chi}%;")
    rendered = rendered.replace("--w-hist: 0%;", f"--w-hist: {score_hist}%;")
    rendered = rendered.replace("--w-ent: 0%;", f"--w-ent: {score_entropy}%;")
    rendered = rendered.replace("--w-pix: 0%;", f"--w-pix: {score_pixel}%;")


    rendered = rendered.replace("{{ASSESSMENT_TEXT}}", assessment_esc)
    rendered = rendered.replace("{{OBSERVATIONS_HTML}}", observations_html)
    rendered = rendered.replace("{{DIMENSIONS}}", dimensions)
    rendered = rendered.replace("{{COLOR_MODE}}", color_mode)
    rendered = rendered.replace("{{CHANNELS}}", channels)
    rendered = rendered.replace("{{PNG_SIG}}", png_sig_esc)
    rendered = rendered.replace("{{PNG_COLOR_TYPE}}", png_color_type)
    rendered = rendered.replace("{{EXIF_STATUS}}", exif_status_esc)
    rendered = rendered.replace("{{TEXT_META_COUNT}}", text_meta_count)
    rendered = rendered.replace("{{STEGANALYSIS_ROWS_HTML}}", steganysis_rows_html)

    with open(out_path, "w", encoding="utf-8") as out_f:
        out_f.write(rendered)

    return out_path
