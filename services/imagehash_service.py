import sys
import os
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from PIL import Image

# Ensure local imagehash directory is in python search path if needed
LOCAL_IMAGEHASH_DIR = os.path.abspath("./imagehash")
if LOCAL_IMAGEHASH_DIR not in sys.path:
    sys.path.insert(0, LOCAL_IMAGEHASH_DIR)

import imagehash
import numpy as np

logger = logging.getLogger("keikai.imagehash")


class ImageHashError(Exception):
    pass


# ---------------------------------------------------------------------------
# Image normalisation
# ---------------------------------------------------------------------------

def normalize_image_for_hashing(img: Image.Image, autocrop: bool = True) -> Image.Image:
    """
    Applies three normalisation steps so that both the reference and candidate
    image are in an identical, deterministic state before hashing:

    1.  Alpha/transparency flattening — composites RGBA/LA/PA images onto a
        solid white background so that transparent logos (e.g. PNG with alpha)
        are not silently converted to black by PIL's `.convert("RGB")`.
        Without this, a white-logo-on-transparent-bg compares as a black image,
        inflating every Hamming distance.

    2.  Colour-mode normalisation — converts to RGB so hashes are always
        computed on a consistent 3-channel image.

    3.  Auto-crop to content bounding box — removes solid-colour padding
        (common when logos are exported with large white borders) so that
        padding-dimension differences between reference and candidate do not
        perturb the DCT frequency coefficients used by pHash.
        The algorithm:
          - converts to greyscale
          - identifies the "background" as the colour of the top-left corner
            pixel (±15 luminance tolerance)
          - crops to the tightest rectangle containing non-background pixels
          - adds a 4-pixel safety margin so partial-pixel anti-aliasing is
            not accidentally clipped

    Parameters
    ----------
    img : PIL.Image already opened (will not be mutated)
    autocrop : bool  Set False to skip crop step (useful for debug comparisons)

    Returns
    -------
    PIL.Image in RGB mode, ready to pass directly to imagehash.phash / dhash
    """
    img = img.copy()  # don't mutate caller's object

    # Step 1: flatten alpha onto white background
    if img.mode in ("RGBA", "LA", "PA", "P"):
        if img.mode == "PA":
            img = img.convert("RGBA")
        elif img.mode == "P":
            img = img.convert("RGBA")  # palette images may have transparency
        elif img.mode == "LA":
            img = img.convert("RGBA")

        if img.mode == "RGBA":
            white_bg = Image.new("RGB", img.size, (255, 255, 255))
            alpha = img.split()[3]          # alpha channel
            white_bg.paste(img, mask=alpha)
            img = white_bg
        else:
            img = img.convert("RGB")
    else:
        img = img.convert("RGB")

    # Step 2: auto-crop to content bounding box
    if autocrop:
        grey = img.convert("L")
        arr = np.array(grey, dtype=np.int16)
        # Background estimated from top-left corner pixel
        bg_val = int(arr[0, 0])
        tol = 15
        mask = np.abs(arr - bg_val) > tol

        rows_with_content = np.any(mask, axis=1)
        cols_with_content = np.any(mask, axis=0)

        if rows_with_content.any() and cols_with_content.any():
            row_indices = np.where(rows_with_content)[0]
            col_indices = np.where(cols_with_content)[0]
            rmin, rmax = row_indices[0], row_indices[-1]
            cmin, cmax = col_indices[0], col_indices[-1]
            # Safety margin
            margin = 4
            rmin = max(0, rmin - margin)
            rmax = min(arr.shape[0] - 1, rmax + margin)
            cmin = max(0, cmin - margin)
            cmax = min(arr.shape[1] - 1, cmax + margin)
            img = img.crop((cmin, rmin, cmax + 1, rmax + 1))
            # If crop produced a degenerate 0-area image, fall back
            if img.width < 4 or img.height < 4:
                # Recrop failed — return full image
                img = img.crop((0, 0, arr.shape[1], arr.shape[0]))

    return img


def compute_color_histogram_similarity(img_a: Image.Image, img_b: Image.Image) -> float:
    """
    Computes a soft colour histogram similarity (0–100 %) between two normalized
    images.  Uses 16-bin histograms on each RGB channel and measures 1 minus the
    normalised L1 distance between the concatenated histograms.

    This is NOT a match gate — it is a corroborating signal surfaced alongside
    pHash/dHash so that wildly inconsistent hash-vs-colour results are visible
    to the investigator rather than hidden.

    Returns
    -------
    float  Colour histogram similarity percentage (0–100)
    """
    bins = 16
    hist_a = []
    hist_b = []
    for ch in range(3):  # R, G, B
        ha = img_a.split()[ch].histogram()
        hb = img_b.split()[ch].histogram()
        # downsample to `bins` bins
        step = 256 // bins
        ha_binned = [sum(ha[i:i+step]) for i in range(0, 256, step)]
        hb_binned = [sum(hb[i:i+step]) for i in range(0, 256, step)]
        hist_a.extend(ha_binned)
        hist_b.extend(hb_binned)

    ha_arr = np.array(hist_a, dtype=np.float64)
    hb_arr = np.array(hist_b, dtype=np.float64)
    ha_arr /= ha_arr.sum() + 1e-9
    hb_arr /= hb_arr.sum() + 1e-9

    l1_dist = float(np.abs(ha_arr - hb_arr).sum())  # 0 = identical, 2 = completely different
    sim = max(0.0, (1.0 - l1_dist / 2.0) * 100.0)
    return round(sim, 2)


# ---------------------------------------------------------------------------
# Core hash computation
# ---------------------------------------------------------------------------

def compute_image_hashes(
    image_path: str,
    original_filename: str = "",
    autocrop: bool = True,
    return_normalized_image: bool = False,
) -> Dict[str, Any]:
    """
    Opens image, applies normalize_image_for_hashing(), then computes pHash
    and dHash using the imagehash library.

    Parameters
    ----------
    image_path : str            Path to the image file
    original_filename : str     Original upload filename for error messages
    autocrop : bool             Whether to auto-crop padding before hashing
    return_normalized_image     If True, also returns the PIL Image used for
                                hashing (for debug preview endpoints)

    Returns
    -------
    Dict with keys: phash, dhash, phash_str, dhash_str, hash_size,
                    normalized_image (only if return_normalized_image=True)
    """
    fname = original_filename or os.path.basename(image_path)
    try:
        with Image.open(image_path) as img:
            img.verify()  # Verify image integrity — closes the file handle

        # Re-open: verify() closes/corrupts the handle
        with Image.open(image_path) as img:
            normalized = normalize_image_for_hashing(img, autocrop=autocrop)

        phash_obj = imagehash.phash(normalized)
        dhash_obj = imagehash.dhash(normalized)

        result = {
            "phash": phash_obj,
            "dhash": dhash_obj,
            "phash_str": str(phash_obj),
            "dhash_str": str(dhash_obj),
            "hash_size": phash_obj.hash.size,  # Total bits (typically 64 for 8x8)
        }
        if return_normalized_image:
            result["normalized_image"] = normalized
        return result

    except ImageHashError:
        raise
    except Exception as e:
        raise ImageHashError(
            f"File '{fname}' is corrupted or not a supported image format "
            f"(PNG, JPG, WEBP, etc.). Error: {str(e)}"
        )


# ---------------------------------------------------------------------------
# Comparison functions
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Calibration & Similarity Scoring
# ---------------------------------------------------------------------------

def calibrate_hash_similarity(dist: int, threshold: int) -> float:
    """
    Calibrates Hamming distance relative to user-configured threshold T.
    - Distance 0 -> 100.0%
    - Distance 0 < d <= T -> smooth decay from 100% to 50%
    - Distance T < d < 2*T -> rapid decay from 50% down to 0%
    - Distance >= 2*T -> 0.0%
    """
    t = max(1, threshold)
    if dist <= 0:
        return 100.0
    elif dist <= t:
        return round(max(50.0, 100.0 - 50.0 * ((dist / t) ** 1.2)), 2)
    elif dist < 2 * t:
        decay = (dist - t) / t
        return round(max(0.0, 50.0 * ((1.0 - decay) ** 1.5)), 2)
    else:
        return 0.0


def derive_similarity_metadata(phash_dist: int, dhash_dist: int, combined_sim: float, threshold: int) -> Tuple[str, str]:
    """
    Derives user-understandable classification label and analyst explanation string.
    """
    likely_match = bool(phash_dist <= threshold)
    if combined_sim >= 90.0:
        label = "VERY HIGH SIMILARITY"
    elif combined_sim >= 70.0:
        label = "HIGH SIMILARITY"
    elif combined_sim >= 40.0:
        label = "POSSIBLE SIMILARITY"
    elif combined_sim >= 15.0:
        label = "LOW SIMILARITY"
    else:
        label = "NO MATCH"

    if likely_match or (dhash_dist <= threshold):
        reason = (
            f"Match confirmed: Perceptual hash distance (pHash: {phash_dist}, dHash: {dhash_dist}) "
            f"is within configured Hamming threshold of {threshold}."
        )
    else:
        reason = (
            f"No match: Both hash distances (pHash: {phash_dist}, dHash: {dhash_dist}) "
            f"exceed configured Hamming threshold of {threshold}."
        )

    return label, reason


# ---------------------------------------------------------------------------
# Comparison functions
# ---------------------------------------------------------------------------

def compare_two_images(
    reference_path: str,
    candidate_path: str,
    threshold: int = 10,
    autocrop: bool = True,
) -> Dict[str, Any]:
    """
    Compares reference and candidate images using normalised pHash and dHash.
    Returns Hamming distances, calibrated similarity percentages, colour histogram
    similarity, classification label, and match explanation.
    """
    ref_data = compute_image_hashes(
        reference_path, autocrop=autocrop, return_normalized_image=True
    )
    cand_data = compute_image_hashes(
        candidate_path, autocrop=autocrop, return_normalized_image=True
    )

    phash_dist = int(ref_data["phash"] - cand_data["phash"])
    dhash_dist = int(ref_data["dhash"] - cand_data["dhash"])

    phash_sim = calibrate_hash_similarity(phash_dist, threshold)
    dhash_sim = calibrate_hash_similarity(dhash_dist, threshold)
    combined_sim = round((phash_sim + dhash_sim) / 2.0, 2)

    similarity_label, match_reason = derive_similarity_metadata(
        phash_dist, dhash_dist, combined_sim, threshold
    )

    color_sim = compute_color_histogram_similarity(
        ref_data["normalized_image"], cand_data["normalized_image"]
    )

    likely_match = bool(phash_dist <= threshold)

    logger.info(
        "compare_two_images: phash_dist=%d dhash_dist=%d combined=%.1f%% color_hist=%.1f%% likely_match=%s",
        phash_dist, dhash_dist, combined_sim, color_sim, likely_match
    )

    return {
        "phash": {
            "reference": ref_data["phash_str"],
            "candidate": cand_data["phash_str"],
            "distance": phash_dist,
            "similarity_percentage": phash_sim,
        },
        "dhash": {
            "reference": ref_data["dhash_str"],
            "candidate": cand_data["dhash_str"],
            "distance": dhash_dist,
            "similarity_percentage": dhash_sim,
        },
        "combined_similarity_percentage": combined_sim,
        "color_histogram_similarity": color_sim,
        "likely_match": likely_match,
        "similarity_label": similarity_label,
        "match_reason": match_reason,
        "threshold": threshold,
    }


def compare_batch_images(
    reference_path: str,
    reference_filename: str,
    candidate_file_tuples: List[Tuple[str, str]],  # [(path, original_filename)]
    threshold: int = 10,
    autocrop: bool = True,
) -> Dict[str, Any]:
    """
    Compares one reference image against multiple candidate images, returning
    a ranked list. Both the reference and every candidate are run through the
    identical normalisation pipeline before hashing.
    """
    ref_data = compute_image_hashes(
        reference_path,
        original_filename=reference_filename,
        autocrop=autocrop,
        return_normalized_image=True,
    )

    ranked_results = []

    for cand_path, cand_name in candidate_file_tuples:
        try:
            cand_data = compute_image_hashes(
                cand_path,
                original_filename=cand_name,
                autocrop=autocrop,
                return_normalized_image=True,
            )

            phash_dist = int(ref_data["phash"] - cand_data["phash"])
            dhash_dist = int(ref_data["dhash"] - cand_data["dhash"])

            phash_sim = calibrate_hash_similarity(phash_dist, threshold)
            dhash_sim = calibrate_hash_similarity(dhash_dist, threshold)
            combined_sim = round((phash_sim + dhash_sim) / 2.0, 2)

            similarity_label, match_reason = derive_similarity_metadata(
                phash_dist, dhash_dist, combined_sim, threshold
            )

            color_sim = compute_color_histogram_similarity(
                ref_data["normalized_image"], cand_data["normalized_image"]
            )

            likely_match = bool(phash_dist <= threshold)

            ranked_results.append({
                "candidate_filename": cand_name,
                "phash_distance": phash_dist,
                "dhash_distance": dhash_dist,
                "phash_similarity": phash_sim,
                "dhash_similarity": dhash_sim,
                "combined_similarity_percentage": combined_sim,
                "color_histogram_similarity": color_sim,
                "similarity_label": similarity_label,
                "match_reason": match_reason,
                "likely_match": likely_match,
            })

        except ImageHashError as e:
            logger.warning("Skipping candidate '%s': %s", cand_name, e)
            ranked_results.append({
                "candidate_filename": cand_name,
                "error": str(e),
                "phash_distance": 64,
                "dhash_distance": 64,
                "phash_similarity": 0.0,
                "dhash_similarity": 0.0,
                "combined_similarity_percentage": 0.0,
                "color_histogram_similarity": 0.0,
                "similarity_label": "NO MATCH",
                "match_reason": f"Corrupted or invalid candidate file: {str(e)}",
                "likely_match": False,
            })

    # Sort: highest similarity first; among ties, lowest phash_distance first
    ranked_results.sort(
        key=lambda x: (-x["combined_similarity_percentage"], x["phash_distance"])
    )

    return {
        "reference_filename": reference_filename,
        "total_candidates": len(candidate_file_tuples),
        "threshold": threshold,
        "ranked_results": ranked_results,
    }


# ---------------------------------------------------------------------------
# Reference Template Library & Brand Page Similarity Engine
# ---------------------------------------------------------------------------

_REFERENCE_CORPUS_CACHE: List[Dict[str, Any]] = []

def load_reference_template_corpus(reference_dir: str = "./reference_templates") -> List[Dict[str, Any]]:
    """
    Loads all brand reference templates from reference_templates/ and precomputes their pHash values.
    Caches in memory for fast performance.
    """
    global _REFERENCE_CORPUS_CACHE
    if _REFERENCE_CORPUS_CACHE:
        return _REFERENCE_CORPUS_CACHE

    corpus = []
    ref_path = Path(reference_dir).resolve()
    if not ref_path.exists():
        logger.warning(f"Reference templates directory not found at {ref_path}")
        return corpus

    import json
    for brand_folder in ref_path.iterdir():
        if brand_folder.is_dir():
            meta_file = brand_folder / "metadata.json"
            img_file = brand_folder / "login.png"
            if not img_file.exists():
                img_files = list(brand_folder.glob("*.png")) + list(brand_folder.glob("*.jpg"))
                if img_files:
                    img_file = img_files[0]
                else:
                    continue

            meta = {}
            if meta_file.exists():
                try:
                    meta = json.loads(meta_file.read_text(encoding="utf-8"))
                except Exception as err:
                    logger.warning(f"Failed to read metadata.json in {brand_folder}: {err}")

            brand_name = meta.get("brand") or brand_folder.name.capitalize()
            page_type = meta.get("page_type") or "login"

            try:
                hashes = compute_image_hashes(str(img_file))
                corpus.append({
                    "brand": brand_name,
                    "page_type": page_type,
                    "image_path": str(img_file),
                    "relative_path": f"{brand_folder.name}/{img_file.name}",
                    "phash_obj": hashes["phash"],
                    "dhash_obj": hashes["dhash"],
                    "phash_str": hashes["phash_str"],
                    "metadata": meta
                })
            except Exception as e:
                logger.warning(f"Failed to compute reference hash for {img_file}: {e}")

    _REFERENCE_CORPUS_CACHE = corpus
    return _REFERENCE_CORPUS_CACHE


def compare_target_against_reference_templates(
    target_image_path: str,
    threshold: int = 16,
    reference_dir: str = "./reference_templates"
) -> Dict[str, Any]:
    """
    Compares target webpage screenshot against all reference brand templates using pHash.
    Returns ranked matches, distance, normalized similarity [0.0 - 1.0], best_match, and method.
    """
    corpus = load_reference_template_corpus(reference_dir)
    if not corpus:
        return {
            "status": "unavailable",
            "reason": "Reference templates unavailable.",
            "matches": [],
            "best_match": None,
            "method": "perceptual_hash"
        }

    try:
        target_hashes = compute_image_hashes(target_image_path)
        target_phash = target_hashes["phash"]

        matches = []
        for tmpl in corpus:
            dist = int(target_phash - tmpl["phash_obj"])
            # Map distance to similarity float score between 0.0 and 1.0 (64 max bits)
            sim_score = max(0.0, round(1.0 - (dist / 64.0), 3))

            matches.append({
                "brand": tmpl["brand"],
                "similarity": sim_score,
                "distance": dist,
                "template": tmpl["relative_path"],
                "page_type": tmpl["page_type"]
            })

        # Sort matches by similarity descending (highest similarity first)
        matches.sort(key=lambda x: (-x["similarity"], x["distance"]))
        best_match = matches[0] if matches else None

        return {
            "status": "complete",
            "matches": matches,
            "best_match": {
                "brand": best_match["brand"],
                "similarity": best_match["similarity"],
                "distance": best_match["distance"],
                "template": best_match["template"]
            } if best_match else None,
            "threshold_distance": threshold,
            "threshold_similarity": max(0.0, round(1.0 - (threshold / 64.0), 3)),
            "method": "perceptual_hash"
        }
    except Exception as e:
        logger.error(f"Failed to compare target against reference templates: {e}")
        return {
            "status": "error",
            "reason": str(e),
            "matches": [],
            "best_match": None,
            "method": "perceptual_hash"
        }


