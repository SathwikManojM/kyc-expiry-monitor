"""Ephemeral OCR helpers for staff-assisted identity-document entry.

The application never persists image bytes or OCR text. Multipart parsing may use
a temporary buffer, which is closed after the request.
"""

from __future__ import annotations

import io
import os
import re
from datetime import date
from pathlib import Path
from typing import Any

from PIL import Image, ImageEnhance, ImageOps, UnidentifiedImageError

from services import parse_master_date

MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_PIXELS = 20_000_000
ALLOWED_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
_DATE_TOKEN = re.compile(
    r"(?<!\d)(?:\d{1,2}[/-]\d{1,2}[/-]\d{4}|\d{4}-\d{1,2}-\d{1,2})(?!\d)"
)


class PhotoScanError(ValueError):
    """Invalid, unsupported, or unreadable image provided for OCR."""


def _extract_labeled_value(text: str, labels: tuple[str, ...]) -> str:
    for line in text.splitlines():
        normalized = " ".join(line.strip().split())
        if not normalized:
            continue
        for label in labels:
            match = re.search(rf"\b{label}\b\s*[:#=-]?\s*(.+)$", normalized, re.IGNORECASE)
            if match:
                candidate = match.group(1).strip(" :-#|")
                candidate = re.sub(r"[^A-Za-z0-9 ./'-]", "", candidate)
                if candidate:
                    return candidate[:120]
    return ""


def _extract_labeled_date(text: str, labels: tuple[str, ...]) -> date | None:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not any(re.search(rf"\b{label}\b", line, re.IGNORECASE) for label in labels):
            continue
        search_text = line + " " + (lines[index + 1] if index + 1 < len(lines) else "")
        for match in _DATE_TOKEN.finditer(search_text):
            parsed = parse_master_date(match.group(0))
            if parsed:
                return parsed
    return None


def extract_id_fields(text: str) -> dict[str, str]:
    """Extract only labeled fields; do not return or persist the full OCR text."""
    dob = _extract_labeled_date(text, ("DOB", "Date of Birth", "Birth Date"))
    expiry = _extract_labeled_date(
        text, ("Date of Expiry", "Expiry Date", "Expiration Date", "Valid Until", "Valid Thru")
    )
    issued = _extract_labeled_date(text, ("Date of Issue", "Issue Date", "Issued On"))
    document_number = _extract_labeled_value(
        text, ("Document No", "Document Number", "Passport No", "Passport Number", "ID No", "ID Number")
    )
    labeled_document_type = _extract_labeled_value(text, ("Document Type", "Type of Document"))
    name = _extract_labeled_value(text, ("Name", "Full Name", "Surname"))
    lowered = text.casefold()
    if labeled_document_type:
        document_type = labeled_document_type
    elif "passport" in lowered:
        document_type = "Passport"
    elif "driving licence" in lowered or "driver license" in lowered or "driving license" in lowered:
        document_type = "Driving licence"
    elif "national id" in lowered or "identity card" in lowered:
        document_type = "National ID"
    else:
        document_type = ""

    result = {
        "full_name": name,
        "dob_text": dob.isoformat() if dob else "",
        "document_type": document_type,
        "document_number": document_number,
        "issue_date": issued.isoformat() if issued else "",
        "expiry_date": expiry.isoformat() if expiry else "",
    }
    return {key: value for key, value in result.items() if value}


def scan_id_photo(image_bytes: bytes) -> dict[str, Any]:
    """OCR a validated image locally; only extracted fields are returned.

    Requires both the Python ``pytesseract`` package and the Tesseract OCR
    executable to be installed. The application does not persist the original image.
    """
    if not image_bytes or len(image_bytes) > MAX_IMAGE_BYTES:
        raise PhotoScanError("Choose an image smaller than 5 MB.")

    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            if source.format not in {"JPEG", "PNG", "WEBP"}:
                raise PhotoScanError("Upload a JPEG, PNG, or WebP image.")
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise PhotoScanError("Image dimensions are too large to scan safely.")
            image = ImageOps.exif_transpose(source).convert("L")
    except PhotoScanError:
        raise
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError) as error:
        raise PhotoScanError("The uploaded file is not a readable image.") from error

    try:
        import pytesseract
        from pytesseract import TesseractNotFoundError
    except ImportError as error:
        raise RuntimeError("OCR support is not installed. Install project requirements and restart.") from error

    scale = min(2, max(1, 1800 // max(image.size)))
    if scale > 1:
        image = image.resize((image.width * scale, image.height * scale))
    image = ImageEnhance.Contrast(image).enhance(1.6)
    configured_tesseract = os.environ.get("TESSERACT_CMD", "").strip()
    if not configured_tesseract:
        standard_install = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tesseract-OCR" / "tesseract.exe"
        if standard_install.is_file():
            configured_tesseract = str(standard_install)
    if configured_tesseract:
        pytesseract.pytesseract.tesseract_cmd = configured_tesseract
    try:
        recognized_text = pytesseract.image_to_string(image, lang="eng", config="--psm 6", timeout=12)
    except TesseractNotFoundError as error:
        raise RuntimeError(
            "The Tesseract OCR engine is not installed or is not on PATH. Install Tesseract and restart KYC Watch."
        ) from error
    except RuntimeError as error:
        raise RuntimeError("OCR took too long. Try a clearer, cropped photo.") from error

    fields = extract_id_fields(recognized_text)
    return {
        "fields": fields,
        "found_fields": sorted(fields),
        "review_required": True,
        "message": "Review every suggested value against the original document before saving.",
    }
