from __future__ import annotations

import re
from pathlib import PurePath
from typing import Dict, List


# ============================================================
# CONSTANTS
# ============================================================

MAX_ATTACHMENT_RISK_SCORE = 100


# Executable file extensions.
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".com",
    ".msi",
    ".scr",
}


# Script file extensions.
SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".ps1",
    ".psm1",
    ".psd1",
    ".wsf",
    ".wsh",
}


# Archive/container formats that can deserve additional review.
SUSPICIOUS_ARCHIVE_EXTENSIONS = {
    ".zip",
    ".rar",
    ".7z",
    ".iso",
}


# Additional document/script formats that can warrant review.
MACRO_OR_ACTIVE_CONTENT_EXTENSIONS = {
    ".docm",
    ".dotm",
    ".xlsm",
    ".xltm",
    ".pptm",
    ".potm",
}


# All extension classes used for static analysis.
ALL_SUSPICIOUS_EXTENSIONS = (
    EXECUTABLE_EXTENSIONS
    | SCRIPT_EXTENSIONS
    | SUSPICIOUS_ARCHIVE_EXTENSIONS
    | MACRO_OR_ACTIVE_CONTENT_EXTENSIONS
)


# Characters that are unusual in ordinary attachment filenames.
UNUSUAL_FILENAME_CHARACTER_PATTERN = re.compile(
    r'[<>:"/\\|?*\x00-\x1F]'
)


# ============================================================
# BASIC HELPERS
# ============================================================

def clean_filename(
    filename: object,
) -> str:
    """
    Convert an incoming filename into a cleaned string.

    This function does not access the filesystem.
    """

    if filename is None:
        return ""

    return str(filename).strip()


def clamp_score(
    score: int,
) -> int:
    """
    Keep risk score between 0 and 100.
    """

    return max(
        0,
        min(
            MAX_ATTACHMENT_RISK_SCORE,
            score,
        ),
    )


def add_finding(
    findings: List[Dict[str, object]],
    indicator_type: str,
    description: str,
    severity: str,
    score_contribution: int,
) -> None:
    """
    Add one explainable attachment finding.
    """

    findings.append(
        {
            "indicator_type": indicator_type,
            "description": description,
            "severity": severity,
            "score_contribution": score_contribution,
        }
    )


# ============================================================
# EXTENSION EXTRACTION
# ============================================================

def extract_extensions(
    filename: str,
) -> List[str]:
    """
    Extract all filename extensions.

    Examples:

        report.pdf
        -> [".pdf"]

        invoice.pdf.exe
        -> [".pdf", ".exe"]

        employee.form.final.vbs
        -> [".form", ".final", ".vbs"]

    The function analyzes the filename string only and does not
    inspect an actual file.
    """

    filename = clean_filename(
        filename
    )

    if not filename:
        return []

    # Normalize separators only for filename analysis.
    normalized = filename.replace(
        "\\",
        "/",
    )

    basename = normalized.rsplit(
        "/",
        1,
    )[-1]

    # Remove leading/trailing spaces.
    basename = basename.strip()

    if not basename:
        return []

    # Split filename manually because PurePath behavior can hide
    # intermediate extensions.
    parts = basename.split(".")

    # No extension.
    if len(parts) <= 1:
        return []

    extensions: List[str] = []

    for part in parts[1:]:
        if part:
            extensions.append(
                f".{part.lower()}"
            )

    return extensions


def get_final_extension(
    filename: str,
) -> str:
    """
    Return the final filename extension.

    Example:

        invoice.pdf.exe
        -> ".exe"
    """

    extensions = extract_extensions(
        filename
    )

    if not extensions:
        return ""

    return extensions[-1]


def get_all_extensions(
    filename: str,
) -> List[str]:
    """
    Public alias for extension extraction.
    """

    return extract_extensions(
        filename
    )


# ============================================================
# DOUBLE EXTENSION ANALYSIS
# ============================================================

def has_double_extension(
    filename: str,
) -> bool:
    """
    Detect whether a filename has at least two extensions.

    Examples:

        report.pdf
        -> False

        invoice.pdf.exe
        -> True
    """

    return len(
        extract_extensions(
            filename
        )
    ) >= 2


def is_suspicious_double_extension(
    filename: str,
) -> bool:
    """
    Detect filenames where a harmless-looking extension is followed
    by a suspicious extension.

    Example:

        invoice.pdf.exe
        -> True
    """

    extensions = extract_extensions(
        filename
    )

    if len(extensions) < 2:
        return False

    final_extension = extensions[-1]

    # Any suspicious final extension is sufficient.
    if final_extension in ALL_SUSPICIOUS_EXTENSIONS:
        return True

    return False


# ============================================================
# EXTENSION CLASSIFICATION
# ============================================================

def get_extension_category(
    extension: str,
) -> str:
    """
    Classify one extension.
    """

    extension = extension.lower()

    if extension in EXECUTABLE_EXTENSIONS:
        return "executable"

    if extension in SCRIPT_EXTENSIONS:
        return "script"

    if extension in SUSPICIOUS_ARCHIVE_EXTENSIONS:
        return "archive"

    if extension in MACRO_OR_ACTIVE_CONTENT_EXTENSIONS:
        return "macro_or_active_content"

    return "normal"


def classify_extensions(
    filename: str,
) -> Dict[str, List[str]]:
    """
    Return suspicious extensions grouped by category.
    """

    extensions = extract_extensions(
        filename
    )

    result = {
        "executable_extensions": [],
        "script_extensions": [],
        "archive_extensions": [],
        "macro_or_active_content_extensions": [],
    }

    for extension in extensions:
        category = get_extension_category(
            extension
        )

        if category == "executable":
            result[
                "executable_extensions"
            ].append(extension)

        elif category == "script":
            result[
                "script_extensions"
            ].append(extension)

        elif category == "archive":
            result[
                "archive_extensions"
            ].append(extension)

        elif category == "macro_or_active_content":
            result[
                "macro_or_active_content_extensions"
            ].append(extension)

    return result


# ============================================================
# FILENAME CHARACTER ANALYSIS
# ============================================================

def find_unusual_filename_characters(
    filename: str,
) -> List[str]:
    """
    Detect characters that may create ambiguity or filesystem
    handling concerns.

    This is only a static filename check.
    """

    filename = clean_filename(
        filename
    )

    matches = sorted(
        set(
            UNUSUAL_FILENAME_CHARACTER_PATTERN.findall(
                filename
            )
        )
    )

    return matches


def has_unusual_filename_characters(
    filename: str,
) -> bool:
    """
    Return True when unusual filename characters are present.
    """

    return bool(
        find_unusual_filename_characters(
            filename
        )
    )


# ============================================================
# HIDDEN / DOT-FILE STYLE ANALYSIS
# ============================================================

def is_hidden_style_filename(
    filename: str,
) -> bool:
    """
    Detect a basename beginning with a dot.

    This is a contextual signal only.
    """

    filename = clean_filename(
        filename
    )

    if not filename:
        return False

    basename = filename.replace(
        "\\",
        "/",
    ).rsplit(
        "/",
        1,
    )[-1]

    return (
        basename.startswith(".")
        and basename not in {
            ".",
            "..",
        }
    )


# ============================================================
# DOUBLE EXTENSION EXPLANATION
# ============================================================

def describe_double_extension(
    filename: str,
) -> str:
    """
    Generate a human-readable explanation for a double-extension
    filename.
    """

    extensions = extract_extensions(
        filename
    )

    if len(extensions) < 2:
        return ""

    return (
        "The attachment filename contains multiple extensions: "
        f"{', '.join(extensions)}."
    )


# ============================================================
# MAIN ATTACHMENT ANALYSIS
# ============================================================

def analyze_attachment(
    attachment_name: str,
) -> Dict[str, object]:
    """
    Perform safe static attachment filename analysis.

    Parameters
    ----------
    attachment_name:
        Attachment filename only.

    Returns
    -------
    dict
        Structured attachment analysis containing:
        - attachment_risk_score
        - attachment_risk
        - findings
        - extensions
        - suspicious extensions
        - double-extension status
        - static-analysis flag

    Security guarantees
    -------------------
    This function does NOT:
        - open the file
        - read file contents
        - execute the file
        - extract archives
        - inspect macros
        - calculate a malware verdict
        - run external commands
    """

    filename = clean_filename(
        attachment_name
    )

    extensions = extract_extensions(
        filename
    )

    final_extension = get_final_extension(
        filename
    )

    extension_categories = classify_extensions(
        filename
    )

    unusual_characters = (
        find_unusual_filename_characters(
            filename
        )
    )

    double_extension = has_double_extension(
        filename
    )

    suspicious_double_extension = (
        is_suspicious_double_extension(
            filename
        )
    )

    hidden_style = is_hidden_style_filename(
        filename
    )

    findings: List[
        Dict[str, object]
    ] = []

    risk_score = 0

    # --------------------------------------------------------
    # Empty filename
    # --------------------------------------------------------

    if not filename:
        return {
            "attachment_name": "",
            "extensions": [],
            "final_extension": "",
            "double_extension": False,
            "suspicious_double_extension": False,
            "extension_categories": extension_categories,
            "unusual_filename_characters": [],
            "hidden_style_filename": False,
            "attachment_risk_score": 0,
            "attachment_risk": "NO ATTACHMENT",
            "findings": [],
            "static_analysis_only": True,
            "execution_performed": False,
        }

    # --------------------------------------------------------
    # Executable extension
    # --------------------------------------------------------

    if extension_categories[
        "executable_extensions"
    ]:

        extensions_text = ", ".join(
            extension_categories[
                "executable_extensions"
            ]
        )

        add_finding(
            findings,
            indicator_type="executable_extension",
            description=(
                "The attachment filename contains an executable "
                f"extension: {extensions_text}. "
                "Unexpected executable attachments should be treated "
                "with caution."
            ),
            severity="high",
            score_contribution=35,
        )

        risk_score += 35

    # --------------------------------------------------------
    # Script extension
    # --------------------------------------------------------

    if extension_categories[
        "script_extensions"
    ]:

        extensions_text = ", ".join(
            extension_categories[
                "script_extensions"
            ]
        )

        add_finding(
            findings,
            indicator_type="script_extension",
            description=(
                "The attachment filename contains a script "
                f"extension: {extensions_text}. "
                "Unexpected scripts may require additional review."
            ),
            severity="high",
            score_contribution=30,
        )

        risk_score += 30

    # --------------------------------------------------------
    # Suspicious archive
    # --------------------------------------------------------

    if extension_categories[
        "archive_extensions"
    ]:

        extensions_text = ", ".join(
            extension_categories[
                "archive_extensions"
            ]
        )

        add_finding(
            findings,
            indicator_type="suspicious_archive_extension",
            description=(
                "The attachment filename uses an archive/container "
                f"extension: {extensions_text}. "
                "Archives may contain other files and should be "
                "handled according to organizational policy."
            ),
            severity="medium",
            score_contribution=15,
        )

        risk_score += 15

    # --------------------------------------------------------
    # Macro / active content
    # --------------------------------------------------------

    if extension_categories[
        "macro_or_active_content_extensions"
    ]:

        extensions_text = ", ".join(
            extension_categories[
                "macro_or_active_content_extensions"
            ]
        )

        add_finding(
            findings,
            indicator_type="macro_or_active_content",
            description=(
                "The attachment filename uses a macro-enabled or "
                f"active-content extension: {extensions_text}. "
                "Unexpected files of this type require additional review."
            ),
            severity="medium",
            score_contribution=20,
        )

        risk_score += 20

    # --------------------------------------------------------
    # Double extension
    # --------------------------------------------------------

    if double_extension:
        contribution = 25

        description = describe_double_extension(
            filename
        )

        if suspicious_double_extension:
            description += (
                " The final extension is associated with an "
                "executable, script, archive, or active-content type."
            )

        else:
            description += (
                " Multiple extensions are not automatically malicious "
                "but may deserve contextual review."
            )

        add_finding(
            findings,
            indicator_type="double_extension",
            description=description,
            severity=(
                "high"
                if suspicious_double_extension
                else "low"
            ),
            score_contribution=contribution,
        )

        risk_score += contribution

    # --------------------------------------------------------
    # Unusual filename characters
    # --------------------------------------------------------

    if unusual_characters:
        characters_text = ", ".join(
            unusual_characters
        )

        add_finding(
            findings,
            indicator_type="unusual_filename_characters",
            description=(
                "The filename contains unusual characters: "
                f"{characters_text}."
            ),
            severity="low",
            score_contribution=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # Hidden-style filename
    # --------------------------------------------------------

    if hidden_style:
        add_finding(
            findings,
            indicator_type="hidden_style_filename",
            description=(
                "The attachment uses a dot-prefixed filename, "
                "which can make a file less noticeable."
            ),
            severity="low",
            score_contribution=5,
        )

        risk_score += 5

    # --------------------------------------------------------
    # Normal attachment
    # --------------------------------------------------------

    if not findings:
        add_finding(
            findings,
            indicator_type="no_filename_risk_indicator",
            description=(
                "No configured filename-based risk indicator was "
                "detected. Filename analysis alone cannot establish "
                "that an attachment is safe."
            ),
            severity="info",
            score_contribution=0,
        )

    # --------------------------------------------------------
    # Final risk score
    # --------------------------------------------------------

    risk_score = clamp_score(
        risk_score
    )

    # --------------------------------------------------------
    # Risk category
    # --------------------------------------------------------

    if risk_score == 0:
        risk_category = "LOW RISK"

    elif risk_score <= 20:
        risk_category = "MODERATE RISK"

    elif risk_score <= 50:
        risk_category = "SUSPICIOUS"

    else:
        risk_category = "HIGH RISK"

    return {
        "attachment_name": filename,
        "extensions": extensions,
        "final_extension": final_extension,
        "double_extension": double_extension,
        "suspicious_double_extension": suspicious_double_extension,
        "extension_categories": extension_categories,
        "unusual_filename_characters": unusual_characters,
        "hidden_style_filename": hidden_style,
        "attachment_risk_score": risk_score,
        "attachment_risk": risk_category,
        "findings": findings,
        "static_analysis_only": True,
        "execution_performed": False,
    }


# ============================================================
# HUMAN-READABLE OUTPUT
# ============================================================

def format_attachment_findings(
    analysis: Dict[str, object],
) -> List[str]:
    """
    Convert structured findings into UI-friendly text.
    """

    findings = analysis.get(
        "findings",
        [],
    )

    result: List[str] = []

    if not isinstance(
        findings,
        list,
    ):
        return result

    for finding in findings:
        if not isinstance(
            finding,
            dict,
        ):
            continue

        description = finding.get(
            "description",
            "",
        )

        if description:
            result.append(
                str(description)
            )

    return result


# ============================================================
# MODULE SELF-TEST
# ============================================================

def run_self_test() -> None:
    """
    Run deterministic checks for the attachment analyzer.
    """

    # --------------------------------------------------------
    # Test 1: Normal PDF
    # --------------------------------------------------------

    safe_result = analyze_attachment(
        "report.pdf"
    )

    assert (
        safe_result["final_extension"]
        == ".pdf"
    )

    assert (
        safe_result["attachment_risk_score"]
        == 0
    )

    assert (
        safe_result["static_analysis_only"]
        is True
    )

    assert (
        safe_result["execution_performed"]
        is False
    )

    # --------------------------------------------------------
    # Test 2: Executable
    # --------------------------------------------------------

    executable_result = analyze_attachment(
        "program.exe"
    )

    assert (
        ".exe"
        in executable_result["extensions"]
    )

    assert (
        executable_result["attachment_risk_score"]
        > 0
    )

    # --------------------------------------------------------
    # Test 3: JavaScript
    # --------------------------------------------------------

    script_result = analyze_attachment(
        "update.js"
    )

    assert (
        ".js"
        in script_result["extensions"]
    )

    # --------------------------------------------------------
    # Test 4: Double extension
    # --------------------------------------------------------

    double_result = analyze_attachment(
        "invoice.pdf.exe"
    )

    assert (
        double_result["double_extension"]
        is True
    )

    assert (
        double_result[
            "suspicious_double_extension"
        ]
        is True
    )

    assert (
        double_result["attachment_risk_score"]
        > 0
    )

    # --------------------------------------------------------
    # Test 5: Archive
    # --------------------------------------------------------

    archive_result = analyze_attachment(
        "documents.zip"
    )

    assert (
        ".zip"
        in archive_result[
            "extension_categories"
        ][
            "archive_extensions"
        ]
    )

    # --------------------------------------------------------
    # Test 6: Macro-enabled document
    # --------------------------------------------------------

    macro_result = analyze_attachment(
        "report.xlsm"
    )

    assert (
        ".xlsm"
        in macro_result[
            "extension_categories"
        ][
            "macro_or_active_content_extensions"
        ]
    )

    # --------------------------------------------------------
    # Test 7: Empty filename
    # --------------------------------------------------------

    empty_result = analyze_attachment(
        ""
    )

    assert (
        empty_result[
            "attachment_risk_score"
        ]
        == 0
    )

    assert (
        empty_result["attachment_risk"]
        == "NO ATTACHMENT"
    )

    # --------------------------------------------------------
    # Test 8: No execution guarantee
    # --------------------------------------------------------

    result = analyze_attachment(
        "invoice.pdf.exe"
    )

    assert (
        result["execution_performed"]
        is False
    )

    assert (
        result["static_analysis_only"]
        is True
    )

    print(
        "Attachment analyzer self-test: PASSED"
    )


if __name__ == "__main__":
    run_self_test()
    