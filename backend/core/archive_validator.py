"""TRASHAK AI - Secure ZIP Archive Validator.

Validates uploaded ZIP archives against security vulnerabilities, zip bombs,
path traversals, encrypted entries, symbolic links, and size limits.
Never extracts files or executes archive content.
"""

import io
import re
import stat
import zipfile
from typing import Any, Dict, List, Set

# Conservative default limits
DEFAULT_MAX_ENTRIES: int = 2000
DEFAULT_MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10 MiB
DEFAULT_MAX_TOTAL_SIZE: int = 100 * 1024 * 1024  # 100 MiB
DEFAULT_MAX_COMPRESSION_RATIO: float = 100.0
DEFAULT_MAX_PATH_LENGTH: int = 500


def validate_archive(
    data: bytes,
    max_entries: int = DEFAULT_MAX_ENTRIES,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
    max_compression_ratio: float = DEFAULT_MAX_COMPRESSION_RATIO,
    max_path_length: int = DEFAULT_MAX_PATH_LENGTH,
) -> Dict[str, Any]:
    """Validate a raw ZIP archive byte buffer against strict security constraints.

    Args:
        data: Raw archive bytes.
        max_entries: Maximum allowed number of entries in the archive.
        max_file_size: Maximum allowed uncompressed size for an individual file (bytes).
        max_total_size: Maximum allowed total uncompressed size (bytes).
        max_compression_ratio: Maximum allowable uncompressed-to-compressed size ratio.
        max_path_length: Maximum allowable character length for any path.

    Returns:
        Dict with keys:
            - 'valid' (bool): True if archive passes all security and structural checks.
            - 'file_count' (int): Total count of valid regular files in the archive.
            - 'total_uncompressed_size' (int): Total uncompressed size in bytes.
            - 'issues' (List[str]): List of identified security or formatting issues.
    """
    issues: List[str] = []
    file_count: int = 0
    total_uncompressed_size: int = 0

    # 1. Basic input validation
    if not isinstance(data, (bytes, bytearray)):
        return {
            "valid": False,
            "file_count": 0,
            "total_uncompressed_size": 0,
            "issues": ["Archive data must be bytes."],
        }

    if len(data) == 0:
        return {
            "valid": False,
            "file_count": 0,
            "total_uncompressed_size": 0,
            "issues": ["Archive data is empty."],
        }

    # 2. Parse ZIP structure safely in-memory without extraction
    try:
        archive_buffer = io.BytesIO(data)
        with zipfile.ZipFile(archive_buffer, "r") as zf:
            infolist = zf.infolist()

            # Empty archive check
            if not infolist:
                return {
                    "valid": False,
                    "file_count": 0,
                    "total_uncompressed_size": 0,
                    "issues": ["Archive contains no entries (empty archive)."],
                }

            # Excessive entries check
            if len(infolist) > max_entries:
                issues.append(
                    f"Archive exceeds maximum allowed entries limit ({len(infolist)} > {max_entries})."
                )

            # Set for case-insensitive duplicate path detection
            seen_paths_lower: Set[str] = set()

            for info in infolist:
                filename = info.filename
                orig_filename = getattr(info, "orig_filename", filename)

                # 3. Path length check
                if len(filename) > max_path_length or len(orig_filename) > max_path_length:
                    issues.append(
                        f"Path exceeds maximum allowed length of {max_path_length} characters: '{filename}'"
                    )

                # 4. Null byte or filename truncation check
                if (
                    "\x00" in filename
                    or "\x00" in orig_filename
                    or len(filename) != len(orig_filename)
                ):
                    issues.append(f"Path contains invalid null byte or truncation: '{orig_filename}'")

                # 5. Path traversal check (e.g. '../', '..\\', or 'a/../../b')
                path_parts = [p for p in re.split(r"[/\\]+", filename) if p]
                orig_path_parts = [p for p in re.split(r"[/\\]+", orig_filename) if p]
                if ".." in path_parts or ".." in orig_path_parts:
                    issues.append(f"Path traversal detected in entry: '{filename}'")

                # 6. Absolute path check (Unix '/', Windows 'C:', UNC '\\server\share')
                if (
                    filename.startswith("/")
                    or filename.startswith("\\")
                    or bool(re.match(r"^[a-zA-Z]:", filename))
                    or filename.startswith("//")
                    or orig_filename.startswith("/")
                    or orig_filename.startswith("\\")
                    or bool(re.match(r"^[a-zA-Z]:", orig_filename))
                    or orig_filename.startswith("//")
                ):
                    issues.append(f"Absolute path detected in entry: '{filename}'")

                # 7. Duplicate path check (case-insensitive, normalized slashes)
                norm_path = filename.replace("\\", "/").rstrip("/")
                norm_path_lower = norm_path.lower()
                if norm_path:
                    if norm_path_lower in seen_paths_lower:
                        issues.append(
                            f"Duplicate path detected in archive (case-insensitive): '{filename}'"
                        )
                    else:
                        seen_paths_lower.add(norm_path_lower)

                # 8. Encrypted entry check (PKWARE specification bit 0 of flag_bits)
                is_encrypted = bool(info.flag_bits & 0x1)
                if hasattr(info, "is_encrypted"):
                    try:
                        is_encrypted = is_encrypted or bool(info.is_encrypted())
                    except Exception:
                        pass

                if is_encrypted:
                    issues.append(f"Encrypted entries are not permitted: '{filename}'")

                # 9. Symbolic link check
                mode = info.external_attr >> 16
                if mode != 0 and stat.S_ISLNK(mode):
                    issues.append(f"Symbolic links are not permitted: '{filename}'")

                # Track file metrics
                is_dir = (
                    info.is_dir()
                    or filename.endswith("/")
                    or filename.endswith("\\")
                )

                if not is_dir:
                    file_count += 1

                # 10. Individual file size limit
                if info.file_size > max_file_size:
                    issues.append(
                        f"File '{filename}' exceeds maximum allowed size ({info.file_size} > {max_file_size} bytes)."
                    )

                total_uncompressed_size += info.file_size

                # 11. Per-entry compression ratio check (zip bomb detection)
                if info.file_size > 0:
                    if info.compress_size == 0:
                        issues.append(
                            f"Suspicious compression metadata for '{filename}' (non-zero uncompressed size with zero compressed size)."
                        )
                    else:
                        entry_ratio = info.file_size / info.compress_size
                        if entry_ratio > max_compression_ratio:
                            issues.append(
                                f"Suspicious compression ratio ({entry_ratio:.1f} > {max_compression_ratio}) for '{filename}'."
                            )

            # 12. Check if archive contains at least one regular file
            if file_count == 0:
                issues.append("Archive contains no regular files.")

            # 13. Total uncompressed size limit
            if total_uncompressed_size > max_total_size:
                issues.append(
                    f"Total uncompressed size exceeds limit ({total_uncompressed_size} > {max_total_size} bytes)."
                )

            # 14. Overall archive compression ratio check
            if len(data) > 0:
                overall_ratio = total_uncompressed_size / len(data)
                if overall_ratio > max_compression_ratio:
                    issues.append(
                        f"Suspicious overall compression ratio ({overall_ratio:.1f} > {max_compression_ratio})."
                    )

    except zipfile.BadZipFile:
        issues.append("Malformed ZIP file: corrupted archive header or structure.")
    except zipfile.LargeZipFile:
        issues.append("ZIP64 archive unsupported or exceeds system archive limits.")
    except Exception as exc:
        issues.append(f"Archive structure could not be parsed: {type(exc).__name__}.")

    valid = len(issues) == 0

    return {
        "valid": valid,
        "file_count": file_count,
        "total_uncompressed_size": total_uncompressed_size,
        "issues": issues,
    }
