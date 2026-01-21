#!/usr/bin/env python3
"""Drag-and-drop PDF batch printer with a graphical printer chooser.

Fixes vs v2:
- Correct Windows EnumPrintersW "size query" behavior (returned_count is 0 on the first call).
- Adds a best-effort PowerShell fallback to enumerate printers if Win32 enumeration fails.

Goal:
- Drag one or more PDFs onto the window and print them all without repeated dialogs.
- Choose the printer once (dropdown), optionally remember it, then reuse for the batch.

Printing approach:
- Windows: Ghostscript + mswinpr2 (silent printing to a specific printer).
- macOS/Linux: uses `lp` (CUPS).

GUI:
- tkinter + tkinterdnd2 for drag-and-drop.

Notes for Windows:
- Ghostscript must be installed and on PATH (gswin64c / gswin32c).
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import datetime
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

CONFIG_FILE_NAME = ".pdf_drop_print_config.json"
SYSTEM_DEFAULT_SENTINEL = "__SYSTEM_DEFAULT__"


@dataclass(frozen=True)
class PrintSettings:
    """User-selected printing settings."""

    printer_name: Optional[str]
    copies: int
    remember_printer: bool


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments.

    Returns:
        Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Drag-and-drop PDF batch printer. If no PDFs are provided, "
            "a drag-and-drop GUI is launched."
        )
    )
    parser.add_argument(
        "pdf_files",
        type=Path,
        nargs="*",
        help="PDF files to print. If omitted, GUI mode is used.",
    )
    parser.add_argument(
        "--printer",
        type=str,
        default=None,
        help=(
            "Printer name to use. If omitted, the OS default printer is used "
            "(Windows/macOS/Linux)."
        ),
    )
    parser.add_argument(
        "--copies",
        type=int,
        default=1,
        help="Number of copies (default: 1).",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="Do not ask for confirmation when multiple PDFs are dropped/printed.",
    )
    parser.add_argument(
        "--gs-binary",
        type=str,
        default=None,
        help=(
            "Ghostscript executable name or full path (Windows). "
            "Default: auto-detect, e.g., gswin64c/gswin32c/gs."
        ),
    )
    parser.add_argument(
        "--remember-printer",
        action="store_true",
        help="Persist the chosen printer name in a small config file next to the script/executable.",
    )
    parser.add_argument(
        "--merge",
        action="store_true",
        help=(
            "Merge (concatenate) all input PDFs into a single PDF before output. "
            "This can reduce print-job overhead on some network printers."
        ),
    )
    parser.add_argument(
        "--merge-output",
        type=Path,
        default=None,
        help=(
            "Output path for the merged PDF. If omitted, a timestamped file is created "
            "in the first input PDF's folder (GUI) or next to the script/executable (CLI)."
        ),
    )
    parser.add_argument(
        "--merge-only",
        action="store_true",
        help="Only write the merged PDF; do not print.",
    )
    parser.add_argument(
        "--keep-merged",
        action="store_true",
        help=(
            "When printing a merged PDF that was auto-generated, keep the merged file "
            "instead of deleting it afterward."
        ),
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Force GUI drag-and-drop mode even if PDFs are specified.",
    )
    return parser.parse_args()


def get_app_directory() -> Path:
    """Return the directory of the running script or executable.

    Design goals:
    - When running as a normal Python script, save config next to the .py file.
      This avoids surprises caused by the current working directory.
    - When compiled (e.g., Nuitka), save config next to the final executable.

    Returns:
        Path to the directory containing the .py file (normal run) or the .exe
        (compiled run).
    """
    # Common convention used by PyInstaller and supported by Nuitka.
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent

    # Normal Python run: __file__ points at the script/module location on disk.
    try:
        return Path(__file__).resolve().parent
    except NameError:
        # Extremely rare (interactive). Fall back to argv[0] / sys.executable.
        argv0 = sys.argv[0] if sys.argv else ""
        candidate = Path(argv0) if argv0 else Path(sys.executable)
        try:
            return candidate.resolve().parent
        except Exception:
            return Path.cwd()


def get_config_path() -> Path:
    """Return the per-app config path (next to the script/executable).

    Returns:
        Path to the config file stored alongside the running program.
    """
    return get_app_directory() / CONFIG_FILE_NAME


def load_saved_printer_name() -> Optional[str]:
    """Load the last saved printer name from the config file.

    Returns:
        The saved printer name if configured. Returns an empty string to mean
        "use system default printer". Returns None if no config exists or the
        config could not be read.
    """
    config_path = get_config_path()
    if not config_path.is_file():
        return None

    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    saved_printer = config_data.get("printer_name")
    if not isinstance(saved_printer, str):
        return None

    saved_printer = saved_printer.strip()
    if not saved_printer:
        return None

    if saved_printer == SYSTEM_DEFAULT_SENTINEL:
        return ""

    return saved_printer


def save_printer_name(printer_name: Optional[str]) -> None:
    """Save a printer name to the config file.

    Args:
        printer_name: Printer name to persist. If empty/None, saves a sentinel that
            represents "system default printer".

    Notes:
        If the program is located under a protected folder (e.g., Program Files),
        Windows may block writing the config file. In that case, move the program
        to a user-writable folder.
    """
    config_path = get_config_path()

    normalized = (printer_name or "").strip()
    stored_value = normalized if normalized else SYSTEM_DEFAULT_SENTINEL

    config_payload = {"printer_name": stored_value}
    try:
        config_path.write_text(json.dumps(config_payload, indent=2), encoding="utf-8")
    except OSError as error:
        # Non-fatal: printing can still proceed, but the selection won't persist.
        print(f"Warning: Failed to write config file: {config_path} ({error})", file=sys.stderr)
        return


def detect_ghostscript_binary(custom_binary: Optional[str] = None) -> Optional[str]:
    """Detect a Ghostscript executable on the system.

    On Windows, the most common binaries are gswin64c.exe / gswin32c.exe.
    Some installs do not add Ghostscript to PATH, and some launch contexts
    (double-click / file association) may not inherit an updated PATH.
    This function therefore:
      1) honors an explicit override (custom_binary)
      2) tries PATH via shutil.which()
      3) on Windows, searches common install locations under Program Files

    Args:
        custom_binary: Optional explicit Ghostscript executable name or full path.

    Returns:
        The detected Ghostscript executable path, or None if not found.
    """
    if custom_binary:
        # Accept either an explicit path or a name found on PATH.
        custom_path = Path(custom_binary)
        if custom_path.is_file():
            return str(custom_path)
        found = shutil.which(custom_binary)
        return found

    # First, try PATH.
    for candidate in ("gswin64c", "gswin32c", "gs", "ghostscript"):
        found = shutil.which(candidate)
        if found is not None:
            return found

    # Windows fallback: scan common installation directories.
    if sys.platform.startswith("win"):
        candidate_paths: list[Path] = []
        for base_dir in (Path("C:/Program Files/gs"), Path("C:/Program Files (x86)/gs")):
            if not base_dir.is_dir():
                continue
            # gs installs look like: C:\Program Files\gs\gs10.06.0\bin\gswin64c.exe
            candidate_paths.extend(base_dir.glob("gs*/bin/gswin64c.exe"))
            candidate_paths.extend(base_dir.glob("gs*/bin/gswin32c.exe"))

        if candidate_paths:
            def sort_key(path_value: Path) -> tuple[int, int, int]:
                match = re.search(r"gs(\d+)\.(\d+)\.(\d+)", str(path_value))
                if match:
                    return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
                return (0, 0, 0)

            candidate_paths_sorted = sorted(candidate_paths, key=sort_key, reverse=True)
            for path_value in candidate_paths_sorted:
                if path_value.name.lower() == "gswin64c.exe":
                    return str(path_value)
            return str(candidate_paths_sorted[0])

    return None




def _format_timestamp_for_filename(timestamp: Optional[datetime.datetime] = None) -> str:
    """Format a timestamp suitable for filenames.

    Args:
        timestamp: Optional timestamp. If omitted, uses the current local time.

    Returns:
        Timestamp string like '20260121_153045'.
    """
    value = timestamp or datetime.datetime.now()
    return value.strftime("%Y%m%d_%H%M%S")


def generate_default_merged_output_path(
    pdf_paths: Sequence[Path],
    base_directory: Optional[Path] = None,
) -> Path:
    """Generate a default output path for a merged PDF.

    Args:
        pdf_paths: Input PDF paths, used to pick a reasonable default directory.
        base_directory: Optional override for where the output should be created.

    Returns:
        Path for a timestamped merged PDF file.
    """
    if base_directory is not None:
        output_directory = base_directory
    elif pdf_paths:
        output_directory = pdf_paths[0].resolve().parent
    else:
        output_directory = get_app_directory()

    timestamp = _format_timestamp_for_filename()
    return (output_directory / f"merged_{timestamp}.pdf").resolve()


def _write_ghostscript_response_file(pdf_paths: Sequence[Path]) -> Path:
    """Write a Ghostscript response file listing input PDFs.

    Ghostscript supports the @filename syntax, which reads additional arguments
    from a file. This is useful on Windows where command lines can be long.

    Args:
        pdf_paths: Input PDF paths to include in the response file.

    Returns:
        Path to a temporary response file. The caller should delete it.
    """
    response_file_handle = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".txt",
        delete=False,
    )
    try:
        for pdf_path in pdf_paths:
            # Quote paths so spaces are preserved.
            response_file_handle.write(f"\"{str(pdf_path)}\"\n")
        response_file_handle.flush()
        return Path(response_file_handle.name)
    finally:
        response_file_handle.close()


def merge_pdfs_with_ghostscript(
    pdf_paths: Sequence[Path],
    gs_binary: str,
    output_pdf_path: Path,
) -> None:
    """Merge multiple PDFs into a single PDF using Ghostscript.

    Args:
        pdf_paths: Input PDFs to concatenate, in order.
        gs_binary: Ghostscript executable path/name.
        output_pdf_path: Destination PDF path.

    Raises:
        RuntimeError: If Ghostscript fails.
    """
    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    # Use a response file to avoid Windows command-line length limits.
    response_file_path = _write_ghostscript_response_file(pdf_paths)
    try:
        command = [
            gs_binary,
            "-dBATCH",
            "-dNOPAUSE",
            "-dSAFER",
            "-sDEVICE=pdfwrite",
            "-dAutoRotatePages=/None",
            f"-sOutputFile={str(output_pdf_path)}",
            f"@{str(response_file_path)}",
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            combined = "\n".join([part for part in [stdout, stderr] if part])
            raise RuntimeError(f"Ghostscript merge failed (exit {result.returncode}).\n{combined}")
    finally:
        try:
            response_file_path.unlink(missing_ok=True)
        except OSError:
            # Best effort cleanup.
            pass


def merge_pdfs_with_pypdf(pdf_paths: Sequence[Path], output_pdf_path: Path) -> None:
    """Merge multiple PDFs into a single PDF using pypdf.

    This is a pure-Python fallback when Ghostscript is not available.

    Args:
        pdf_paths: Input PDFs to concatenate, in order.
        output_pdf_path: Destination PDF path.

    Raises:
        RuntimeError: If pypdf is not installed.
    """
    try:
        from pypdf import PdfReader, PdfWriter  # pylint: disable=import-outside-toplevel
    except ImportError as error:  # pragma: no cover
        raise RuntimeError(
            "Merging requires Ghostscript or the 'pypdf' package. Install with: pip install pypdf"
        ) from error

    output_pdf_path.parent.mkdir(parents=True, exist_ok=True)

    writer = PdfWriter()
    for pdf_path in pdf_paths:
        reader = PdfReader(str(pdf_path))
        for page in reader.pages:
            writer.add_page(page)

    with output_pdf_path.open("wb") as output_file:
        writer.write(output_file)


def merge_pdfs(
    pdf_paths: Sequence[Path],
    output_pdf_path: Path,
    gs_binary_override: Optional[str],
) -> None:
    """Merge multiple PDFs into a single PDF.

    Prefers Ghostscript when available (fast and reliable), otherwise falls back
    to pypdf.

    Args:
        pdf_paths: Input PDFs to concatenate, in order.
        output_pdf_path: Destination PDF path.
        gs_binary_override: Optional Ghostscript binary override.

    Raises:
        RuntimeError: If no supported merger is available.
    """
    gs_binary = detect_ghostscript_binary(gs_binary_override)
    if gs_binary:
        merge_pdfs_with_ghostscript(pdf_paths=pdf_paths, gs_binary=gs_binary, output_pdf_path=output_pdf_path)
        return

    merge_pdfs_with_pypdf(pdf_paths=pdf_paths, output_pdf_path=output_pdf_path)


def _safe_unlink(file_path: Path) -> None:
    """Delete a file path best-effort.

    Args:
        file_path: File path to delete.

    Returns:
        None.
    """
    try:
        file_path.unlink(missing_ok=True)
    except OSError:
        pass
def _load_winspool() -> Optional[object]:
    """Load the Windows print spooler DLL.

    Some Python distributions cannot resolve 'winspool' by short name; using the
    explicit 'winspool.drv' avoids that.

    Returns:
        A ctypes DLL handle, or None if not available.
    """
    if not sys.platform.startswith("win"):
        return None

    try:
        import ctypes  # pylint: disable=import-outside-toplevel
    except Exception:
        return None

    try:
        return ctypes.WinDLL("winspool.drv")
    except OSError:
        return None


def get_default_printer_name_windows() -> Optional[str]:
    """Get the Windows default printer name (no extra dependencies)."""
    if not sys.platform.startswith("win"):
        return None

    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        from ctypes import wintypes  # pylint: disable=import-outside-toplevel
    except Exception:
        return None

    winspool = _load_winspool()
    if winspool is None:
        return None

    get_default_printer = winspool.GetDefaultPrinterW
    get_default_printer.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    get_default_printer.restype = wintypes.BOOL

    needed_chars = wintypes.DWORD(0)
    # First call gets required buffer size (in WCHARs).
    get_default_printer(None, ctypes.byref(needed_chars))
    if needed_chars.value == 0:
        return None

    buffer = ctypes.create_unicode_buffer(needed_chars.value)
    if not get_default_printer(buffer, ctypes.byref(needed_chars)):
        return None

    value = buffer.value.strip()
    return value or None


def normalize_printer_name(printer_name: Optional[str]) -> Optional[str]:
    """Normalize user-provided printer name."""
    if printer_name is None:
        return None
    normalized = printer_name.strip()
    return normalized or None


def collect_pdfs_from_inputs(inputs: Sequence[Path], recursive: bool = False) -> list[Path]:
    """Collect PDF files from a list of input paths."""
    pdf_paths: set[Path] = set()

    for item in inputs:
        candidate = Path(item)
        if candidate.is_file() and candidate.suffix.lower() == ".pdf":
            pdf_paths.add(candidate.resolve())
            continue

        if candidate.is_dir():
            pattern = "**/*.pdf" if recursive else "*.pdf"
            for pdf in candidate.glob(pattern):
                if pdf.is_file():
                    pdf_paths.add(pdf.resolve())

    return sorted(pdf_paths)


def list_printers_windows_win32() -> list[str]:
    """List installed printers on Windows using EnumPrintersW (no extra deps)."""
    if not sys.platform.startswith("win"):
        return []

    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        from ctypes import wintypes  # pylint: disable=import-outside-toplevel
    except Exception:
        return []

    winspool = _load_winspool()
    if winspool is None:
        return []

    # Flags: local printers + connected/network printers.
    printer_enum_local = 0x00000002
    printer_enum_connections = 0x00000004
    flags = printer_enum_local | printer_enum_connections

    class PrinterInfo4(ctypes.Structure):
        _fields_ = [
            ("pPrinterName", wintypes.LPWSTR),
            ("pServerName", wintypes.LPWSTR),
            ("Attributes", wintypes.DWORD),
        ]

    enum_printers = winspool.EnumPrintersW
    enum_printers.argtypes = [
        wintypes.DWORD,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.LPBYTE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    enum_printers.restype = wintypes.BOOL

    needed_bytes = wintypes.DWORD(0)
    returned_count = wintypes.DWORD(0)

    # First call: intentionally expected to fail with INSUFFICIENT_BUFFER, but will
    # populate needed_bytes. returned_count is commonly 0 on this call.
    enum_printers(flags, None, 4, None, 0, ctypes.byref(needed_bytes), ctypes.byref(returned_count))
    if needed_bytes.value == 0:
        return []

    buffer = ctypes.create_string_buffer(needed_bytes.value)
    ok = enum_printers(
        flags,
        None,
        4,
        ctypes.cast(buffer, wintypes.LPBYTE),
        needed_bytes.value,
        ctypes.byref(needed_bytes),
        ctypes.byref(returned_count),
    )
    if not ok or returned_count.value == 0:
        return []

    printer_info_ptr = ctypes.cast(buffer, ctypes.POINTER(PrinterInfo4))

    printer_names: list[str] = []
    for index in range(int(returned_count.value)):
        name = (printer_info_ptr[index].pPrinterName or "").strip()
        if name:
            printer_names.append(name)

    # De-dup, keep stable order.
    seen: set[str] = set()
    unique_names: list[str] = []
    for name in printer_names:
        if name not in seen:
            unique_names.append(name)
            seen.add(name)
    return unique_names


def list_printers_windows_powershell() -> list[str]:
    """Best-effort printer enumeration using PowerShell Get-Printer.

    Returns:
        List of printer names, or empty list if PowerShell isn't available or fails.
    """
    if not sys.platform.startswith("win"):
        return []

    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if powershell is None:
        return []

    # Emit only the Name property, one per line.
    command = [
        powershell,
        "-NoProfile",
        "-Command",
        "Get-Printer | Select-Object -ExpandProperty Name",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return []

    names: list[str] = []
    for line in (result.stdout or "").splitlines():
        value = line.strip()
        if value:
            names.append(value)

    seen: set[str] = set()
    unique_names: list[str] = []
    for name in names:
        if name not in seen:
            unique_names.append(name)
            seen.add(name)
    return unique_names


def list_printers_windows() -> list[str]:
    """List Windows printers using Win32, with PowerShell fallback."""
    printers = list_printers_windows_win32()
    if printers:
        return printers
    return list_printers_windows_powershell()


def list_printers_cups() -> list[str]:
    """List installed printers via CUPS using `lpstat` (macOS/Linux)."""
    lpstat_binary = shutil.which("lpstat")
    if lpstat_binary is None:
        return []

    result = subprocess.run([lpstat_binary, "-p"], check=False, capture_output=True, text=True)
    if result.returncode != 0:
        return []

    printer_names: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("printer "):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1].strip():
            printer_names.append(parts[1].strip())

    seen: set[str] = set()
    unique_names: list[str] = []
    for name in printer_names:
        if name not in seen:
            unique_names.append(name)
            seen.add(name)
    return unique_names


def list_available_printers() -> list[str]:
    """List available printers for the current platform."""
    if sys.platform.startswith("win"):
        return list_printers_windows()
    return list_printers_cups()


def print_pdf_windows_ghostscript(pdf_path: Path, gs_binary: str, printer_name: str, copies: int) -> None:
    """Print a PDF on Windows using Ghostscript (silent, no dialogs)."""
    output_target = f"%printer%{printer_name}"
    command: list[str] = [
        gs_binary,
        "-dBATCH",
        "-dNOPAUSE",
        "-sDEVICE=mswinpr2",
        f"-dNumCopies={copies}",
        f"-sOutputFile={output_target}",
        str(pdf_path),
    ]

    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_snippet = (result.stderr or "").strip()[-1500:]
        raise RuntimeError(
            f"Ghostscript failed printing {pdf_path.name} (rc={result.returncode}).\n{stderr_snippet}"
        )


def print_pdf_cups(pdf_path: Path, printer_name: Optional[str], copies: int) -> None:
    """Print a PDF via CUPS using `lp` (macOS/Linux)."""
    lp_binary = shutil.which("lp")
    if lp_binary is None:
        raise RuntimeError("`lp` was not found on PATH (required for macOS/Linux printing).")

    command: list[str] = [lp_binary, "-n", str(copies)]
    if printer_name:
        command.extend(["-d", printer_name])
    command.append(str(pdf_path))

    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        stderr_snippet = (result.stderr or "").strip()[-1500:]
        raise RuntimeError(f"`lp` failed printing {pdf_path.name} (rc={result.returncode}).\n{stderr_snippet}")


def print_pdfs(pdf_paths: Sequence[Path], settings: PrintSettings, gs_binary_override: Optional[str]) -> None:
    """Print PDFs sequentially using the configured settings."""
    if not pdf_paths:
        raise ValueError("No PDF files provided.")

    normalized_printer = normalize_printer_name(settings.printer_name)

    if sys.platform.startswith("win"):
        gs_binary = detect_ghostscript_binary(gs_binary_override)
        if gs_binary is None:
            raise RuntimeError("Ghostscript was not found on PATH (required for silent Windows PDF printing).")

        if normalized_printer is None:
            normalized_printer = get_default_printer_name_windows()

        if normalized_printer is None:
            raise RuntimeError("Could not determine a Windows default printer. Select one in the dropdown.")

        for pdf_path in pdf_paths:
            print_pdf_windows_ghostscript(
                pdf_path=pdf_path,
                gs_binary=gs_binary,
                printer_name=normalized_printer,
                copies=settings.copies,
            )
    else:
        for pdf_path in pdf_paths:
            print_pdf_cups(pdf_path=pdf_path, printer_name=normalized_printer, copies=settings.copies)

    if settings.remember_printer:
        save_printer_name(normalized_printer)


def run_gui(
    default_printer_name: Optional[str],
    default_copies: int,
    default_confirm_multiple: bool,
    default_remember_printer: bool,
    default_gs_binary: Optional[str],
) -> None:
    """Run drag-and-drop GUI mode."""
    try:
        import tkinter as tk  # pylint: disable=import-outside-toplevel
        from tkinter import filedialog, messagebox, ttk  # pylint: disable=import-outside-toplevel
        from tkinterdnd2 import DND_FILES, TkinterDnD  # pylint: disable=import-outside-toplevel
    except ImportError as error:
        raise RuntimeError("GUI mode requires tkinter and tkinterdnd2. Install with: pip install tkinterdnd2") from error

    root = TkinterDnD.Tk()
    root.title("PDF Drop Printer")
    root.geometry("780x540")

    top_frame = ttk.Frame(root, padding=10)
    top_frame.pack(fill="x")

    system_default_label = "<System default>"

    printer_label = ttk.Label(top_frame, text="Printer:")
    printer_label.grid(row=0, column=0, sticky="w")

    initial_selection = default_printer_name.strip() if default_printer_name else ""
    printer_display_var = tk.StringVar(value=initial_selection if initial_selection else system_default_label)

    printer_combobox = ttk.Combobox(
        top_frame,
        textvariable=printer_display_var,
        width=62,
        state="normal",  # allow typing for odd/network printers even if enumeration misses them
    )
    printer_combobox.grid(row=0, column=1, sticky="we", padx=(8, 0))

    def refresh_printer_list() -> None:
        """Refresh the printer dropdown list.

        Behavior:
        - If the user typed a printer name not in the enumerated list, keep it.
        - If the current selection is "<System default>" but we have a saved/default
          printer name, select that (helps the "remember printer" feature).
        - Otherwise keep the current selection if it is valid.
        """
        try:
            available = list_available_printers()
        except Exception:  # pylint: disable=broad-except
            available = []

        values = [system_default_label] + available
        printer_combobox["values"] = values

        current = (printer_display_var.get() or "").strip()

        # If the user typed a custom name (not in the dropdown list), keep it.
        if current and current not in values:
            return

        preferred = (default_printer_name or "").strip()
        if (not current) or (current == system_default_label):
            if preferred and preferred in values:
                printer_display_var.set(preferred)
                return
            printer_display_var.set(system_default_label)
            return

        # Keep an explicit non-default selection that is valid.
        if current in values:
            printer_display_var.set(current)
            return

        printer_display_var.set(system_default_label)


    refresh_button = ttk.Button(top_frame, text="Refresh", command=refresh_printer_list)
    refresh_button.grid(row=0, column=2, sticky="w", padx=(8, 0))

    refresh_printer_list()

    copies_label = ttk.Label(top_frame, text="Copies:")
    copies_label.grid(row=1, column=0, sticky="w", pady=(8, 0))

    copies_var = tk.IntVar(value=max(1, int(default_copies)))
    copies_spinbox = ttk.Spinbox(top_frame, from_=1, to=99, textvariable=copies_var, width=6)
    copies_spinbox.grid(row=1, column=1, sticky="w", padx=(8, 0), pady=(8, 0))

    confirm_var = tk.BooleanVar(value=default_confirm_multiple)
    confirm_checkbox = ttk.Checkbutton(
        top_frame,
        variable=confirm_var,
        text="Confirm before printing multiple PDFs",
    )
    confirm_checkbox.grid(row=2, column=1, sticky="w", padx=(8, 0), pady=(8, 0))

    remember_var = tk.BooleanVar(value=default_remember_printer)
    remember_checkbox = ttk.Checkbutton(
        top_frame,
        variable=remember_var,
        text="Remember printer for next time",
    )
    remember_checkbox.grid(row=3, column=1, sticky="w", padx=(8, 0), pady=(6, 0))


    merge_var = tk.BooleanVar(value=False)
    merge_checkbox = ttk.Checkbutton(
        top_frame,
        variable=merge_var,
        text="Merge (concatenate) PDFs before output",
    )
    merge_checkbox.grid(row=4, column=1, sticky="w", padx=(8, 0), pady=(8, 0))

    merge_action_var = tk.StringVar(value="print")
    merge_print_radio = ttk.Radiobutton(
        top_frame,
        text="Print merged PDF",
        variable=merge_action_var,
        value="print",
    )
    merge_print_radio.grid(row=5, column=1, sticky="w", padx=(28, 0), pady=(2, 0))

    merge_save_radio = ttk.Radiobutton(
        top_frame,
        text="Save merged PDF",
        variable=merge_action_var,
        value="save",
    )
    merge_save_radio.grid(row=6, column=1, sticky="w", padx=(28, 0), pady=(2, 0))

    keep_merged_var = tk.BooleanVar(value=False)
    keep_merged_checkbox = ttk.Checkbutton(
        top_frame,
        variable=keep_merged_var,
        text="Keep merged PDF after printing (when printing merged)",
    )
    keep_merged_checkbox.grid(row=7, column=1, sticky="w", padx=(28, 0), pady=(2, 0))

    merged_output_var = tk.StringVar(value="")
    merged_output_entry = ttk.Entry(top_frame, textvariable=merged_output_var, width=62)
    merged_output_entry.grid(row=8, column=1, sticky="we", padx=(28, 0), pady=(6, 0))

    merged_output_browse_button = ttk.Button(top_frame, text="Browse...", command=lambda: None)
    merged_output_browse_button.grid(row=8, column=2, sticky="w", padx=(8, 0), pady=(6, 0))

    def update_merge_ui_state() -> None:
        """Enable/disable merge-related widgets based on selection."""
        is_enabled = bool(merge_var.get())
        action = (merge_action_var.get() or "print").strip().lower()

        radio_state = "normal" if is_enabled else "disabled"
        merge_print_radio.configure(state=radio_state)
        merge_save_radio.configure(state=radio_state)

        is_save = is_enabled and action == "save"
        entry_state = "normal" if is_save else "disabled"
        merged_output_entry.configure(state=entry_state)
        merged_output_browse_button.configure(state=entry_state)

        keep_state = "normal" if (is_enabled and action == "print") else "disabled"
        keep_merged_checkbox.configure(state=keep_state)

    def browse_merged_output() -> None:
        """Browse for a merged PDF output path."""
        initial_directory = str(get_app_directory())
        suggested_name = f"merged_{_format_timestamp_for_filename()}.pdf"
        chosen_path = filedialog.asksaveasfilename(
            parent=root,
            title="Save merged PDF as...",
            initialdir=initial_directory,
            initialfile=suggested_name,
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
        )
        if chosen_path:
            merged_output_var.set(chosen_path)
            update_merge_ui_state()

    merged_output_browse_button.configure(command=browse_merged_output)

    # Keep UI state in sync.
    merge_var.trace_add("write", lambda *_: update_merge_ui_state())
    merge_action_var.trace_add("write", lambda *_: update_merge_ui_state())
    update_merge_ui_state()

    top_frame.columnconfigure(1, weight=1)

    instruction_text = (
        "Drag and drop one or more PDF files (or folders containing PDFs) into the box below.\n"
        "Choose a printer once, then drop PDFs to print them.\n\n"
        "Tip: Enable 'Merge PDFs' to concatenate into one file before printing or saving.\n\n"
        "Windows: requires Ghostscript for silent printing.\n"
        "macOS/Linux: uses `lp` (CUPS)."
    )

    drop_label = tk.Label(
        root,
        text=instruction_text,
        relief="groove",
        bd=2,
        padx=20,
        pady=20,
        justify="center",
        anchor="center",
        wraplength=740,
    )
    drop_label.pack(expand=True, fill="both", padx=20, pady=20)
    drop_label.drop_target_register(DND_FILES)

    status_var = tk.StringVar(value=f"Ready. Config: {get_config_path()}")
    status_label = ttk.Label(root, textvariable=status_var, padding=(10, 0, 10, 10))
    status_label.pack(fill="x")

    def handle_drop(event: object) -> None:
        """Handle files dropped onto the drop area."""
        data = event.data  # type: ignore[attr-defined]
        dropped_items = drop_label.tk.splitlist(data)
        input_paths = [Path(item) for item in dropped_items]

        pdf_paths = collect_pdfs_from_inputs(input_paths, recursive=False)

        if not pdf_paths:
            messagebox.showinfo("No PDFs", "No .pdf files were found in what you dropped.", parent=root)
            return

        if confirm_var.get() and len(pdf_paths) > 1:
            confirm = messagebox.askyesno(
                "Confirm batch print",
                f"You are about to print {len(pdf_paths)} PDFs.\nProceed?",
                parent=root,
            )
            if not confirm:
                return



        merged_temp_to_delete: Optional[Path] = None

        merge_enabled = bool(merge_var.get())
        merge_action = (merge_action_var.get() or "print").strip().lower()

        if merge_enabled:
            if merge_action == "save":
                output_text = (merged_output_var.get() or "").strip()
                output_path = Path(output_text) if output_text else generate_default_merged_output_path(pdf_paths=pdf_paths)
                merged_output_var.set(str(output_path))

                status_var.set(f"Merging {len(pdf_paths)} PDF(s)...")
                root.update_idletasks()

                try:
                    merge_pdfs(pdf_paths=pdf_paths, output_pdf_path=output_path, gs_binary_override=default_gs_binary)
                except Exception as error:  # pylint: disable=broad-except
                    status_var.set("Error.")
                    messagebox.showerror("Merge failed", str(error), parent=root)
                    return

                status_var.set(f"Saved merged PDF: {output_path.name}")
                messagebox.showinfo("Saved", f"Saved merged PDF to:\n{output_path}", parent=root)
                return

            keep_merged = bool(keep_merged_var.get())
            output_text = (merged_output_var.get() or "").strip()
            if output_text:
                output_path = Path(output_text)
            else:
                output_path = Path(tempfile.gettempdir()) / f"merged_{_format_timestamp_for_filename()}.pdf"
                if not keep_merged:
                    merged_temp_to_delete = output_path

            status_var.set(f"Merging {len(pdf_paths)} PDF(s)...")
            root.update_idletasks()

            try:
                merge_pdfs(pdf_paths=pdf_paths, output_pdf_path=output_path, gs_binary_override=default_gs_binary)
            except Exception as error:  # pylint: disable=broad-except
                status_var.set("Error.")
                messagebox.showerror("Merge failed", str(error), parent=root)
                return

            pdf_paths = [output_path]
        selected = (printer_display_var.get() or "").strip()
        printer_name = "" if selected == system_default_label else selected

        settings = PrintSettings(
            printer_name=printer_name,
            copies=max(1, int(copies_var.get())),
            remember_printer=bool(remember_var.get()),
        )

        # Persist selection immediately so it is remembered even if printing fails.
        if settings.remember_printer:
            save_printer_name(normalize_printer_name(settings.printer_name))

        status_var.set(f"Printing {len(pdf_paths)} PDF(s)...")
        root.update_idletasks()

        try:
            print_pdfs(pdf_paths=pdf_paths, settings=settings, gs_binary_override=default_gs_binary)
        except Exception as error:
            status_var.set("Error.")
            messagebox.showerror("Print failed", str(error), parent=root)
            return


        if merged_temp_to_delete is not None:
            _safe_unlink(merged_temp_to_delete)
        status_var.set("Done.")
        messagebox.showinfo("Done", f"Printed {len(pdf_paths)} PDF(s).", parent=root)

    drop_label.dnd_bind("<<Drop>>", handle_drop)

    root.mainloop()


def main() -> None:
    """Main entry point."""
    args = parse_arguments()

    if args.copies < 1:
        raise SystemExit("--copies must be >= 1.")

    saved_printer_name = load_saved_printer_name()

    if args.gui or not args.pdf_files:
        initial_printer = args.printer if args.printer is not None else (saved_printer_name or "")
        run_gui(
            default_printer_name=initial_printer,
            default_copies=args.copies,
            default_confirm_multiple=not args.no_confirm,
            default_remember_printer=args.remember_printer,
            default_gs_binary=args.gs_binary,
        )
        return

    pdf_paths = collect_pdfs_from_inputs(args.pdf_files, recursive=False)
    if not pdf_paths:
        raise SystemExit("No PDF files found in the provided arguments.")

    settings = PrintSettings(
        printer_name=args.printer if args.printer is not None else saved_printer_name,
        copies=args.copies,
        remember_printer=args.remember_printer,
    )

    pdf_paths_to_print = pdf_paths
    merged_auto_generated_to_delete: Optional[Path] = None

    if args.merge or args.merge_only:
        output_path = args.merge_output
        if output_path is None:
            output_path = generate_default_merged_output_path(
                pdf_paths=pdf_paths, base_directory=get_app_directory()
            )

        merge_pdfs(pdf_paths=pdf_paths, output_pdf_path=output_path, gs_binary_override=args.gs_binary)

        if args.merge_only:
            print(f"Wrote merged PDF: {output_path}")
            return

        pdf_paths_to_print = [output_path]
        if args.merge_output is None and (not args.keep_merged):
            merged_auto_generated_to_delete = output_path

    print_pdfs(pdf_paths=pdf_paths_to_print, settings=settings, gs_binary_override=args.gs_binary)

    if merged_auto_generated_to_delete is not None:
        _safe_unlink(merged_auto_generated_to_delete)

    if args.merge or args.merge_only:
        print(f"Printed merged PDF: {pdf_paths_to_print[0].name}")
    else:
        print(f"Printed {len(pdf_paths_to_print)} PDF(s).")


if __name__ == "__main__":
    main()
