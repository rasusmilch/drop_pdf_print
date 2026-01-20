"""Drag-and-drop PDF batch printer (no repeated printer prompts).

This is a simplified "drop box" utility: drag one or more PDFs onto the window
and they will be printed sequentially to a single chosen printer.

Printing approach:
- Windows: Ghostscript + mswinpr2 device (prints directly to the chosen printer).
- macOS/Linux: tries `lp` (CUPS). If `lp` is unavailable, the script errors.

Dependencies (GUI):
- tkinter (ships with most Python installs on Windows/macOS; Linux may need a package)
- tkinterdnd2 (pip install tkinterdnd2)

Dependency (printing):
- Ghostscript on Windows (must be installed and on PATH for silent printing)

Notes:
- The printer is selected once (defaults to the OS default printer) and then reused
  for all PDFs in the batch.
- A small JSON config file can remember the last-used printer.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence


CONFIG_FILE_NAME = ".pdf_drop_print_config.json"


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
        help="Persist the chosen printer name in a small config file in your home directory.",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Force GUI drag-and-drop mode even if PDFs are specified.",
    )
    return parser.parse_args()


def get_config_path() -> Path:
    """Return the per-user config path."""
    return Path.home() / CONFIG_FILE_NAME


def load_saved_printer_name() -> Optional[str]:
    """Load the last saved printer name from the config file.

    Returns:
        The saved printer name, or None if not configured.
    """
    config_path = get_config_path()
    if not config_path.is_file():
        return None

    try:
        config_data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    saved_printer = config_data.get("printer_name")
    if isinstance(saved_printer, str) and saved_printer.strip():
        return saved_printer.strip()

    return None


def save_printer_name(printer_name: Optional[str]) -> None:
    """Save a printer name to the config file.

    Args:
        printer_name: Printer name to persist.
    """
    config_path = get_config_path()
    config_payload = {"printer_name": printer_name or ""}
    try:
        config_path.write_text(json.dumps(config_payload, indent=2), encoding="utf-8")
    except OSError:
        # Non-fatal: printing can still proceed.
        return


def detect_ghostscript_binary(custom_binary: Optional[str] = None) -> Optional[str]:
    """Detect a Ghostscript executable on the system.

    Args:
        custom_binary: Optional explicit Ghostscript executable name or path.

    Returns:
        The detected Ghostscript executable name or path, or None if not found.
    """
    if custom_binary:
        return custom_binary if shutil.which(custom_binary) is not None else None

    for candidate in ("gswin64c", "gswin32c", "gs", "ghostscript"):
        if shutil.which(candidate) is not None:
            return candidate

    return None


def get_default_printer_name_windows() -> Optional[str]:
    """Get the Windows default printer name (no extra dependencies).

    Returns:
        Default printer name if available, otherwise None.
    """
    if not sys.platform.startswith("win"):
        return None

    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # pylint: disable=broad-except
        return None

    get_default_printer = ctypes.windll.winspool.GetDefaultPrinterW
    get_default_printer.argtypes = [wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    get_default_printer.restype = wintypes.BOOL

    needed_chars = wintypes.DWORD(0)
    # First call gets required buffer size (in TCHARs).
    get_default_printer(None, ctypes.byref(needed_chars))
    if needed_chars.value == 0:
        return None

    buffer = ctypes.create_unicode_buffer(needed_chars.value)
    if not get_default_printer(buffer, ctypes.byref(needed_chars)):
        return None

    value = buffer.value.strip()
    return value or None


def list_printers_windows() -> list[str]:
    """List installed printers on Windows using EnumPrintersW (no extra deps).

    Returns:
        List of printer names (may be empty).
    """
    if not sys.platform.startswith("win"):
        return []

    try:
        import ctypes
        from ctypes import wintypes
    except Exception:  # pylint: disable=broad-except
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

    enum_printers = ctypes.windll.winspool.EnumPrintersW
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

    # First call to get required buffer size.
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

    array_type = PrinterInfo4 * returned_count.value
    printers = ctypes.cast(buffer, ctypes.POINTER(array_type)).contents

    printer_names: list[str] = []
    for printer in printers:
        name = (printer.pPrinterName or "").strip()
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


def list_printers_cups() -> list[str]:
    """List installed printers via CUPS using `lpstat` (macOS/Linux).

    Returns:
        List of printer names (may be empty).
    """
    lpstat_binary = shutil.which("lpstat")
    if lpstat_binary is None:
        return []

    result = subprocess.run(
        [lpstat_binary, "-p"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return []

    printer_names: list[str] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        # Typical format: "printer NAME is idle. enabled since ..."
        if not line.startswith("printer "):
            continue
        parts = line.split()
        if len(parts) >= 2:
            name = parts[1].strip()
            if name:
                printer_names.append(name)

    seen: set[str] = set()
    unique_names: list[str] = []
    for name in printer_names:
        if name not in seen:
            unique_names.append(name)
            seen.add(name)

    return unique_names


def list_available_printers() -> list[str]:
    """List available printers for the current platform.

    Returns:
        List of printer names (may be empty).
    """
    if sys.platform.startswith("win"):
        return list_printers_windows()
    return list_printers_cups()


def normalize_printer_name(printer_name: Optional[str]) -> Optional[str]:
    """Normalize user-provided printer name."""
    if printer_name is None:
        return None
    normalized = printer_name.strip()
    return normalized or None


def collect_pdfs_from_inputs(inputs: Sequence[Path], recursive: bool = False) -> list[Path]:
    """Collect PDF files from a list of input paths.

    - If a path is a PDF file, it is included.
    - If a path is a directory, PDFs inside it are included (optionally recursive).

    Args:
        inputs: Candidate paths (files or directories).
        recursive: Whether to recurse into subdirectories.

    Returns:
        Sorted list of unique PDF paths.
    """
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


def print_pdf_windows_ghostscript(
    pdf_path: Path,
    gs_binary: str,
    printer_name: str,
    copies: int,
) -> None:
    """Print a PDF on Windows using Ghostscript (silent, no dialogs).

    Args:
        pdf_path: Path to PDF.
        gs_binary: Ghostscript executable.
        printer_name: Windows printer name.
        copies: Number of copies.

    Raises:
        RuntimeError: If Ghostscript invocation fails.
    """
    # Ghostscript expects "%printer%PRINTER NAME" for mswinpr2 output.
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


def print_pdf_cups(
    pdf_path: Path,
    printer_name: Optional[str],
    copies: int,
) -> None:
    """Print a PDF via CUPS using `lp` (macOS/Linux).

    Args:
        pdf_path: Path to PDF.
        printer_name: Printer name, or None to use system default.
        copies: Number of copies.

    Raises:
        RuntimeError: If printing fails or `lp` is not available.
    """
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


def print_pdfs(
    pdf_paths: Sequence[Path],
    settings: PrintSettings,
    gs_binary_override: Optional[str],
) -> None:
    """Print PDFs sequentially using the configured settings.

    Args:
        pdf_paths: PDF file paths to print.
        settings: Print settings (printer, copies, remember).
        gs_binary_override: Optional Ghostscript binary override.
    """
    if not pdf_paths:
        raise ValueError("No PDF files provided.")

    normalized_printer = normalize_printer_name(settings.printer_name)

    if sys.platform.startswith("win"):
        gs_binary = detect_ghostscript_binary(gs_binary_override)
        if gs_binary is None:
            raise RuntimeError(
                "Ghostscript was not found on PATH (required for silent Windows PDF printing)."
            )

        if normalized_printer is None:
            normalized_printer = get_default_printer_name_windows()

        if normalized_printer is None:
            raise RuntimeError("Could not determine a Windows default printer. Specify --printer.")

        for pdf_path in pdf_paths:
            print_pdf_windows_ghostscript(
                pdf_path=pdf_path,
                gs_binary=gs_binary,
                printer_name=normalized_printer,
                copies=settings.copies,
            )
    else:
        # macOS/Linux
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
    """Run drag-and-drop GUI mode.

    Args:
        default_printer_name: Initial printer name.
        default_copies: Initial copies value.
        default_confirm_multiple: Whether to confirm when multiple PDFs are dropped.
        default_remember_printer: Whether to remember printer selection.
        default_gs_binary: Optional Ghostscript binary override.
    """
    try:
        import tkinter as tk
        from tkinter import messagebox, ttk
        from tkinterdnd2 import DND_FILES, TkinterDnD
    except ImportError as error:
        raise RuntimeError(
            "GUI mode requires tkinter and tkinterdnd2. Install with: pip install tkinterdnd2"
        ) from error

    root = TkinterDnD.Tk()
    root.title("PDF Drop Printer")
    root.geometry("720x420")

    top_frame = ttk.Frame(root, padding=10)
    top_frame.pack(fill="x")

    printer_label = ttk.Label(top_frame, text="Printer:")
    printer_label.grid(row=0, column=0, sticky="w")

    system_default_label = "<System default>"

    printer_display_var = tk.StringVar()

    printer_combobox = ttk.Combobox(
        top_frame,
        textvariable=printer_display_var,
        width=58,
        state="normal",  # allow typing if enumeration misses something (network printers, etc.)
    )
    printer_combobox.grid(row=0, column=1, sticky="we", padx=(8, 0))

    def refresh_printer_list() -> None:
        """Refresh the printer dropdown list."""
        available = list_available_printers()
        values = [system_default_label] + available
        printer_combobox["values"] = values

        # Keep selection if possible; otherwise fall back to default.
        current = (printer_display_var.get() or "").strip()
        if current and current in values:
            printer_display_var.set(current)
            return

        if default_printer_name and default_printer_name in values:
            printer_display_var.set(default_printer_name)
        else:
            printer_display_var.set(system_default_label)

    refresh_button = ttk.Button(top_frame, text="Refresh", command=refresh_printer_list)
    refresh_button.grid(row=0, column=2, sticky="w", padx=(8, 0))

    # Initialize dropdown choices and selection.
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

    top_frame.columnconfigure(1, weight=1)

    instruction_text = (
        "Drag and drop one or more PDF files (or folders containing PDFs) into the box below.\n"
        "They will be printed sequentially to the selected printer.\n"
        "\n"
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
        wraplength=680,
    )
    drop_label.pack(expand=True, fill="both", padx=20, pady=20)
    drop_label.drop_target_register(DND_FILES)

    status_var = tk.StringVar(value="Ready.")
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

        settings = PrintSettings(
            printer_name=(
                None
                if printer_display_var.get().strip() == system_default_label
                else (printer_display_var.get().strip() or None)
            ),
            copies=max(1, int(copies_var.get())),
            remember_printer=bool(remember_var.get()),
        )

        status_var.set(f"Printing {len(pdf_paths)} PDF(s)...")
        root.update_idletasks()

        try:
            print_pdfs(pdf_paths=pdf_paths, settings=settings, gs_binary_override=default_gs_binary)
        except Exception as error:  # pylint: disable=broad-except
            status_var.set("Error.")
            messagebox.showerror("Print failed", str(error), parent=root)
            return

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
        # GUI mode: start with CLI printer override, else saved printer, else blank (system default).
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

    print_pdfs(pdf_paths=pdf_paths, settings=settings, gs_binary_override=args.gs_binary)
    print(f"Printed {len(pdf_paths)} PDF(s).")


if __name__ == "__main__":
    main()
