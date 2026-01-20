#!/usr/bin/env python3
"""Drag-and-drop PDF batch printer with a graphical printer chooser.

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
    """Get the Windows default printer name (no extra dependencies).

    Returns:
        Default printer name if available, otherwise None.
    """
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


def list_printers_windows() -> list[str]:
    """List installed printers on Windows using EnumPrintersW (no extra deps).

    Returns:
        List of printer names (may be empty).
    """
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

    # First call to get required buffer size.
    enum_printers(flags, None, 4, None, 0, ctypes.byref(needed_bytes), ctypes.byref(returned_count))
    if needed_bytes.value == 0 or returned_count.value == 0:
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
            raise RuntimeError("Could not determine a Windows default printer. Specify a printer in the dropdown.")

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
        from tkinter import messagebox, ttk  # pylint: disable=import-outside-toplevel
        from tkinterdnd2 import DND_FILES, TkinterDnD  # pylint: disable=import-outside-toplevel
    except ImportError as error:
        raise RuntimeError("GUI mode requires tkinter and tkinterdnd2. Install with: pip install tkinterdnd2") from error

    root = TkinterDnD.Tk()
    root.title("PDF Drop Printer")
    root.geometry("760x440")

    top_frame = ttk.Frame(root, padding=10)
    top_frame.pack(fill="x")

    system_default_label = "<System default>"

    printer_label = ttk.Label(top_frame, text="Printer:")
    printer_label.grid(row=0, column=0, sticky="w")

    printer_display_var = tk.StringVar(value=system_default_label)

    printer_combobox = ttk.Combobox(
        top_frame,
        textvariable=printer_display_var,
        width=60,
        state="normal",  # allow typing for odd/network printers even if enumeration misses them
    )
    printer_combobox.grid(row=0, column=1, sticky="we", padx=(8, 0))

    def refresh_printer_list() -> None:
        """Refresh the printer dropdown list."""
        available: list[str] = []
        try:
            available = list_available_printers()
        except Exception:
            available = []

        values = [system_default_label] + available
        printer_combobox["values"] = values

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
        "They will be printed sequentially to the selected printer.\n\n"
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
        wraplength=720,
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

        selected = (printer_display_var.get() or "").strip()
        printer_name = "" if selected == system_default_label else selected

        settings = PrintSettings(
            printer_name=printer_name,
            copies=max(1, int(copies_var.get())),
            remember_printer=bool(remember_var.get()),
        )

        status_var.set(f"Printing {len(pdf_paths)} PDF(s)...")
        root.update_idletasks()

        try:
            print_pdfs(pdf_paths=pdf_paths, settings=settings, gs_binary_override=default_gs_binary)
        except Exception as error:
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
