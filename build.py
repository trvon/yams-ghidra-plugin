#!/usr/bin/env python3
"""
Build script for yams-ghidra-plugin.

Creates a standalone executable using PyInstaller that can be loaded
by the YAMS daemon without requiring a Python interpreter.

Usage:
    python build.py [--onedir]

Options:
    --onedir    Create a directory with dependencies instead of single file
                (faster build, easier debugging, but requires copying whole dir)
"""

import argparse
import subprocess
import sys
import shutil
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Build yams-ghidra-plugin binary")
    parser.add_argument(
        "--onedir",
        action="store_true",
        help="Build as directory instead of single file",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Clean build artifacts before building",
    )
    args = parser.parse_args()

    root = Path(__file__).parent
    dist_dir = root / "dist"
    build_dir = root / "build"

    if args.clean:
        print("Cleaning build artifacts...")
        shutil.rmtree(dist_dir, ignore_errors=True)
        shutil.rmtree(build_dir, ignore_errors=True)
        # Keep committed *.spec files (tracked in the monorepo).

    # Ensure dependencies are installed
    print("Installing dependencies...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-e", str(root)],
        check=True,
    )
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "pyinstaller"],
        check=True,
    )

    # Build with PyInstaller
    # Note: route generated *.spec into build/ so we don't rewrite the committed plugin.spec.
    print("Building with PyInstaller...")
    pyinstaller_build_dir = build_dir / "pyinstaller"
    pyinstaller_work_dir = pyinstaller_build_dir / "work"
    pyinstaller_build_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--name",
        "plugin",
        "--hidden-import=json",
        "--hidden-import=sys",
        "--hidden-import=os",
        "--collect-all",
        "yams_sdk",
        "--noconfirm",
        "--distpath",
        str(dist_dir),
        "--workpath",
        str(pyinstaller_work_dir),
        "--specpath",
        str(pyinstaller_build_dir),
    ]

    if args.onedir:
        cmd.append("--onedir")
    else:
        cmd.append("--onefile")

    cmd.append(str(root / "plugin.py"))

    subprocess.run(cmd, check=True, cwd=root)

    # Copy manifest and docs to dist
    print("Copying manifest files...")
    if args.onedir:
        output_dir = dist_dir / "plugin"
    else:
        output_dir = dist_dir

    output_dir.mkdir(parents=True, exist_ok=True)

    shutil.copy(root / "yams-plugin.json", output_dir)
    shutil.copy(root / "README.md", output_dir)
    shutil.copy(root / "LICENSE", output_dir)

    print(f"\n✓ Build complete! Output in: {output_dir}")
    print("\nTo use with YAMS (recommended):")
    print(f"  yams plugin trust add {output_dir}")
    print("  # trust-add queues scan/load in the background; run this shortly:")
    print("  yams plugin list")
    print(
        "\nIf it doesn't appear yet, restart the daemon to auto-load trusted plugins:"
    )
    print("  yams daemon restart")
    print("\nOr load explicitly:")
    print(f"  yams plugin load {output_dir}")


if __name__ == "__main__":
    main()
