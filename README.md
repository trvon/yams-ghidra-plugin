# YAMS Ghidra Plugin

[![Build](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml)
[![Test](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml)

Binary analysis plugin for YAMS using PyGhidra. Implements `content_extractor_v1` via JSON-RPC over stdio.

## Requirements

- Ghidra 11.x+ ([download](https://ghidra-sre.org/))
- Python 3.9+
- Java 17+

## Installation

```bash
# Install dependencies
pip install pyghidra yams-sdk

# Set Ghidra path
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
```

## Usage

### Standalone
```bash
# Test handshake
echo '{"id":1,"method":"handshake.manifest"}' | python plugin.py

# Analyze binary
echo '{"id":1,"method":"ghidra.analyze","params":{"source":{"type":"path","path":"/bin/ls"}}}' | python plugin.py
```

### With YAMS
```bash
yams plugin trust add plugins/yams-ghidra-plugin
yams plugin load plugins/yams-ghidra-plugin/plugin.py
```

## JSON-RPC Methods

| Method | Description |
|--------|-------------|
| `handshake.manifest` | Plugin metadata |
| `plugin.init` | Initialize with `{ghidra_install?, project_dir?}` |
| `plugin.health` | Status check |
| `extractor.supports` | Check MIME/extension support |
| `extractor.extract` | Extract text via decompilation |
| `ghidra.analyze` | Analyze binary, list functions |
| `ghidra.decompile_function` | Decompile specific function |
| `ghidra.search` | Search functions by name/content |

## Supported Formats

**Extensions:** `.exe`, `.dll`, `.so`, `.dylib`, `.elf`, `.o`, `.bin`

**MIME types:** `application/x-executable`, `application/x-sharedlib`, `application/x-mach-binary`

## Development

```bash
pip install -e ".[dev]"
python build.py        # Build standalone binary
ruff check plugin.py   # Lint
```
