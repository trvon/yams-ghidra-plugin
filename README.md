# YAMS Ghidra Plugin

[![Build](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml)
[![Test](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml)

Binary analysis plugin for YAMS using PyGhidra.

Implements:
- `content_extractor_v1` (binary text extraction / decompilation)
- `kg_entity_provider_v1` (binary entities + call graph edges for the knowledge graph)

## Requirements

- Ghidra 11.x+ ([download](https://ghidra-sre.org/))
- Python 3.9+
- Java 17+

## Installation

```bash
# Install dependencies (source-mode; the compiled release bundle doesn't need these)
pip install yams-sdk pyghidra

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
# Recommended: build a bundle that contains yams-plugin.json + plugin{,.exe}
# (Use --onedir if you want a self-contained directory bundle.)
python build.py --onedir

# Trust the built plugin directory (trust-add queues scan/load in the background)
yams plugin trust add plugins/yams-ghidra-plugin/dist/plugin
yams plugin list

# If needed, restart the daemon to auto-load trusted plugins
yams daemon restart

# Or load explicitly by path
yams plugin load plugins/yams-ghidra-plugin/dist/plugin

# Verify
yams plugin info yams_ghidra
yams plugin health

# Dev fallback (runs plugin.py via Python; slower / less secure)
yams plugin trust add plugins/yams-ghidra-plugin
yams plugin load plugins/yams-ghidra-plugin
```

Note: if `yams plugin load ...` prints a generic failure, verify with `yams plugin list` / `yams plugin info yams_ghidra` first; it may already be loaded.

## Knowledge Graph Entities

When loaded, the daemon can call the plugin's `kg_entity_provider_v1` to extract:
- binary / function nodes
- imports/exports/strings
- edges like `CONTAINS`, `CALLS`, `IMPORTS`, `EXPORTS`

This runs as part of post-ingest processing for supported binary extensions.

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

**Extensions:** `.exe`, `.dll`, `.so`, `.dylib`, `.elf`, `.o`, `.a`, `.sys`, `.drv`, `.ocx`, `.cpl`, `.scr`, `.bin`, `.out`, `.dex`, `.wasm`

**MIME types:** `application/x-executable`, `application/x-msdownload`, `application/x-sharedlib`, `application/x-mach-binary`, `application/x-object`, `application/octet-stream`, `application/vnd.android.dex`, `application/wasm`

## Development

```bash
pip install -e ".[dev]"
python build.py        # Build standalone binary
ruff check plugin.py   # Lint
```
