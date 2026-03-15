# YAMS Ghidra Plugin

[![Build](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml)
[![Test](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml)

Binary analysis plugin for YAMS using PyGhidra.

Implements:
- `content_extractor_v1` (binary text extraction / decompilation)
- `kg_entity_provider_v1` (binary entities + call graph edges for the knowledge graph)

Local development and CI both use the same `uv` + Python 3.11 workflow.

## Requirements

- Ghidra 11.x+ ([download](https://ghidra-sre.org/))
- Python 3.11 (the build and CI workflow are currently tested on 3.11)
- Java 17+
- [uv](https://docs.astral.sh/uv/)

## Development Setup

```bash
uv python install 3.11
uv sync --dev

# Optional: install local Ghidra bindings for source-mode analysis
uv sync --dev --extra ghidra
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
```

Use `uv sync --dev` for the normal source-mode setup.

For a distributable build that can actually run Ghidra extraction, build from an
environment that includes the Ghidra extra:

```bash
uv sync --dev --extra ghidra
uv run python build.py --onedir
```

The built plugin still requires a real Ghidra installation at runtime via
`GHIDRA_INSTALL_DIR` or plugin init config.

## Usage

### Run from source
```bash
# Test handshake
echo '{"id":1,"method":"handshake.manifest"}' | uv run python plugin.py

# Analyze a binary (requires `--extra ghidra` and a Ghidra install)
echo '{"id":1,"method":"ghidra.analyze","params":{"source":{"type":"path","path":"/bin/ls"}}}' | uv run python plugin.py
```

### Build the distributable plugin
```bash
# Recommended: build a self-contained directory bundle
# Requires: uv sync --dev --extra ghidra
uv run python build.py --onedir

# Smaller one-file build
uv run python build.py
```

The GitHub Actions `test.yml` and `build.yml` workflows use the same commands.

### Load into YAMS
For the recommended `--onedir` build:

```bash
yams plugin trust add dist/plugin
yams plugin list

# If needed, restart the daemon to auto-load trusted plugins
yams daemon restart

# Or load explicitly by path
yams plugin load dist/plugin

# Verify
yams plugin info yams_ghidra
yams plugin health
```

For the one-file build, trust or load `dist` instead of `dist/plugin`.

```bash
# Dev fallback (runs plugin.py via Python; slower / less secure)
yams plugin trust add .
yams plugin load .
```

Note: if `yams plugin load ...` prints a generic failure, verify with `yams plugin list` or `yams plugin info yams_ghidra` first; it may already be loaded.

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
uv sync --dev
uv run python build.py
uv run ruff check build.py plugin.py
```
