# YAMS Ghidra Plugin

[![Build](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/build.yml)
[![Test](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/test.yml)

Binary analysis plugin for YAMS using PyGhidra. Implements `content_extractor_v1` via JSON-RPC over stdio.

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
```

Install the optional Ghidra bindings when you want to run local analysis from
source:

```bash
uv sync --dev --extra ghidra
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
```

The build script no longer installs dependencies for you. Sync the environment
first, then run it through `uv`.

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
uv run python build.py
# or: uv run python build.py --onedir
```

The GitHub Actions `test.yml` and `build.yml` workflows use the same commands.

### Load into YAMS
For the default one-file build, load the `dist` directory:

```bash
yams plugin trust add dist
yams plugin load dist
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
uv sync --dev
uv run python build.py
uv run ruff check build.py plugin.py
```
