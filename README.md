# YAMS Ghidra External Plugin (Experimental)

## Status

[![Ghidra Plugin CI](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/ghidra-plugin-ci.yml/badge.svg)](https://github.com/trvon/yams-ghidra-plugin/actions/workflows/ghidra-plugin-ci.yml)

Remote: git@github.com:trvon/yams-ghidra-plugin.git (from .gitmodules)

This external plugin for YAMS uses PyGhidra to analyze binaries. It implements 
the `content_extractor_v1` interface and communicates via newline-delimited JSON-RPC 
over stdio using the YAMS SDK.

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Ghidra | 11.x+ | Tested with 11.4.2. Download from [ghidra-sre.org](https://ghidra-sre.org/) |
| Python | 3.9+ | Required for yams-sdk |
| Java | 17+ | Required by Ghidra |
| PyGhidra | 1.0+ | `pip install pyghidra` |
| yams-sdk | 0.0.1+ | See installation below |

## Installation

### Step 1: Install the YAMS SDK

```bash
# From the YAMS repo root, initialize submodules if needed
git submodule update --init external/yams-sdk

# Install yams-sdk (editable mode for development)
pip install -e external/yams-sdk

# Or install from PyPI (when published)
# pip install yams-sdk
```

### Step 2: Install PyGhidra

```bash
pip install pyghidra
```

### Step 3: Set Ghidra Path

Choose one of these methods:

**Option A: Environment Variable (recommended)**
```bash
# Linux/macOS
export GHIDRA_INSTALL_DIR="/path/to/ghidra_11.4.2_PUBLIC"

# Windows PowerShell
$env:GHIDRA_INSTALL_DIR = "C:\ghidra_11.4.2_PUBLIC"

# Windows CMD
set GHIDRA_INSTALL_DIR=C:\ghidra_11.4.2_PUBLIC
```

**Option B: Pass in plugin.init config**
```json
{"id": 2, "method": "plugin.init", "params": {"ghidra_install": "/path/to/ghidra"}}
```

## Quick Start

### Test the Plugin (Standalone)

```bash
# From repo root - test handshake
echo '{"id":1,"method":"handshake.manifest"}' | python plugins/yams-ghidra-plugin/plugin.py

# Expected output:
# {"jsonrpc": "2.0", "id": 1, "result": {"name": "yams_ghidra", "version": "0.0.1", ...}}
```

### Analyze a Binary

```bash
# Initialize plugin with Ghidra path
echo '{"id":1,"method":"plugin.init","params":{"ghidra_install":"/path/to/ghidra"}}' | \
  python plugins/yams-ghidra-plugin/plugin.py

# Analyze binary
echo '{"id":2,"method":"ghidra.analyze","params":{"source":{"type":"path","path":"/path/to/binary"}}}' | \
  python plugins/yams-ghidra-plugin/plugin.py
```

### Use with YAMS Daemon

```bash
# Trust and load the plugin
yams plugin trust add plugins/yams-ghidra-plugin
yams plugin load plugins/yams-ghidra-plugin/plugin.py
yams plugin list
```

## JSON-RPC Methods

### Core Protocol

| Method | Description |
|--------|-------------|
| `handshake.manifest` | Returns plugin metadata and capabilities |
| `plugin.init` | Initialize with config `{ghidra_install?, project_dir?, project_name?}` |
| `plugin.health` | Returns `{status: "ok", started: bool, project_dir: string}` |
| `plugin.shutdown` | Clean shutdown |

### Content Extractor Interface

| Method | Description |
|--------|-------------|
| `extractor.supports` | Check if MIME type/extension is supported |
| `extractor.extract` | Extract searchable text from binary via decompilation |

### Ghidra Analysis Methods

| Method | Input | Output |
|--------|-------|--------|
| `ghidra.analyze` | `{source, opts?}` | `{arch, count, functions: [{name, addr}]}` |
| `ghidra.list_functions` | `{source, opts?: {limit, offset}}` | `{items: [{name, addr}], total}` |
| `ghidra.get_function` | `{source, func: {name or addr}}` | `{name, addr, body?}` |
| `ghidra.decompile_function` | `{source, func, opts?: {timeout_sec}}` | `{ok, decomp, meta}` |
| `ghidra.search` | `{source, query: {text}, opts?}` | `{hits: [{title, addr, snippet}], total}` |
| `ghidra.grep` | `{source, pattern: {regex}, opts?}` | `{matches: [{path, addr, snippet}], total}` |

### Source Parameter

The `source` parameter accepts:

```json
// File path
{"type": "path", "path": "/path/to/binary.exe"}

// Base64 encoded bytes
{"type": "bytes", "data": "base64-encoded-binary-data"}
```

## Supported Formats

**MIME Types:**
- `application/x-executable`
- `application/x-sharedlib`
- `application/x-mach-binary`
- `application/x-object`
- `application/octet-stream`

**Extensions:**
- Windows: `.exe`, `.dll`
- Linux: `.so`, `.elf`, `.o`, `.a`
- macOS: `.dylib`
- Generic: `.bin`, `.out`

## Troubleshooting

### "pyghidra not available"
```bash
pip install pyghidra
```

### "Ghidra not found"
Ensure `GHIDRA_INSTALL_DIR` is set correctly and points to the Ghidra installation directory (containing `ghidraRun`).

### "yams_sdk not found"
```bash
pip install -e external/yams-sdk
```

### Java Version Issues
Ghidra 11.x requires Java 17+. Check with:
```bash
java -version
```

## Development

### Running Tests

```bash
# Set required environment variables
export GHIDRA_INSTALL_DIR="/path/to/ghidra"
export TEST_GHIDRA_BIN="/path/to/test/binary"

# Run SDK tests
python tests/sdk/test_ghidra_plugin_analyze.py
```

### Project Structure

```
plugins/yams-ghidra-plugin/
├── plugin.py           # Main plugin implementation
├── pyproject.toml      # Python package metadata
├── yams-plugin.json    # YAMS plugin descriptor
└── README.md           # This file
```

## Notes

- Uses PyGhidra's high-level API for Ghidra integration
- Plugin runs headless (no GUI required)
- Ghidra project files are created in a temp directory by default
- For production use, configure `project_dir` to persist analysis results
