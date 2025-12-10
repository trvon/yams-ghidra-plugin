#!/usr/bin/env python3
"""YAMS Ghidra Plugin - Binary analysis via PyGhidra.

This external plugin implements content_extractor_v1 for binary analysis.
It uses PyGhidra to decompile and analyze executable files.

Supports PBI-093: Binary Analysis Entity Graph - emits KG nodes/edges for
storage in YAMS knowledge graph.
"""
import base64
import hashlib
import os
import tempfile
from typing import Optional, Dict, Any

from yams_sdk.base import BasePlugin
from yams_sdk.decorators import rpc


# Default limits (configurable via config.toml: binary_analysis.*)
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_MAX_FUNCTIONS = 10000
DEFAULT_MAX_CODE_SIZE_BYTES = 1048576  # 1MB per function
DEFAULT_BATCH_SIZE = 500


class GhidraPlugin(BasePlugin):
    """Ghidra-based binary analysis plugin for YAMS."""

    def __init__(self) -> None:
        super().__init__()
        self._project_dir: Optional[str] = None
        self._project_name: str = "YamsGhidra"
        self._ghidra_install: Optional[str] = os.environ.get(
            "GHIDRA_INSTALL_DIR"
        )
        self._started = False
        # Configurable limits (from config.toml: binary_analysis.*)
        self._timeout_seconds = DEFAULT_TIMEOUT_SECONDS
        self._max_functions = DEFAULT_MAX_FUNCTIONS
        self._max_code_size = DEFAULT_MAX_CODE_SIZE_BYTES
        self._batch_size = DEFAULT_BATCH_SIZE
        # Register RPCs discovered via decorator metadata
        for name in dir(self):
            fn = getattr(self, name)
            rpc_name = getattr(fn, "__rpc_name__", None)
            if rpc_name:
                self.register(rpc_name, fn)

    def manifest(self) -> dict:
        return {
            "name": "yams_ghidra",
            "version": "0.1.0",
            "interfaces": ["content_extractor_v1", "kg_entity_provider_v1"],
            "capabilities": {
                "content_extraction": {
                    "formats": [
                        "application/x-executable",
                        "application/x-sharedlib",
                        "application/x-mach-binary",
                        "application/x-object"
                    ],
                    "extensions": [
                        ".exe", ".dll", ".so", ".dylib", ".elf", ".o", ".a"
                    ]
                },
                "kg_entities": {
                    "node_types": [
                        "binary",
                        "binary.function",
                        "binary.import",
                        "binary.export",
                        "binary.string",
                        "binary.library"
                    ],
                    "edge_relations": [
                        "CALLS",
                        "CONTAINS",
                        "IMPORTS",
                        "EXPORTS"
                    ]
                }
            }
        }

    def init(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with Ghidra.

        Note: pyghidra is NOT imported at init time to support running as a
        standalone plugin.exe bundle. The JVM/Ghidra initialization is deferred
        to the first extraction call, allowing the plugin to report health and
        respond to queries even when pyghidra isn't available.
        """
        self._ghidra_install = config.get(
            "ghidra_install", self._ghidra_install
        )
        self._project_dir = config.get("project_dir") or tempfile.mkdtemp(
            prefix="yams-ghidra-"
        )
        self._project_name = config.get("project_name", self._project_name)

        # Load configurable limits from binary_analysis section
        ba_cfg = config.get("binary_analysis", {})
        self._timeout_seconds = int(
            ba_cfg.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
        )
        self._max_functions = int(
            ba_cfg.get("max_functions", DEFAULT_MAX_FUNCTIONS)
        )
        self._max_code_size = int(
            ba_cfg.get("max_code_size_bytes", DEFAULT_MAX_CODE_SIZE_BYTES)
        )
        self._batch_size = int(
            ba_cfg.get("batch_size", DEFAULT_BATCH_SIZE)
        )
        # Defer pyghidra initialization to first use (_ensure_ghidra_started)

    def health(self) -> dict:
        return {
            "status": "ok" if self._started else "degraded",
            "started": self._started,
            "project_dir": self._project_dir,
            "pyghidra_available": self._pyghidra_available()
        }

    def _pyghidra_available(self) -> bool:
        """Check if pyghidra can be imported."""
        try:
            import pyghidra  # type: ignore  # noqa: F401
            return True
        except ImportError:
            return False

    def _ensure_ghidra_started(self) -> None:
        """Start Ghidra/JVM on first use."""
        if self._started:
            return

        try:
            import pyghidra  # type: ignore
        except ImportError as e:
            raise RuntimeError(
                f"pyghidra not available: {e}. "
                "Install pyghidra or set GHIDRA_INSTALL_DIR."
            ) from e

        # Start JVM and initialize Ghidra in headless mode
        if self._ghidra_install:
            pyghidra.start(install_dir=self._ghidra_install)
        else:
            pyghidra.start()
        self._started = True

    @staticmethod
    def _materialize_source(source: Dict[str, Any]) -> str:
        """Convert source descriptor to file path."""
        st = source.get("type")
        if st == "path":
            return source["path"]
        if st == "bytes":
            data_b64 = source.get("data")
            if not data_b64:
                raise ValueError("bytes source requires 'data' base64 field")
            data = base64.b64decode(data_b64)
            fd, p = tempfile.mkstemp(prefix="yams-ghidra-bin-")
            os.write(fd, data)
            os.close(fd)
            return p
        raise ValueError("unsupported source.type; expected 'path' or 'bytes'")

    def _open_program(self, path: str):
        """Open a program using pyghidra's open_program API."""
        self._ensure_ghidra_started()
        import pyghidra  # type: ignore
        return pyghidra.open_program(
            path,
            project_location=self._project_dir,
            project_name=self._project_name,
            analyze=True
        )

    def _iter_functions(self, program, limit: int, offset: int = 0):
        """Iterate over functions in a program."""
        listing = program.getListing()
        it = listing.getFunctions(True)
        skipped = 0
        collected = 0
        while it.hasNext():
            f = it.next()
            if skipped < offset:
                skipped += 1
                continue
            yield f
            collected += 1
            if collected >= limit:
                break

    @rpc("extractor.supports")
    def extractor_supports(self, mime_type: str, extension: str) -> dict:
        """Check if extractor supports given MIME type or extension."""
        binary_mimes = {
            "application/x-executable",
            "application/x-sharedlib",
            "application/x-mach-binary",
            "application/x-object",
            "application/octet-stream",
        }
        binary_exts = {
            ".exe", ".dll", ".so", ".dylib", ".elf", ".o", ".a",
            ".bin", ".out"
        }
        is_mime_ok = mime_type in binary_mimes
        is_ext_ok = extension.lower() in binary_exts
        return {"supported": is_mime_ok or is_ext_ok}

    @rpc("extractor.extract")
    def extractor_extract(
        self,
        source: Dict[str, Any],
        options: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Extract searchable text from binary via Ghidra decompilation."""
        opts = options or {}
        max_functions = int(opts.get("max_functions", 100))
        timeout_sec = int(opts.get("timeout_sec", 30))

        try:
            opts_analyze = {"max_functions": max_functions}
            analyze_result = self.analyze(source, opts_analyze)
            arch = analyze_result.get("arch", "unknown")
            functions = analyze_result.get("functions", [])

            if not functions:
                return {
                    "text": None,
                    "metadata": {},
                    "error": "No functions found in binary"
                }

            path = self._materialize_source(source)
            text_parts = [
                f"Binary Analysis: {os.path.basename(path)}",
                f"Architecture: {arch}",
                f"Total Functions: {len(functions)}",
                "",
                "=" * 80,
                "FUNCTION LISTINGS",
                "=" * 80,
                ""
            ]

            metadata = {
                "architecture": arch,
                "function_count": str(len(functions)),
                "extractor": "ghidra",
                "max_functions": str(max_functions)
            }

            decompiled_count = 0
            failed_count = 0

            for func in functions:
                try:
                    decomp_result = self.decompile_function(
                        source, func, {"timeout_sec": timeout_sec}
                    )
                    if decomp_result.get("ok"):
                        decompiled_count += 1
                        text_parts.extend([
                            f"\n{'=' * 80}",
                            f"Function: {func['name']}",
                            f"Address: {func['addr']}",
                            f"{'=' * 80}",
                            "",
                            decomp_result.get("decomp", ""),
                            ""
                        ])
                    else:
                        failed_count += 1
                        text_parts.append(
                            f"\n// Function {func['name']} @ {func['addr']}: "
                            f"Decompilation failed\n"
                        )
                except Exception as e:  # noqa: BLE001
                    failed_count += 1
                    text_parts.append(
                        f"\n// Function {func['name']} @ {func['addr']}: "
                        f"Error: {e}\n"
                    )

            metadata["decompiled_count"] = str(decompiled_count)
            metadata["failed_count"] = str(failed_count)

            return {
                "text": "\n".join(text_parts),
                "metadata": metadata,
                "error": None
            }
        except Exception as e:  # noqa: BLE001
            return {
                "text": None,
                "metadata": {},
                "error": f"Extraction failed: {e}"
            }

    @rpc("ghidra.analyze")
    def analyze(
        self,
        source: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Analyze a binary and return function list."""
        path = self._materialize_source(source)
        max_functions = int((opts or {}).get("max_functions", 50))

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            lang = program.getLanguage().getLanguageID().getIdAsString()
            funcs = []
            for f in self._iter_functions(program, limit=max_functions):
                funcs.append({
                    "name": f.getName(),
                    "addr": f.getEntryPoint().toString()
                })
            return {"arch": lang, "count": len(funcs), "functions": funcs}

    @rpc("ghidra.list_functions")
    def list_functions(
        self,
        source: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """List functions with pagination."""
        path = self._materialize_source(source)
        limit = int((opts or {}).get("limit", 100))
        offset = int((opts or {}).get("offset", 0))

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            items = []
            for f in self._iter_functions(program, limit=limit, offset=offset):
                items.append({
                    "name": f.getName(),
                    "addr": f.getEntryPoint().toString()
                })
            return {"items": items, "total": offset + len(items)}

    @rpc("ghidra.get_function")
    def get_function(
        self,
        source: Dict[str, Any],
        func: Dict[str, Any],
        include_body: bool = False
    ) -> dict:
        """Get details of a specific function."""
        path = self._materialize_source(source)

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            addr_factory = program.getAddressFactory()
            target = None

            if "addr" in func:
                a = addr_factory.getAddress(func["addr"])
                target = listing.getFunctionAt(a)
            elif "name" in func:
                it = listing.getFunctions(True)
                while it.hasNext():
                    f = it.next()
                    if f.getName() == func["name"]:
                        target = f
                        break

            if target is None:
                return {"ok": False, "error": "NotFound"}

            out = {
                "name": target.getName(),
                "addr": target.getEntryPoint().toString()
            }
            if include_body:
                out["body"] = f"Function {target.getName()} at {out['addr']}"
            return out

    @rpc("ghidra.decompile_function")
    def decompile_function(
        self,
        source: Dict[str, Any],
        func: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Decompile a function to C code."""
        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
        except ImportError:
            return {"ok": False, "error": "DecompilerUnavailable"}

        path = self._materialize_source(source)
        timeout = int((opts or {}).get("timeout_sec", 30))

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            addr_factory = program.getAddressFactory()
            target = None

            if "addr" in func:
                a = addr_factory.getAddress(func["addr"])
                target = listing.getFunctionAt(a)
            elif "name" in func:
                it = listing.getFunctions(True)
                while it.hasNext():
                    f = it.next()
                    if f.getName() == func["name"]:
                        target = f
                        break

            if target is None:
                return {"ok": False, "error": "NotFound"}

            di = DecompInterface()
            if not di.openProgram(program):
                return {"ok": False, "error": "OpenProgramFailed"}

            monitor = ConsoleTaskMonitor()
            res = di.decompileFunction(target, timeout, monitor)
            if not res or not res.getDecompiledFunction():
                return {"ok": False, "error": "DecompileFailed"}

            decomp = res.getDecompiledFunction().getC()
            return {
                "ok": True,
                "decomp": decomp,
                "meta": {
                    "name": target.getName(),
                    "addr": target.getEntryPoint().toString()
                }
            }

    @rpc("ghidra.search")
    def search(
        self,
        source: Dict[str, Any],
        query: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Search functions by name or decompiled text."""
        text = (query or {}).get("text", "").strip()
        if not text:
            return {"hits": [], "total": 0}

        path = self._materialize_source(source)
        max_hits = int((opts or {}).get("max_hits", 25))
        timeout = int((opts or {}).get("timeout_sec", 10))
        hits = []
        total = 0

        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
            has_decompiler = True
        except ImportError:
            has_decompiler = False

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            it = listing.getFunctions(True)

            di = None
            monitor = None
            if has_decompiler:
                di = DecompInterface()
                di.openProgram(program)
                monitor = ConsoleTaskMonitor()

            while it.hasNext():
                f = it.next()
                name = f.getName()
                addr = f.getEntryPoint().toString()
                found = text.lower() in name.lower()
                snippet = ""

                if not found and di is not None:
                    try:
                        res = di.decompileFunction(f, timeout, monitor)
                        if res and res.getDecompiledFunction():
                            c = res.getDecompiledFunction().getC()
                            if text.lower() in c.lower():
                                found = True
                                idx = c.lower().find(text.lower())
                                start = max(0, idx - 40)
                                end = min(len(c), idx + 40)
                                snippet = c[start:end]
                    except Exception:  # noqa: BLE001
                        pass

                if found:
                    total += 1
                    if len(hits) < max_hits:
                        hits.append({
                            "title": name,
                            "addr": addr,
                            "snippet": snippet
                        })

            return {"hits": hits, "total": total}

    @rpc("ghidra.grep")
    def grep(
        self,
        source: Dict[str, Any],
        pattern: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Regex grep over decompiled function text."""
        import re

        regex = (pattern or {}).get("regex", "")
        if not regex:
            return {"matches": [], "total": 0}

        flags = 0
        if (pattern or {}).get("flags") == "i":
            flags |= re.IGNORECASE
        rx = re.compile(regex, flags)

        path = self._materialize_source(source)
        max_hits = int((opts or {}).get("max_hits", 25))
        timeout = int((opts or {}).get("timeout_sec", 10))
        matches = []
        total = 0

        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
        except ImportError:
            return {
                "matches": [],
                "total": 0,
                "error": "DecompilerUnavailable"
            }

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            listing = program.getListing()
            it = listing.getFunctions(True)

            di = DecompInterface()
            if not di.openProgram(program):
                return {
                    "matches": [],
                    "total": 0,
                    "error": "OpenProgramFailed"
                }

            monitor = ConsoleTaskMonitor()

            while it.hasNext():
                f = it.next()
                try:
                    res = di.decompileFunction(f, timeout, monitor)
                    if not res or not res.getDecompiledFunction():
                        continue
                    c = res.getDecompiledFunction().getC()
                    for m in rx.finditer(c):
                        total += 1
                        if len(matches) < max_hits:
                            start = max(0, m.start() - 40)
                            end = min(len(c), m.end() + 40)
                            matches.append({
                                "path": f.getName(),
                                "addr": f.getEntryPoint().toString(),
                                "snippet": c[start:end]
                            })
                except Exception:  # noqa: BLE001
                    continue

            return {"matches": matches, "total": total}

    @rpc("ghidra.getEntities")
    def get_entities(
        self,
        source: Dict[str, Any],
        opts: Optional[Dict[str, Any]] = None
    ) -> dict:
        """Extract KG entities (nodes/edges/aliases) for binary analysis.

        This RPC supports PBI-093: Binary Analysis Entity Graph.
        Returns structured data for ingestion into YAMS knowledge graph.

        Args:
            source: Binary source descriptor (path or bytes)
            opts: Options dict with:
                - offset: Starting function index (default 0)
                - limit: Max functions to process (default batch_size)
                - entity_types: List of types to extract
                  ["function", "import", "export", "string"]
                - include_decompiled: Whether to include decompiled code
                - include_call_graph: Whether to include CALLS edges

        Returns:
            {
                "nodes": [...],
                "edges": [...],
                "aliases": [...],
                "binary_sha": "sha256:...",
                "next_offset": int,
                "total_functions": int,
                "has_more": bool
            }
        """
        opts = opts or {}
        offset = int(opts.get("offset", 0))
        limit = min(
            int(opts.get("limit", self._batch_size)),
            self._max_functions
        )
        entity_types = set(opts.get("entity_types", [
            "function", "import", "export", "string"
        ]))
        include_decompiled = bool(opts.get("include_decompiled", True))
        include_call_graph = bool(opts.get("include_call_graph", True))
        timeout = int(opts.get("timeout_sec", self._timeout_seconds))

        path = self._materialize_source(source)

        # Compute binary SHA256
        with open(path, "rb") as f:
            binary_sha = hashlib.sha256(f.read()).hexdigest()
        binary_sha_short = binary_sha[:12]

        nodes = []
        edges = []
        aliases = []

        try:
            from ghidra.app.decompiler import DecompInterface  # type: ignore
            from ghidra.util.task import ConsoleTaskMonitor  # type: ignore
            has_decompiler = True
        except ImportError:
            has_decompiler = False

        with self._open_program(path) as flat_api:
            program = flat_api.getCurrentProgram()
            lang = program.getLanguage().getLanguageID().getIdAsString()
            fmt = program.getExecutableFormat()
            entry = program.getImageBase().toString()

            # Binary node (always included)
            binary_node_key = f"binary:{binary_sha}"
            nodes.append({
                "node_key": binary_node_key,
                "label": os.path.basename(path),
                "type": "binary",
                "properties": {
                    "architecture": lang,
                    "format": fmt,
                    "entry_point": entry,
                    "size": os.path.getsize(path),
                    "analysis_tool": "ghidra",
                    "sha256": binary_sha
                }
            })

            # Extract imports
            if "import" in entity_types:
                ext_mgr = program.getExternalManager()
                for lib_name in ext_mgr.getExternalLibraryNames():
                    if lib_name == "<EXTERNAL>":
                        continue
                    # Library node
                    lib_key = f"lib:{lib_name}"
                    nodes.append({
                        "node_key": lib_key,
                        "label": lib_name,
                        "type": "binary.library",
                        "properties": {}
                    })
                    edges.append({
                        "src_key": binary_node_key,
                        "dst_key": lib_key,
                        "relation": "IMPORTS"
                    })

                    # Import symbols from this library
                    ext_locs = ext_mgr.getExternalLocations(lib_name)
                    while ext_locs.hasNext():
                        ext_loc = ext_locs.next()
                        sym_name = ext_loc.getLabel()
                        import_key = f"import:{lib_name}:{sym_name}"
                        nodes.append({
                            "node_key": import_key,
                            "label": sym_name,
                            "type": "binary.import",
                            "properties": {
                                "library": lib_name
                            }
                        })
                        aliases.append({
                            "node_key": import_key,
                            "alias": sym_name,
                            "source": "ghidra"
                        })

            # Extract exports
            if "export" in entity_types:
                sym_table = program.getSymbolTable()
                for sym in sym_table.getExternalEntryPointIterator():
                    sym_name = sym.getName()
                    export_key = f"export:{binary_sha_short}:{sym_name}"
                    nodes.append({
                        "node_key": export_key,
                        "label": sym_name,
                        "type": "binary.export",
                        "properties": {
                            "address": sym.getAddress().toString()
                        }
                    })
                    edges.append({
                        "src_key": binary_node_key,
                        "dst_key": export_key,
                        "relation": "EXPORTS"
                    })
                    aliases.append({
                        "node_key": export_key,
                        "alias": sym_name,
                        "source": "ghidra"
                    })

            # Extract functions with pagination
            if "function" in entity_types:
                listing = program.getListing()
                func_iter = listing.getFunctions(True)
                total_count = 0

                # Count total (for pagination info)
                while func_iter.hasNext():
                    func_iter.next()
                    total_count += 1

                # Reset and iterate with offset/limit
                di = None
                monitor = None
                if has_decompiler and include_decompiled:
                    di = DecompInterface()
                    di.openProgram(program)
                    monitor = ConsoleTaskMonitor()

                func_nodes = []
                for f in self._iter_functions(
                    program, limit=limit, offset=offset
                ):
                    addr = f.getEntryPoint().toString()
                    func_key = f"fn:{binary_sha_short}:{addr}"
                    func_name = f.getName()

                    props = {
                        "address": addr,
                        "signature": f.getPrototypeString(False, False),
                        "size": f.getBody().getNumAddresses(),
                        "calling_convention": (
                            f.getCallingConventionName() or "unknown"
                        ),
                        "is_thunk": f.isThunk()
                    }

                    # Decompile if requested
                    if di is not None:
                        try:
                            res = di.decompileFunction(f, timeout, monitor)
                            if res and res.getDecompiledFunction():
                                code = res.getDecompiledFunction().getC()
                                # Truncate if too large
                                if len(code) > self._max_code_size:
                                    code = code[:self._max_code_size]
                                    props["truncated"] = True
                                props["decompiled"] = code
                        except Exception:  # noqa: BLE001
                            pass

                    nodes.append({
                        "node_key": func_key,
                        "label": func_name,
                        "type": "binary.function",
                        "properties": props
                    })

                    # CONTAINS edge
                    edges.append({
                        "src_key": binary_node_key,
                        "dst_key": func_key,
                        "relation": "CONTAINS"
                    })

                    # Aliases (original name + any synonyms)
                    aliases.append({
                        "node_key": func_key,
                        "alias": func_name,
                        "source": "ghidra"
                    })

                    # Demangle if needed
                    demangled = self._demangle(func_name)
                    if demangled and demangled != func_name:
                        aliases.append({
                            "node_key": func_key,
                            "alias": demangled,
                            "source": "ghidra-demangle"
                        })

                    func_nodes.append((func_key, f))

                # Extract call graph edges
                if include_call_graph:
                    for func_key, f in func_nodes:
                        called = f.getCalledFunctions(None)
                        for callee in called:
                            callee_addr = callee.getEntryPoint().toString()
                            # Check if internal or external
                            callee_key = f"fn:{binary_sha_short}:{callee_addr}"
                            if callee.isExternal():
                                ext_loc = callee.getExternalLocation()
                                if ext_loc:
                                    lib = ext_loc.getLibraryName()
                                    sym = ext_loc.getLabel()
                                    callee_key = f"import:{lib}:{sym}"

                            edges.append({
                                "src_key": func_key,
                                "dst_key": callee_key,
                                "relation": "CALLS"
                            })

                has_more = (offset + limit) < total_count
                next_offset = offset + limit if has_more else total_count
            else:
                total_count = 0
                has_more = False
                next_offset = 0

            # Extract strings
            if "string" in entity_types:
                data_iter = program.getListing().getDefinedData(True)
                str_count = 0
                max_strings = min(1000, self._max_functions)
                while data_iter.hasNext() and str_count < max_strings:
                    data = data_iter.next()
                    dt = data.getDataType()
                    if dt and "string" in dt.getName().lower():
                        val = data.getValue()
                        if val and isinstance(val, str) and len(val) > 3:
                            addr = data.getAddress().toString()
                            str_key = f"str:{binary_sha_short}:{addr}"
                            nodes.append({
                                "node_key": str_key,
                                "label": val[:50],  # Truncate label
                                "type": "binary.string",
                                "properties": {
                                    "value": val,
                                    "address": addr,
                                    "length": len(val)
                                }
                            })
                            str_count += 1

        return {
            "nodes": nodes,
            "edges": edges,
            "aliases": aliases,
            "binary_sha": f"sha256:{binary_sha}",
            "next_offset": next_offset,
            "total_functions": total_count,
            "has_more": has_more
        }

    def _demangle(self, name: str) -> Optional[str]:
        """Attempt to demangle a C++ symbol name."""
        if not name or not name.startswith(("_Z", "?")):
            return None

        # Try Ghidra's built-in demangler first
        try:
            from ghidra.app.util.demangler import (  # type: ignore
                DemanglerUtil
            )
            demangled = DemanglerUtil.demangle(name)
            if demangled:
                return demangled.getSignature(False)
        except Exception:  # noqa: BLE001
            pass

        return None


if __name__ == "__main__":
    GhidraPlugin().run()
