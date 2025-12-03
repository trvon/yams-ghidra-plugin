#!/usr/bin/env python3
"""YAMS Ghidra Plugin - Binary analysis via PyGhidra.

This external plugin implements content_extractor_v1 for binary analysis.
It uses PyGhidra to decompile and analyze executable files.
"""
import base64
import os
import tempfile
from typing import Optional, Dict, Any

from yams_sdk.base import BasePlugin
from yams_sdk.decorators import rpc


class GhidraPlugin(BasePlugin):
    """Ghidra-based binary analysis plugin for YAMS."""

    def __init__(self) -> None:
        super().__init__()
        self._project_dir: Optional[str] = None
        self._project_name: str = "YamsGhidra"
        self._ghidra_install: Optional[str] = os.environ.get("GHIDRA_INSTALL_DIR")
        self._started = False
        # Register RPCs discovered via decorator metadata
        for name in dir(self):
            fn = getattr(self, name)
            rpc_name = getattr(fn, "__rpc_name__", None)
            if rpc_name:
                self.register(rpc_name, fn)

    def manifest(self) -> dict:
        return {
            "name": "yams_ghidra",
            "version": "0.0.2",
            "interfaces": ["content_extractor_v1"],
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
                }
            }
        }

    def init(self, config: Dict[str, Any]) -> None:
        """Initialize the plugin with Ghidra."""
        try:
            import pyghidra  # type: ignore
        except ImportError as e:
            raise RuntimeError(f"pyghidra not available: {e}")

        self._ghidra_install = config.get(
            "ghidra_install", self._ghidra_install
        )
        self._project_dir = config.get("project_dir") or tempfile.mkdtemp(
            prefix="yams-ghidra-"
        )
        self._project_name = config.get("project_name", self._project_name)

        if not self._started:
            # Start JVM and initialize Ghidra in headless mode
            if self._ghidra_install:
                pyghidra.start(install_dir=self._ghidra_install)
            else:
                pyghidra.start()
            self._started = True

    def health(self) -> dict:
        return {
            "status": "ok",
            "started": self._started,
            "project_dir": self._project_dir
        }

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
        """Check if this extractor supports the given MIME type or extension."""
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
        supported = mime_type in binary_mimes or extension.lower() in binary_exts
        return {"supported": supported}

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
            analyze_result = self.analyze(source, {"max_functions": max_functions})
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
            return {"text": None, "metadata": {}, "error": f"Extraction failed: {e}"}

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


if __name__ == "__main__":
    GhidraPlugin().run()
