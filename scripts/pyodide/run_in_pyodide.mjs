#!/usr/bin/env node
// Boots a real Pyodide (CPython-on-WebAssembly) runtime under Node and
// runs check_in_pyodide.py inside it. The `pyodide` npm package runs
// the same WebAssembly build of CPython a browser loads, with no
// display or browser binary.
//
// Usage: node run_in_pyodide.mjs <repo-root> <python-script>

import { loadPyodide } from "pyodide";
import { readFileSync } from "node:fs";

const [, , repoRoot, scriptPath] = process.argv;
if (!repoRoot || !scriptPath) {
  console.error("usage: run_in_pyodide.mjs <repo-root> <python-script>");
  process.exit(2);
}

async function main() {
  const pyodide = await loadPyodide();

  // Mount the checked-out repo read-only so the script can reach the
  // built wheel (dist/*.whl) and the real-capture fixture corpus
  // (tests/fixtures/*.pcap) without re-fetching anything over the
  // network from inside the WASM sandbox.
  pyodide.FS.mkdirTree("/repo");
  pyodide.FS.mount(
    pyodide.FS.filesystems.NODEFS,
    { root: repoRoot },
    "/repo",
  );

  const code = readFileSync(scriptPath, "utf-8");
  // The script's own last statement (main()) is its exit code: 0 for
  // success, 1 for a caught failure. An uncaught Python exception
  // (e.g. the netprotocols import itself failing) instead throws here.
  const exitCode = await pyodide.runPythonAsync(code);
  process.exit(exitCode);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
