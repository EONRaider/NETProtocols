"""Sphinx configuration for the cross-reference check.

``sphinx-build -W -n -b dummy docs <outdir>`` renders every docstring
in ``netprotocols`` through autodoc and fails on any cross-reference
role that does not resolve. The dummy builder writes no output.

Each object is documented once, under the module that defines it:
``index.rst`` documents the package, and :func:`add_modules` appends an
``automodule`` directive for every submodule, private ones included.
:func:`resolve_import` resolves a reference that names an object
through a module that imports it, such as ``netprotocols.TCP`` for
``netprotocols.layer4.tcp.TCP``, to the object's defining module.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from docutils import nodes
from sphinx.addnodes import pending_xref
from sphinx.application import Sphinx
from sphinx.environment import BuildEnvironment

import netprotocols

project = "netprotocols"
extensions = ["sphinx.ext.autodoc", "sphinx.ext.intersphinx"]

nitpicky = True

autodoc_default_options = {
    "members": True,
    "undoc-members": True,
    "private-members": True,
    "ignore-module-all": True,
}
autodoc_typehints = "none"

intersphinx_mapping = {"python": ("https://docs.python.org/3.12", None)}

exclude_patterns = ["CLAIMS.md"]


def submodules() -> list[str]:
    """Return the dotted name of every module under ``netprotocols``."""
    return sorted(
        info.name
        for info in pkgutil.walk_packages(
            netprotocols.__path__, prefix="netprotocols."
        )
    )


def add_modules(app: Sphinx, docname: str, source: list[str]) -> None:
    """Append an ``automodule`` directive per submodule to ``index``.

    :param app: The Sphinx application.
    :param docname: The name of the document being read.
    :param source: The document's source, as a one-item list.
    """
    if docname != "index":
        return
    source[0] += "".join(
        f"\n.. automodule:: {name}\n" for name in submodules()
    )


def defining_name(target: str, module: str | None) -> str | None:
    """Return ``target`` spelt through the module that defines it.

    ``target`` is a dotted name, looked up from the package root or, for
    a name that does not start with ``netprotocols.``, from ``module``.
    Its longest importable prefix is imported and the rest read as
    attributes; the first class or function on that path supplies its
    own ``__module__`` and ``__qualname__``, and any parts after it are
    kept.

    :param target: The reference's target.
    :param module: The module the reference appears in, or ``None``.
    :returns: The defining module's spelling, or ``None`` when the path
        does not resolve, holds no class or function, or already names
        the defining module.
    """
    if not target.startswith("netprotocols."):
        if module is None:
            return None
        target = f"{module}.{target}"
    parts = target.split(".")
    obj: Any = None
    for split in range(len(parts), 0, -1):
        try:
            obj = importlib.import_module(".".join(parts[:split]))
        except ImportError:
            continue
        break
    else:
        return None
    for index in range(split, len(parts)):
        try:
            obj = getattr(obj, parts[index])
        except AttributeError:
            return None
        if isinstance(obj, type) or callable(obj):
            qualname = getattr(obj, "__qualname__", None)
            owner = getattr(obj, "__module__", None)
            if not (qualname and owner):
                return None
            spelt = ".".join([owner, qualname, *parts[index + 1 :]])
            return None if spelt == target else spelt
    return None


def resolve_import(
    app: Sphinx,
    env: BuildEnvironment,
    node: pending_xref,
    contnode: nodes.TextElement,
) -> nodes.reference | None:
    """Resolve a Python reference that names an imported object.

    :param app: The Sphinx application.
    :param env: The build environment.
    :param node: The unresolved reference.
    :param contnode: The node the reference displays.
    :returns: A reference to the object under its defining module, or
        ``None`` when :func:`defining_name` finds none or that object
        is not documented.
    """
    if node.get("refdomain") != "py":
        return None
    target = defining_name(node["reftarget"], node.get("py:module"))
    if target is None:
        return None
    return env.get_domain("py").resolve_xref(
        env,
        node["refdoc"],
        app.builder,
        node["reftype"],
        target,
        node,
        contnode,
    )


def setup(app: Sphinx) -> None:
    """Connect the event handlers above.

    :param app: The Sphinx application.
    """
    app.connect("source-read", add_modules)
    app.connect("missing-reference", resolve_import)
