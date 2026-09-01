"""Tests that each layer sub-package exports what the layer defines.

The top-level package re-exports every public name, so an omission in a
layer's own ``__init__`` is invisible until someone writes
``from netprotocols.layer7 import DHCP`` and it fails while
``from netprotocols import DHCP`` works. Deriving the expectation from
``__module__`` rather than a hand-written list means a protocol added to
the top level but forgotten in its layer fails here.
"""

import importlib

import pytest

import netprotocols

LAYER_PACKAGES = ["layer2", "layer3", "layer4", "layer7"]


def owning_layer(name: str) -> str | None:
    """The layer sub-package defining ``name``, if any."""
    module = getattr(getattr(netprotocols, name), "__module__", None)
    if module is None:  # e.g. __version__, a plain str
        return None
    parts = module.split(".")
    if len(parts) >= 2 and parts[1] in LAYER_PACKAGES:
        return parts[1]
    return None


LAYER_NAMES = sorted(
    (layer, name)
    for name in netprotocols.__all__
    if (layer := owning_layer(name)) is not None
)


class TestLayerExports:
    @pytest.mark.parametrize("layer,name", LAYER_NAMES)
    def test_name_is_exported_by_its_layer(self, layer: str, name: str) -> None:
        """Anything importable from netprotocols is importable from its
        own layer sub-package, and is the very same object."""
        package = importlib.import_module(f"netprotocols.{layer}")
        assert name in package.__all__, (
            f"netprotocols.{name} is defined in {layer} but missing from "
            f"netprotocols/{layer}/__init__.py's __all__"
        )
        assert getattr(package, name) is getattr(netprotocols, name), (
            f"netprotocols.{layer}.{name} is a different object from "
            f"netprotocols.{name}"
        )

    @pytest.mark.parametrize("layer", LAYER_PACKAGES)
    def test_layer_exports_nothing_extra(self, layer: str) -> None:
        """A layer must not export a name the top level does not, which
        would make it reachable by only one of the two paths."""
        package = importlib.import_module(f"netprotocols.{layer}")
        extra = set(package.__all__) - set(netprotocols.__all__)
        assert not extra, (
            f"netprotocols/{layer}/__init__.py exports {sorted(extra)}, "
            f"absent from the top-level __all__"
        )

    @pytest.mark.parametrize("layer", LAYER_PACKAGES)
    def test_layer_all_matches_its_namespace(self, layer: str) -> None:
        """Every name in a layer's __all__ actually resolves."""
        package = importlib.import_module(f"netprotocols.{layer}")
        missing = [n for n in package.__all__ if not hasattr(package, n)]
        assert not missing, (
            f"netprotocols/{layer}/__init__.py lists {missing} in __all__ "
            f"but does not import them"
        )

    def test_every_layer_contributes_something(self) -> None:
        """Guards the derivation itself: if __module__ inspection broke,
        LAYER_NAMES would silently empty and every test above would
        vacuously pass."""
        covered = {layer for layer, _ in LAYER_NAMES}
        assert covered == set(LAYER_PACKAGES), (
            f"expected every layer to own at least one exported name; "
            f"got {sorted(covered)}"
        )
