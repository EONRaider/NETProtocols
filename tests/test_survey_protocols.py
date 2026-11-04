"""Tests for scripts/survey_protocols.py's reading of scapy's load_layers.

The survey labels each scapy ``layers/`` cell by whether ``import
scapy.all`` loads it, from the ``load_layers`` list in scapy's
``config.py``. These tests run that reader, and ``main()`` up to it,
over fake package trees under ``tmp_path``; no competitor source is
downloaded.
"""

import importlib.util
import re
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "survey_protocols.py"


def _load_survey() -> ModuleType:
    spec = importlib.util.spec_from_file_location("survey_protocols", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


survey = _load_survey()

#: The shape of scapy 2.8.0's declaration, CRLF line ends included.
DECLARATION = (
    "class Conf(ConfClass):\r\n"
    "    load_layers: List[str] = [\r\n"
    "        'bluetooth',\r\n"
    "        'dns',\r\n"
    "        'tls.all',\r\n"
    "    ]\r\n"
)


def _scapy(tmp_path: Path, config: str | None) -> Path:
    """A fake scapy package directory, with ``config`` as its config.py."""
    root = tmp_path / "scapy"
    root.mkdir()
    (root / "__init__.py").write_text("")
    if config is not None:
        (root / "config.py").write_text(config, newline="")
    return root


#: Each success case's ``config.py`` and the names it declares.
READABLE = {
    "scapy-2.8.0": (DECLARATION, {"bluetooth", "dns", "tls.all"}),
    "double-quoted": (
        DECLARATION.replace("'", '"'),
        {"bluetooth", "dns", "tls.all"},
    ),
    "list-annotation": (
        DECLARATION.replace("List[str]", "list[str]"),
        {"bluetooth", "dns", "tls.all"},
    ),
    "unannotated": (
        DECLARATION.replace(": List[str]", ""),
        {"bluetooth", "dns", "tls.all"},
    ),
    "bracket-on-next-line": (
        DECLARATION.replace(" = [\r\n", " = \\\r\n        [\r\n"),
        {"bluetooth", "dns", "tls.all"},
    ),
    "commented-out-entry": (
        DECLARATION.replace(
            "        'dns',\r\n", "        'dns',\r\n        # 'tls',\r\n"
        ),
        {"bluetooth", "dns", "tls.all"},
    ),
    "mixed-quoting": (
        DECLARATION.replace("'dns'", '"dns"'),
        {"bluetooth", "dns", "tls.all"},
    ),
    "bracket-in-comment": (
        DECLARATION.replace(
            "        'dns',\r\n",
            "        'dns',  # see conf.load_layers [docs]\r\n",
        ),
        {"bluetooth", "dns", "tls.all"},
    ),
    "ipv6-remove-block": (
        DECLARATION
        + "\r\n"
        + "if not Conf.ipv6_enabled:\r\n"
        + '    log_scapy.warning("IPv6 support disabled in Python. '
        + 'Cannot load Scapy IPv6 layers.")\r\n'
        + '    for m in ["inet6", "dhcp6", "sixlowpan"]:\r\n'
        + "        if m in Conf.load_layers:\r\n"
        + "            Conf.load_layers.remove(m)\r\n",
        {"bluetooth", "dns", "tls.all"},
    ),
}


@pytest.mark.parametrize(
    ("config", "names"), READABLE.values(), ids=READABLE.keys()
)
def test_loaded_layers_reads_the_declaration(
    tmp_path: Path, config: str, names: set[str]
) -> None:
    root = _scapy(tmp_path, config)
    assert survey.scapy_loaded_layers(root) == names


#: Each failure case's ``config.py`` (``None``: no such file) and a
#: fragment of the message it raises.
UNREADABLE = {
    "missing": (None, "config.py: no such file"),
    "syntax-error": (
        DECLARATION.replace("    ]\r\n", ""),
        "does not parse as Python",
    ),
    "empty-file": ("", "0 top-level `class Conf`"),
    "no-conf": (
        DECLARATION.replace("class Conf(", "class Config("),
        "0 top-level `class Conf`",
    ),
    "nested-conf": (
        "class Outer:\r\n    "
        + DECLARATION.replace("\r\n", "\r\n    ").rstrip(),
        "0 top-level `class Conf`",
    ),
    "two-confs": (DECLARATION * 2, "2 top-level `class Conf`"),
    "no-load-layers": (
        DECLARATION.replace("load_layers", "other_layers"),
        "binds `load_layers` in 0 statements",
    ),
    "assigned-twice": (
        DECLARATION + "    load_layers = ['dns']\r\n",
        "binds `load_layers` in 2 statements",
    ),
    "augmented": (
        DECLARATION + "    load_layers += ['sctp']\r\n",
        "binds `load_layers` in 2 statements",
    ),
    "annotation-only": (
        "class Conf(ConfClass):\r\n    load_layers: List[str]\r\n",
        "is not assigned a non-empty list",
    ),
    "tuple": (
        DECLARATION.replace(" = [", " = (").replace("    ]", "    )"),
        "is not assigned a non-empty list",
    ),
    "empty-list": (
        "class Conf(ConfClass):\r\n    load_layers: List[str] = []\r\n",
        "is not assigned a non-empty list",
    ),
    "empty-plus-list": (
        DECLARATION.replace(" = [", " = [] + ["),
        "is not assigned a non-empty list",
    ),
    "list-plus-name": (
        DECLARATION.replace("    ]\r\n", "    ] + EXTRA_LAYERS\r\n"),
        "is not assigned a non-empty list",
    ),
    "name": (
        "class Conf(ConfClass):\r\n    load_layers = DEFAULT_LAYERS\r\n",
        "is not assigned a non-empty list",
    ),
    "non-str-element": (
        DECLARATION.replace("'dns'", "DNS"),
        "is not assigned a non-empty list",
    ),
    "bytes-element": (
        DECLARATION.replace("'dns'", "b'dns'"),
        "is not assigned a non-empty list",
    ),
    "conditional-rebind": (
        DECLARATION
        + "    if EXTRA:\r\n"
        + "        load_layers = load_layers + ['sctp']\r\n",
        "line 8: `load_layers` is named outside its declaration",
    ),
    "append-in-conf": (
        DECLARATION + "    load_layers.append('sctp')\r\n",
        "line 7: `load_layers` is named outside its declaration",
    ),
    "property-override": (
        DECLARATION
        + "    @property\r\n"
        + "    def load_layers(self):\r\n"
        + "        return ['sctp']\r\n",
        "line 8: `load_layers` is named outside its declaration",
    ),
    "module-append": (
        DECLARATION + "Conf.load_layers.append('sctp')\r\n",
        "line 7: `load_layers` is named outside its declaration",
    ),
    "module-assign": (
        DECLARATION + "Conf.load_layers = ['sctp']\r\n",
        "line 7: `load_layers` is named outside its declaration",
    ),
    "instance-append": (
        DECLARATION + "conf = Conf()\r\nconf.load_layers.append('sctp')\r\n",
        "line 8: `load_layers` is named outside its declaration",
    ),
    "setattr": (
        DECLARATION + "setattr(Conf, 'load_layers', ['sctp'])\r\n",
        "line 7: `load_layers` is named outside its declaration",
    ),
    "subclass-override": (
        DECLARATION
        + "class Outer:\r\n"
        + "    class Conf(Conf):\r\n"
        + "        load_layers = ['sctp']\r\n",
        "line 9: `load_layers` is named outside its declaration",
    ),
}


@pytest.mark.parametrize(
    ("config", "message"), UNREADABLE.values(), ids=UNREADABLE.keys()
)
def test_unreadable_declaration_raises(
    tmp_path: Path, config: str | None, message: str
) -> None:
    root = _scapy(tmp_path, config)
    with pytest.raises(survey.Unreadable, match=re.escape(message)):
        survey.scapy_loaded_layers(root)


@pytest.mark.parametrize(
    ("config", "message"), UNREADABLE.values(), ids=UNREADABLE.keys()
)
def test_main_exits_1_before_any_table(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    config: str | None,
    message: str,
) -> None:
    scapy = _scapy(tmp_path, config)
    others = []
    for name in ("dpkt", "pypacker"):
        package = tmp_path / name
        package.mkdir()
        (package / "__init__.py").write_text("")
        others.append(package)
    monkeypatch.setattr(
        "sys.argv",
        [
            str(SCRIPT),
            *("--dpkt", str(others[0])),
            *("--scapy", str(scapy)),
            *("--pypacker", str(others[1])),
        ],
    )
    assert survey.main() == 1
    out, err = capsys.readouterr()
    assert out == ""
    assert err.startswith("scapy: FAILED config.py: ")
    assert message in err
    assert err.endswith(
        "; cannot tell which layers/ modules `import scapy.all` loads.\n"
    )
