"""Tests for scripts/survey_protocols.py's reading of scapy's load_layers.

The survey labels each scapy ``layers/`` cell by whether ``import
scapy.all`` loads it, from the ``load_layers`` list in scapy's
``config.py``. These tests run that reader, and ``main()`` up to it,
over fake package trees under ``tmp_path``; no competitor source is
downloaded.
"""

import importlib.util
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


def test_loaded_layers_reads_the_declaration(tmp_path: Path) -> None:
    root = _scapy(tmp_path, DECLARATION)
    assert survey.scapy_loaded_layers(root) == {"bluetooth", "dns", "tls.all"}


def test_missing_config_is_unreadable(tmp_path: Path) -> None:
    root = _scapy(tmp_path, None)
    with pytest.raises(survey.Unreadable, match=r"config\.py: no such file"):
        survey.scapy_loaded_layers(root)


@pytest.mark.parametrize(
    "config",
    [
        DECLARATION.replace("List[str]", "list[str]"),
        DECLARATION.replace(" = [", " = (").replace("    ]", "    )"),
        "",
    ],
    ids=["annotation", "tuple", "empty-file"],
)
def test_unmatched_declaration_is_unreadable(
    tmp_path: Path, config: str
) -> None:
    root = _scapy(tmp_path, config)
    with pytest.raises(survey.Unreadable, match="matches nothing"):
        survey.scapy_loaded_layers(root)


@pytest.mark.parametrize(
    "config",
    [
        DECLARATION.replace("'", '"'),
        DECLARATION.replace(" = [", " = [] + ["),
    ],
    ids=["double-quoted", "split"],
)
def test_declaration_without_names_is_unreadable(
    tmp_path: Path, config: str
) -> None:
    root = _scapy(tmp_path, config)
    with pytest.raises(survey.Unreadable, match="no quoted module names"):
        survey.scapy_loaded_layers(root)


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (None, "no such file"),
        (DECLARATION.replace("List[str]", "list[str]"), "matches nothing"),
    ],
    ids=["missing", "unmatched"],
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
