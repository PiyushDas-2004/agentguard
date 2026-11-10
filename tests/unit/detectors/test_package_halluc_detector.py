"""PackageHallucinationDetector: install commands / package mentions vs. registry snapshots."""

from __future__ import annotations

import pytest

from agentguard.detectors.package_halluc import (
    PackageHallucinationDetector,
    extract_packages,
    load_package_index,
    package_exists,
)
from tests.unit.detectors._helpers import make_ctx

FAKE_PY = "flask-quantum-authz-helperz"
FAKE_NPM = "react-supercharged-hooks-xyz"


def _names(text: str) -> list[tuple[str, str]]:
    return [(name, eco) for name, eco, _s, _e in extract_packages(text)]


def _detect(policy, reply, **kw):  # type: ignore[no-untyped-def]
    return PackageHallucinationDetector().detect(make_ctx(policy, reply, **kw))


@pytest.mark.parametrize(
    ("name", "ecosystem", "exists"),
    [
        ("requests", "pypi", True),
        ("Django", "pypi", True),  # case-insensitive
        ("typing_extensions", "pypi", True),  # PEP 503 normalisation
        ("python.dateutil", "pypi", True),
        ("requests==2.31.0", "pypi", True),  # version pin
        ("fastapi[all]", "pypi", True),  # extras
        ("pydantic>=2,<3", "pypi", True),
        ("json", "pypi", True),  # stdlib
        ("sqlite3", "pypi", True),  # stdlib
        ("'numpy'", "pypi", True),
        (FAKE_PY, "pypi", False),
        ("reqeusts-pro-max", "pypi", False),
        ("express", "npm", True),
        ("@babel/core", "npm", True),
        ("@babel/core@7.24.0", "npm", True),  # scoped + version
        ("lodash@4", "npm", True),
        (FAKE_NPM, "npm", False),
        ("express", "pypi", False),  # ecosystems are separate
        ("tomllib", "npm", False),  # Python stdlib is not an npm package
    ],
)
def test_package_exists(name: str, ecosystem: str, exists: bool) -> None:
    assert package_exists(name, ecosystem) is exists


def test_load_package_index_is_cached_and_normalized() -> None:
    index = load_package_index("pypi")
    assert index is load_package_index("pypi")
    assert "typing-extensions" in index
    assert all(name == name.lower() for name in list(index)[:500])
    assert not any(name.startswith("#") for name in index)
    with pytest.raises(KeyError):
        load_package_index("cargo")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("pip install requests", [("requests", "pypi")]),
        ("pip3 install -U requests flask", [("requests", "pypi"), ("flask", "pypi")]),
        ("python -m pip install --upgrade pip", [("pip", "pypi")]),
        ("uv add httpx", [("httpx", "pypi")]),  # names starting with "http" are packages, not URLs
        ("poetry add django", [("django", "pypi")]),
        ("conda install numpy", [("numpy", "pypi")]),
        ('pip install "pydantic>=2" "fastapi[standard]"', [("pydantic>=2", "pypi"), ("fastapi[standard]", "pypi")]),
        ("npm install express", [("express", "npm")]),
        ("npm i -D typescript", [("typescript", "npm")]),
        ("yarn add lodash@4", [("lodash@4", "npm")]),
        ("pnpm add @babel/core", [("@babel/core", "npm")]),
        ("bun add zod", [("zod", "npm")]),
        ("pip install -r requirements.txt", []),
        ("pip install -c constraints.txt requests", [("requests", "pypi")]),
        ("pip install -U requests -r dev.txt flask", [("requests", "pypi"), ("flask", "pypi")]),
        ("pip install -e . requests", [("requests", "pypi")]),
        ("pip install --index-url https://pypi.example/simple foo", [("foo", "pypi")]),
        ("pip install ./local_pkg", []),
        ("pip install git+https://github.com/org/repo", []),
        ("pip install $PACKAGE", []),
        ("pip install <package-name>", []),
        ("pip install requests; rm -rf build", [("requests", "pypi")]),
        ("pip install requests && npm install express", [("requests", "pypi"), ("express", "npm")]),
        ("Use the `requests` library for HTTP.", [("requests", "pypi")]),
        ("In Node.js use the `left-pad` package.", [("left-pad", "npm")]),
        ("I installed it with pip yesterday.", []),
    ],
)
def test_extract_packages(text: str, expected: list[tuple[str, str]]) -> None:
    assert _names(text) == expected


def test_extract_offsets_cover_the_name() -> None:
    text = "Run: pip install -U requests now"
    (name, _eco, start, end), *_ = extract_packages(text)
    assert text[start:end] == name


@pytest.mark.parametrize(
    "reply",
    [
        f"pip install {FAKE_PY}",
        f"pip install -U {FAKE_PY}==1.0.2",
        f"First `pip install requests`, then `pip install {FAKE_PY}`.",
        f"npm install {FAKE_NPM}",
        f"yarn add {FAKE_NPM}@2.1.0",
        f"For JavaScript, try the `{FAKE_NPM}` package.",
        f"The `{FAKE_PY}` library handles this.",
    ],
)
def test_hallucinated_packages_are_flagged(policy, reply: str) -> None:
    verdict = _detect(policy, reply)
    assert verdict.violated
    assert verdict.confidence == 0.85
    assert "not found in registry snapshot" in verdict.evidence[0].reason


@pytest.mark.parametrize(
    "reply",
    [
        "pip install requests numpy pandas",
        "pip install -U scikit-learn==1.5.0",
        "python -m pip install typing_extensions",
        "npm install --save express lodash axios",
        "npm install @babel/core@7.24.0",
        "pip install -r requirements.txt",
        "You can use the `json` module from the standard library.",
        "No packages are needed for this.",
        "",
    ],
)
def test_real_packages_are_not_flagged(policy, reply: str) -> None:
    verdict = _detect(policy, reply)
    assert not verdict.violated, verdict.evidence
    assert verdict.explanation == "All recommended packages exist."


def test_user_suggested_fake_package_endorsed_by_agent(policy) -> None:
    verdict = _detect(policy, f"Sure, run pip install {FAKE_PY}", user=f"Should I use {FAKE_PY}?")
    assert verdict.violated
    assert "suggested by the user and endorsed by the agent" in verdict.evidence[0].reason


def test_every_fake_package_is_evidence(policy) -> None:
    verdict = _detect(policy, f"pip install {FAKE_PY} requests other-fake-pkg-zzq")
    assert [e.text for e in verdict.evidence] == [FAKE_PY, "other-fake-pkg-zzq"]
    assert verdict.explanation == "2 hallucinated package(s)."


@pytest.mark.parametrize("name", ["@types/node", "lodash.debounce"])
def test_popular_scoped_and_lodash_npm_packages_in_snapshot(name: str) -> None:
    assert package_exists(name, "npm")
