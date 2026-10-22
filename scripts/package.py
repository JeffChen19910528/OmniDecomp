"""Builds a release package: binaries, plugin manifests, docs, SBOM, license list, hashes and version info.

    python -I scripts/package.py [--skip-build] [--no-smoke]

Output: dist/OmniDecomp-<version>-<target>.zip plus dist/SHA256SUMS. The zip is written with fixed
timestamps and sorted entries, so building the same tree twice yields the same archive when the binaries
are identical. After packing, the archive is unpacked into a fresh directory and the packaged binary is run
against a self-made sample (the smoke test); a failing smoke test fails the script.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"
EXE = ".exe" if sys.platform == "win32" else ""
BINS = [f"omnidecomp{EXE}", f"omnidecomp-gui{EXE}"]
DOCS = ["INSTALL.md", "PLUGIN_API.md", "SECURITY.md", "SUPPORTED_FORMATS.md", "ACCEPTANCE.md"]
FIXED_TIME = (2026, 1, 1, 0, 0, 0)


def run(cmd, **kw):
    kw.setdefault("encoding", "utf-8")
    return subprocess.run(cmd, cwd=ROOT, check=True, capture_output=True, text=True, **kw).stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def host_triple():
    for line in run(["rustc", "-vV"]).splitlines():
        if line.startswith("host:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit("cannot determine host triple")


def workspace_version():
    meta = json.loads(run(["cargo", "metadata", "--format-version", "1", "--locked", "--no-deps"]))
    return next(p["version"] for p in meta["packages"] if p["name"] == "omnidecomp-cli")


def stage(stage_dir, version, triple):
    release = ROOT / "target" / "release"
    for b in BINS:
        if not (release / b).is_file():
            raise SystemExit(f"missing {release / b}; build first")
        shutil.copy2(release / b, stage_dir / b)
    # Plugin manifests only: the engines themselves are never bundled.
    for d in sorted((ROOT / "plugins").iterdir()):
        if d.is_dir():
            for f in sorted(d.iterdir()):
                if f.is_file():
                    (stage_dir / "plugins" / d.name).mkdir(parents=True, exist_ok=True)
                    shutil.copy2(f, stage_dir / "plugins" / d.name / f.name)
    (stage_dir / "docs").mkdir()
    for name in DOCS:
        shutil.copy2(ROOT / "docs" / name, stage_dir / "docs" / name)
    for name in ("README.md", "README.zh-TW.md", "THIRD_PARTY_NOTICES.md"):
        shutil.copy2(ROOT / name, stage_dir / name)
    run([sys.executable, "-I", str(ROOT / "scripts" / "sbom.py"),
         "--out", str(stage_dir / "omnidecomp.cdx.json"), "--licenses", str(stage_dir / "THIRD_PARTY_LICENSES.md")])
    rustc = run(["rustc", "-V"]).strip()
    files = sorted(p for p in stage_dir.rglob("*") if p.is_file())
    info = {
        "name": "OmniDecomp",
        "version": version,
        "target": triple,
        "rustc": rustc,
        "profile": "release",
        "files": {p.relative_to(stage_dir).as_posix(): sha256(p) for p in files},
    }
    (stage_dir / "VERSION.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8", newline="\n")


def make_zip(stage_dir, zip_path):
    prefix = zip_path.stem
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(q for q in stage_dir.rglob("*") if q.is_file()):
            rel = p.relative_to(stage_dir).as_posix()
            zi = zipfile.ZipInfo(f"{prefix}/{rel}", FIXED_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (0o755 if rel in BINS else 0o644) << 16
            z.writestr(zi, p.read_bytes())


def smoke(zip_path):
    """Unpacks into a clean directory and exercises the packaged binary. Raises on any failure."""
    with tempfile.TemporaryDirectory(prefix="omnidecomp-smoke-") as tmp:
        tmp = Path(tmp)
        with zipfile.ZipFile(zip_path) as z:
            bad = z.testzip()
            assert bad is None, f"corrupt entry {bad}"
            z.extractall(tmp)
            # extractall drops Unix permission bits; `unzip` restores them, so do the same to test what users get.
            for zi in z.infolist():
                mode = (zi.external_attr >> 16) & 0o777
                if mode:
                    (tmp / zi.filename).chmod(mode)
        root = tmp / zip_path.stem
        info = json.loads((root / "VERSION.json").read_text(encoding="utf-8"))
        for rel, digest in info["files"].items():
            assert sha256(root / rel) == digest, f"hash mismatch for {rel}"
        exe = root / BINS[0]
        state = tmp / "state" / "plugins.json"
        common = ["--state-file", str(state)]
        out = subprocess.run([str(exe), "--version"], capture_output=True, text=True, encoding="utf-8", check=True).stdout
        assert info["version"] in out, out
        out = subprocess.run([str(exe), *common, "plugins", "list"], capture_output=True, text=True, encoding="utf-8", check=True).stdout
        for needle in ("format-pe", "ilspycmd", "cfr"):
            assert needle in out, f"plugins list lacks {needle}:\n{out}"
        assert "invalid" not in out.lower(), out
        out = subprocess.run([str(exe), "engines", "list"], capture_output=True, text=True, encoding="utf-8", check=True).stdout
        assert "iced-x86" in out, out
        # A real input: analyse the packaged binary itself (a PE on Windows, ELF on Linux), read-only.
        r = subprocess.run([str(exe), *common, "info", str(exe), "--format", "json"], capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0, r.stderr
        assert json.loads(r.stdout), "info produced no JSON"
        r = subprocess.run([str(exe), *common, "disasm", str(exe), "--max-instructions", "20"], capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 0 and r.stdout.strip(), r.stderr
        # Failure path keeps its documented exit code.
        r = subprocess.run([str(exe), *common, "info", str(tmp / "missing.bin")], capture_output=True, text=True, encoding="utf-8")
        assert r.returncode == 3, (r.returncode, r.stderr)
        # Decompile must refuse without consent even when nothing is enabled.
        r = subprocess.run([str(exe), *common, "decompile", str(exe), "--engine", "ilspycmd"], capture_output=True, text=True, encoding="utf-8")
        assert r.returncode != 0
        assert info["files"].get(BINS[1]), "GUI binary missing from package"
    print("smoke test: ok")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true")
    ap.add_argument("--no-smoke", action="store_true")
    args = ap.parse_args()
    if not args.skip_build:
        subprocess.run(["cargo", "build", "--release", "--locked", "-p", "omnidecomp-cli", "-p", "omnidecomp-gui"], cwd=ROOT, check=True)
    version, triple = workspace_version(), host_triple()
    DIST.mkdir(exist_ok=True)
    zip_path = DIST / f"OmniDecomp-{version}-{triple}.zip"
    with tempfile.TemporaryDirectory(prefix="omnidecomp-stage-") as tmp:
        stage_dir = Path(tmp)
        stage(stage_dir, version, triple)
        make_zip(stage_dir, zip_path)
    digest = sha256(zip_path)
    # One SHA256SUMS for every platform's zip: keep the other entries, replace this one.
    sums = DIST / "SHA256SUMS"
    old = sums.read_text(encoding="utf-8").splitlines() if sums.exists() else []
    keep = [l for l in old if l.strip() and not l.endswith(f"  {zip_path.name}")]
    keep.append(f"{digest}  {zip_path.name}")
    keep.sort(key=lambda l: l.split("  ", 1)[1])
    sums.write_text("\n".join(keep) + "\n", encoding="utf-8", newline="\n")
    print(f"package: {zip_path} ({zip_path.stat().st_size} bytes)\nsha256: {digest}")
    if not args.no_smoke:
        smoke(zip_path)


if __name__ == "__main__":
    main()
