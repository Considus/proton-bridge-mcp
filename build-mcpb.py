#!/usr/bin/env python3
"""Build the MCPB bundle.

An MCPB bundle is what the MCP Registry and the Connectors Directory can
actually list. Clone-and-run is fine for developers and is not a package type,
so without this the server is locked out of both.

    ./build-mcpb.py --check     verify the manifest agrees with the server
    ./build-mcpb.py             build dist/proton-bridge-mcp-<version>.mcpb

The tool list and the version live in server.py. This script copies them into
manifest.json and refuses to build if the two have drifted, so the file a
reviewer reads cannot quietly stop describing the server they are reviewing.

Releasing, and the order matters. Build once, upload the artifact that build
produced, then publish server.json from the same run. The archive carries
timestamps so the build is not reproducible, and a second build of identical
sources hashes differently. A rebuild after stamping leaves server.json
pointing at a hash no published file has, which clients read as a corrupted
download rather than as a mistake in the listing.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST = os.path.join(HERE, "manifest.json")
REGISTRY = os.path.join(HERE, "server.json")
DIST = os.path.join(HERE, "dist")
MCPB_CLI = ["npx", "-y", "@anthropic-ai/mcpb@2.1.2"]

# What travels in the bundle. setup.py is deliberately absent: a bundle install
# is configured through the manifest's user_config, and a copy of setup.py
# inside a directory the installer replaces on update would only mislead.
INCLUDE = ["manifest.json", "server.py", "README.md", "LICENSE", "NOTICE"]
INCLUDE_DIRS = [os.path.join("assets", "considus-icon.png")]

# pypdf is the one optional dependency worth carrying: without it, reading the
# text of a PDF invoice silently stops working. keyring is not bundled, because
# a bundle install gets its password from user_config instead.
VENDOR = ["pypdf"]


def _server():
    """Import server.py without requiring it to be configured."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_proton_server", os.path.join(HERE, "server.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _expected(mod):
    return ([{"name": d["name"], "description": d["description"]}
             for d in mod.TOOL_DEFS], mod.SERVER_VERSION)


def check(fix=False):
    """True if manifest.json agrees with server.py."""
    mod = _server()
    tools, version = _expected(mod)
    with open(MANIFEST, encoding="utf-8") as f:
        man = json.load(f)

    problems = []
    if man.get("tools") != tools:
        problems.append("tools: manifest lists %d, server exposes %d"
                        % (len(man.get("tools") or []), len(tools)))
    if man.get("version") != version:
        problems.append("version: manifest %s, server %s"
                        % (man.get("version"), version))

    if problems and fix:
        man["tools"] = tools
        man["version"] = version
        with open(MANIFEST, "w", encoding="utf-8") as f:
            json.dump(man, f, indent=2, ensure_ascii=False)
            f.write("\n")
        print("manifest.json updated from server.py")
        return True

    for p in problems:
        print("drift: " + p, file=sys.stderr)
    return not problems


def _vendor(libdir):
    if not VENDOR:
        return
    os.makedirs(libdir, exist_ok=True)
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet",
                    "--target", libdir] + VENDOR, check=True)
    # pip leaves metadata that only inflates the bundle, so most of it goes.
    # The licences do not. pypdf is BSD-3-Clause, which requires its copyright
    # notice travel with any redistribution, and this bundle is a
    # redistribution. Deleting .dist-info wholesale took the notice with it,
    # so the licence files are lifted out first and kept beside the package.
    for entry in sorted(os.listdir(libdir)):
        path = os.path.join(libdir, entry)
        if entry.endswith((".dist-info", ".egg-info")):
            _keep_licences(path, libdir, entry.split("-")[0])
            shutil.rmtree(path, ignore_errors=True)
        elif entry == "__pycache__":
            shutil.rmtree(path, ignore_errors=True)

    kept = sorted(f for f in os.listdir(libdir) if f.endswith(".LICENSE"))
    if len(kept) < len(VENDOR):
        raise SystemExit(
            "Refusing to build: found %d licence file(s) for %d vendored "
            "package(s) in %s. Shipping a dependency without its licence is a "
            "redistribution problem, not a tidiness one." %
            (len(kept), len(VENDOR), libdir))
    print("  vendored licences  " + ", ".join(kept))


# Where the packaging tools of the last few years have put licence text inside
# .dist-info. Newer pip uses the licenses/ subdirectory, older versions put the
# file at the top level, and the name varies by project.
_LICENCE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE", "AUTHORS")


def _keep_licences(distinfo, libdir, pkg):
    """Copy a package's licence files out of .dist-info before it is deleted."""
    found = []
    for root, _dirs, files in os.walk(distinfo):
        for name in sorted(files):
            stem = os.path.splitext(name)[0].upper()
            if stem.startswith(_LICENCE_NAMES):
                found.append(os.path.join(root, name))
    if not found:
        return
    # One file per package, concatenated when a project ships several, so the
    # bundle carries a single obvious <package>.LICENSE.
    out = os.path.join(libdir, "%s.LICENSE" % pkg)
    with open(out, "w", encoding="utf-8") as dest:
        for i, src in enumerate(found):
            if i:
                dest.write("\n\n" + "-" * 70 + "\n\n")
            dest.write("%s\n\n" % os.path.basename(src))
            with open(src, encoding="utf-8", errors="replace") as f:
                dest.write(f.read())


def build():
    if not check():
        print("\nRun ./build-mcpb.py --sync to copy server.py's tool list and "
              "version into manifest.json.", file=sys.stderr)
        return 1

    with open(MANIFEST, encoding="utf-8") as f:
        version = json.load(f)["version"]

    stage = tempfile.mkdtemp(prefix="mcpb-")
    try:
        for rel in INCLUDE:
            shutil.copy2(os.path.join(HERE, rel), os.path.join(stage, rel))
        for rel in INCLUDE_DIRS:
            dest = os.path.join(stage, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(os.path.join(HERE, rel), dest)
        _vendor(os.path.join(stage, "lib"))

        os.makedirs(DIST, exist_ok=True)
        out = os.path.join(DIST, "proton-bridge-mcp-%s.mcpb" % version)
        subprocess.run(MCPB_CLI + ["pack", stage, out], check=True)
    finally:
        shutil.rmtree(stage, ignore_errors=True)

    with open(out, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    size = os.path.getsize(out)

    _stamp_registry(version, os.path.basename(out), digest)

    print("\n%s" % out)
    print("  size        %.1f KB" % (size / 1024.0))
    print("  fileSha256  %s" % digest)
    print("\nserver.json now carries that hash. Clients check it before they")
    print("install, so the release asset has to be this exact file.")
    print("\nThe build is not reproducible, the archive carries timestamps, so")
    print("a rebuild produces a different hash from identical sources. Upload")
    print("the file above, do not rebuild between stamping and uploading, and")
    print("publish server.json from the same build that made the artifact.")
    return 0


def _stamp_registry(version, filename, digest):
    """Put the hash of the file we just built into server.json.

    Doing this by hand is how a registry entry ends up pointing at a hash that
    was true one build ago, and a client that validates the hash then refuses
    to install with nothing to say about why."""
    with open(REGISTRY, encoding="utf-8") as f:
        reg = json.load(f)
    reg["version"] = version
    pkg = reg["packages"][0]
    pkg["identifier"] = (
        "https://github.com/Considus/proton-bridge-mcp/releases/download/v%s/%s"
        % (version, filename))
    pkg["fileSha256"] = digest
    with open(REGISTRY, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--check":
        sys.exit(0 if check() else 1)
    if arg == "--sync":
        sys.exit(0 if check(fix=True) else 1)
    sys.exit(build())
