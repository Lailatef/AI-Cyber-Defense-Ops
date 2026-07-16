"""Download the latest Hayabusa release for the current platform and extract it to ./hayabusa/.

Usage:
    python scripts/download_hayabusa.py [--dest DIR] [--repo OWNER/REPO]

Only uses the standard library so it works before any project dependencies
(requirements.txt) are installed.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import stat
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile

DEFAULT_REPO = "Yamato-Security/hayabusa"
DEFAULT_DEST = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hayabusa")

# Substrings excluded from matching so we don't pick a "live-response" bundle
# or the "all-platforms" source archive instead of a plain single-binary release.
EXCLUDED_ASSET_MARKERS = ("live-response", "all-platforms")


def detect_os_tag() -> str:
    system = platform.system()
    if system == "Windows":
        return "win"
    if system == "Linux":
        return "lin"
    if system == "Darwin":
        return "mac"
    raise RuntimeError(f"Unsupported OS: {system}")


def detect_arch_tag() -> str:
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        return "x64"
    if machine in ("arm64", "aarch64"):
        return "aarch64"
    if machine in ("x86", "i386", "i686"):
        return "x86"
    raise RuntimeError(f"Unsupported architecture: {machine}")


def fetch_latest_release(repo: str) -> dict:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            # GitHub's API rejects requests with no User-Agent header.
            "User-Agent": "mcp-hayabusa-downloader",
        },
    )
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response)
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Failed to reach GitHub API at {url}: {exc}") from exc


def pick_asset(assets: list[dict], os_tag: str, arch_tag: str) -> dict:
    marker = f"-{os_tag}-{arch_tag}"
    candidates = [
        asset
        for asset in assets
        if marker in asset["name"]
        and not any(excluded in asset["name"] for excluded in EXCLUDED_ASSET_MARKERS)
    ]
    if not candidates:
        available = ", ".join(a["name"] for a in assets)
        raise RuntimeError(
            f"No release asset found matching '{marker}'. Available assets: {available}"
        )
    if len(candidates) > 1:
        # Linux releases ship both -gnu and -musl builds; prefer glibc (gnu).
        gnu_candidates = [a for a in candidates if "gnu" in a["name"]]
        if gnu_candidates:
            return gnu_candidates[0]
    return candidates[0]


def download_asset(asset: dict, tmp_path: str) -> None:
    request = urllib.request.Request(
        asset["browser_download_url"],
        headers={"User-Agent": "mcp-hayabusa-downloader"},
    )
    with urllib.request.urlopen(request) as response, open(tmp_path, "wb") as tmp_file:
        tmp_file.write(response.read())


def extract_zip(zip_path: str, dest_dir: str) -> None:
    os.makedirs(dest_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path) as archive:
        archive.extractall(dest_dir)

    # zip archives don't preserve the executable bit; restore it on POSIX
    # systems for the extracted hayabusa binary.
    if os.name == "posix":
        for root, _dirs, files in os.walk(dest_dir):
            for name in files:
                if name == "hayabusa" or name.startswith("hayabusa-"):
                    path = os.path.join(root, name)
                    mode = os.stat(path).st_mode
                    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=DEFAULT_DEST, help="Directory to extract Hayabusa into")
    parser.add_argument("--repo", default=DEFAULT_REPO, help="GitHub repo to fetch releases from")
    args = parser.parse_args()

    try:
        os_tag = detect_os_tag()
        arch_tag = detect_arch_tag()
        print(f"Detected platform: {os_tag}-{arch_tag}")

        release = fetch_latest_release(args.repo)
        version = release.get("tag_name", "unknown")
        print(f"Latest release: {version}")

        asset = pick_asset(release["assets"], os_tag, arch_tag)
        print(f"Selected asset: {asset['name']} ({asset['size']} bytes)")

        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            print("Downloading...")
            download_asset(asset, tmp_path)
            print(f"Extracting to {args.dest} ...")
            extract_zip(tmp_path, args.dest)
        finally:
            os.remove(tmp_path)

        print(f"Done. Hayabusa {version} extracted to {args.dest}")
        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
