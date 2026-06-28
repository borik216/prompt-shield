"""PromptShield command-line entry point.

One ``promptshield`` command replaces the scattered ``.venv/bin/mitmdump -s ...``
and ``uvicorn ...`` invocations and bundles the one-time onboarding (cert mint +
trust install + proxy guidance) behind a single ``setup`` subcommand.

    promptshield run         # start the detector proxy (writes detected.jsonl)
    promptshield record      # start the raw recorder (writes recorded.json)
    promptshield dashboard   # start the FastAPI dashboard
    promptshield cert        # mint + install the mitmproxy CA cert
    promptshield setup       # full onboarding doctor (deps, cert, proxy steps)

Everything is best-effort and never hard-fails on a privileged step: the doctor
prints copy-paste manual fallbacks (and points at http://mitm.it) when an
automated install needs admin/sudo.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time

import detector  # to locate the addon files inside the installed package

_REPO = os.path.dirname(os.path.abspath(__file__))
_DETECTOR_DIR = os.path.dirname(os.path.abspath(detector.__file__))
_DETECTOR_ADDON = os.path.join(_DETECTOR_DIR, "addon.py")
_RECORDER_ADDON = os.path.join(_REPO, "recorder", "addon.py")

# mitmproxy writes its CA material here on first run.
_MITM_CONFDIR = os.path.expanduser("~/.mitmproxy")
_CA_PEM = os.path.join(_MITM_CONFDIR, "mitmproxy-ca-cert.pem")


def _bin(name: str) -> str:
    """Locate a console script (mitmdump/uvicorn), preferring the active venv."""
    found = shutil.which(name)
    if found:
        return found
    candidate = os.path.join(os.path.dirname(sys.executable), name)
    return candidate if os.path.exists(candidate) else name


# --- subcommands --------------------------------------------------------------

def cmd_run(args: argparse.Namespace) -> int:
    """Run the detector addon under mitmdump (passes through extra mitm args)."""
    cmd = [_bin("mitmdump"), "-s", _DETECTOR_ADDON, *args.extra]
    return subprocess.call(cmd)


def cmd_record(args: argparse.Namespace) -> int:
    cmd = [_bin("mitmdump"), "-s", _RECORDER_ADDON, *args.extra]
    return subprocess.call(cmd)


def cmd_dashboard(args: argparse.Namespace) -> int:
    cmd = [_bin("uvicorn"), "dashboard.main:app", "--port", str(args.port)]
    if args.reload:
        cmd.append("--reload")
    return subprocess.call(cmd, cwd=_REPO)


def ensure_cert() -> bool:
    """Make sure mitmproxy's CA cert exists, minting it if needed.

    mitmproxy generates the cert on first startup, so when it's missing we start
    mitmdump just long enough for the file to appear, then stop it.
    """
    if os.path.exists(_CA_PEM):
        return True
    print("Minting mitmproxy CA cert (one-time)...")
    proc = subprocess.Popen(
        [_bin("mitmdump"), "-q", "--listen-port", "0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):  # ~5s
            if os.path.exists(_CA_PEM):
                break
            time.sleep(0.1)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    ok = os.path.exists(_CA_PEM)
    print(("  cert ready: " + _CA_PEM) if ok else "  could not mint cert automatically")
    return ok


def cmd_cert(args: argparse.Namespace) -> int:
    # Imported here so `promptshield run` doesn't pay the import on the hot path.
    from detector.platform_utils import install_ca_cert

    if not ensure_cert():
        print("Open http://mitm.it while the proxy runs to install the cert manually.")
        return 1
    ok, msg = install_ca_cert(_CA_PEM)
    if ok:
        print("Installed the PromptShield CA cert into the system trust store.")
    else:
        print(f"Automated cert install did not complete: {msg}")
        print("Manual fallback: start the proxy, then visit http://mitm.it to install the cert.")
        print(f"  (cert file: {_CA_PEM})")
    return 0 if ok else 1


def cmd_setup(args: argparse.Namespace) -> int:
    """Onboarding doctor: cert + trust install + proxy guidance, all best-effort."""
    from detector.platform_utils import detect_platform, proxy_instructions

    plat = detect_platform()
    print(f"PromptShield setup — detected platform: {plat}\n")

    print("1) Certificate")
    cmd_cert(args)

    print("\n2) Proxy")
    print(proxy_instructions())
    print("\n   Tip: while the proxy is running you can always install the cert from")
    print("   http://mitm.it (works on every OS and browser).")

    print("\n3) Run it")
    print("   promptshield run          # start the detector proxy on :8080")
    print("   promptshield dashboard    # view detections at http://127.0.0.1:8000")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="promptshield", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="start the detector proxy (detected.jsonl)")
    run.add_argument("extra", nargs=argparse.REMAINDER, help="extra args passed to mitmdump")
    run.set_defaults(func=cmd_run)

    rec = sub.add_parser("record", help="start the raw recorder (recorded.json)")
    rec.add_argument("extra", nargs=argparse.REMAINDER, help="extra args passed to mitmdump")
    rec.set_defaults(func=cmd_record)

    dash = sub.add_parser("dashboard", help="start the FastAPI dashboard")
    dash.add_argument("--port", type=int, default=8000)
    dash.add_argument("--reload", action="store_true")
    dash.set_defaults(func=cmd_dashboard)

    cert = sub.add_parser("cert", help="mint + install the mitmproxy CA cert")
    cert.set_defaults(func=cmd_cert)

    setup = sub.add_parser("setup", help="onboarding doctor (cert + proxy steps)")
    setup.set_defaults(func=cmd_setup)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
