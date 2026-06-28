"""Cross-platform host helpers.

PromptShield runs on WSL2, native Linux, macOS, and native Windows. A handful of
actions are OS-specific: opening a file/URL in the user's browser (used by the
DLP block fallback) and, for the ``promptshield`` CLI doctor, installing the
mitmproxy CA cert into the OS trust store.

Everything here is **best-effort and fails-open**: on any error a helper logs and
returns a falsy/empty result rather than raising, so neither the proxy addon nor
the CLI ever crashes because of a platform quirk.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger("promptshield")

# detect_platform() return values.
WSL = "wsl"
MACOS = "macos"
LINUX = "linux"
WINDOWS = "windows"

_DEVNULL = subprocess.DEVNULL


def detect_platform() -> str:
    """Return one of ``wsl`` / ``macos`` / ``linux`` / ``windows``.

    WSL is reported separately from plain Linux because its browser, trust
    store, and proxy all live on the Windows side and need Windows interop
    (``cmd.exe`` / ``certutil.exe``) rather than the native Linux tooling.
    """
    if sys.platform == "darwin":
        return MACOS
    if sys.platform.startswith("win"):
        return WINDOWS
    if sys.platform.startswith("linux"):
        try:
            with open("/proc/version", encoding="utf-8") as f:
                if "microsoft" in f.read().lower():
                    return WSL
        except OSError:
            pass
        return LINUX
    return sys.platform


def _wslpath_to_windows(path: str) -> str:
    """Convert a Linux path to its Windows form for WSL interop (``\\\\wsl.localhost``)."""
    return (
        subprocess.check_output(["wslpath", "-w", path], stderr=_DEVNULL)
        .decode()
        .strip()
    )


def open_path(target: str) -> bool:
    """Open a local file path or URL in the user's default browser/app.

    Cross-platform replacement for the old WSL2-only ``cmd.exe start`` hack.
    Returns ``True`` if the open command was launched, ``False`` on any error
    (the caller treats this as "couldn't show it" and carries on).
    """
    plat = detect_platform()
    try:
        if plat == WSL:
            # Local files must be handed to the Windows browser as a Windows path;
            # URLs (http://, file://) pass through untouched.
            win_target = target
            if os.path.exists(target):
                win_target = _wslpath_to_windows(target)
            subprocess.Popen(
                ["cmd.exe", "/c", "start", "", win_target],
                stdout=_DEVNULL,
                stderr=_DEVNULL,
            )
        elif plat == MACOS:
            subprocess.Popen(["open", target], stdout=_DEVNULL, stderr=_DEVNULL)
        elif plat == WINDOWS:
            os.startfile(target)  # type: ignore[attr-defined]  # Windows-only
        else:  # native Linux
            subprocess.Popen(["xdg-open", target], stdout=_DEVNULL, stderr=_DEVNULL)
        return True
    except Exception as exc:  # fail-open: never propagate to the proxy/CLI
        log.warning("could not open %r in browser: %s", target, exc)
        return False


# --- CA-cert trust install (used by the `promptshield` CLI doctor) ------------
#
# These shell out to the platform's trust-store tool and need admin/sudo. They
# return (ok, message); the CLI prints the message and a manual fallback either
# way, so a failed automated install is never fatal — the user can always fall
# back to mitmproxy's http://mitm.it page.

def _run(cmd: list[str]) -> tuple[bool, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
        out = (proc.stdout + proc.stderr).strip()
        return proc.returncode == 0, out
    except FileNotFoundError:
        return False, f"command not found: {cmd[0]}"
    except Exception as exc:  # noqa: BLE001 - best-effort
        return False, str(exc)


def install_ca_cert(pem_path: str) -> tuple[bool, str]:
    """Best-effort install of the mitmproxy CA cert into the OS trust store.

    ``pem_path`` is mitmproxy's ``~/.mitmproxy/mitmproxy-ca-cert.pem``. Needs
    elevated privileges, so it usually prompts for a password (or fails, in
    which case the CLI prints manual steps). Browsers using their own NSS store
    (Firefox, Chrome on Linux) may still need ``certutil`` — noted by the CLI.
    """
    plat = detect_platform()
    if not os.path.exists(pem_path):
        return False, f"cert not found at {pem_path} (run `promptshield cert` first)"

    if plat == MACOS:
        return _run([
            "sudo", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
            "-k", "/Library/Keychains/System.keychain", pem_path,
        ])
    if plat == LINUX:
        # update-ca-certificates only picks up *.crt under the local CA dir.
        dest = "/usr/local/share/ca-certificates/mitmproxy.crt"
        ok, msg = _run(["sudo", "cp", pem_path, dest])
        if not ok:
            return ok, msg
        return _run(["sudo", "update-ca-certificates"])
    if plat in (WINDOWS, WSL):
        # The browser is on Windows in both cases, so install into the Windows
        # root store via certutil.exe. On WSL the .pem is reachable from Windows
        # through its UNC path.
        cert = pem_path
        if plat == WSL:
            try:
                cert = _wslpath_to_windows(pem_path)
            except Exception as exc:  # noqa: BLE001
                return False, f"wslpath failed: {exc}"
        certutil = "certutil.exe" if plat == WSL else "certutil"
        return _run([certutil, "-addstore", "-f", "root", cert])

    return False, f"unsupported platform: {plat}"


def proxy_instructions(host: str = "127.0.0.1", port: int = 8080) -> str:
    """Return copy-paste manual proxy-configuration steps for the current OS.

    System-proxy mutation is intentionally left manual (it is invasive and
    network-service-name dependent); the doctor prints these instead.
    """
    plat = detect_platform()
    if plat == MACOS:
        return (
            f"macOS: System Settings → Network → (your service) → Details → Proxies,\n"
            f"  enable 'Web Proxy (HTTP)' and 'Secure Web Proxy (HTTPS)' = {host}:{port}.\n"
            f"  Or: networksetup -setwebproxy 'Wi-Fi' {host} {port}"
        )
    if plat in (WINDOWS, WSL):
        return (
            f"Windows: Settings → Network & Internet → Proxy → Manual proxy setup,\n"
            f"  set Address {host} Port {port}. (On WSL the proxy runs inside WSL; "
            f"point the Windows browser at it.)"
        )
    return (
        f"Linux: set the proxy in your browser, or export\n"
        f"  http_proxy=http://{host}:{port} https_proxy=http://{host}:{port}\n"
        f"  (GNOME: gsettings set org.gnome.system.proxy mode 'manual', then the "
        f"http/https host+port keys)."
    )
