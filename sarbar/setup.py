"""`sarbar setup` — install the scanner binaries sarbar wraps.

Both engines are installed so that they work **two ways at once**:

  * as a standalone command in your shell  -> symlinked into ~/.local/bin
  * under the hood of sarbar               -> resolved by absolute path

Two layouts, both standard Linux:

  --system (or `sudo bash install.sh`)   the proper one
      /usr/bin/trivy, /usr/bin/falco      executables
      /etc/falco/                         falco configuration
      /var/lib/sarbar/                    run history
      needs root, because /usr and /etc do

  without --system                       the fallback
      ~/.sarbar/bin/                      executables
      ~/.sarbar/etc/falco/                falco configuration
      ~/.sarbar/history.db               run history
      needs nothing, but ~/.sarbar/bin must be on PATH

Use --system when you can. The fallback exists so that sarbar is still usable in
an air-gapped container or on a machine where nobody is allowed to install
anything system-wide.

Where the binaries come from
----------------------------
trivy  GitHub releases — a plain .tar.gz with a static binary.
falco  The project's own Debian repository. Falco stopped publishing runnable
       binaries on GitHub: every release from 0.40.0 to 0.45.0 ships only
       `falco-x86_64.debug`, which is a debug symbol blob and cannot execute
       ("exec format error"). The official install script at
       falco.org/script/install is deprecated and now exits 1. The .deb from
       download.falco.org is therefore the only reliable source, and we extract
       the binary and its /etc/falco configuration without installing the
       package system-wide.

Everything is verified with `--version` after download. A file that downloads
but does not execute is deleted and reported as broken, never as installed.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


SYSTEM_BIN = "/usr/bin"
SYSTEM_ETC = "/etc"
SYSTEM_DATA = "/var/lib/sarbar"   # only for a daemon build; unused today


class Layout:
    """Where things live. `system` is the proper Linux layout."""

    def __init__(self, system: bool = False):
        self.system = system
        # resolved at call time, not import time, so HOME changes are honoured
        home = os.path.expanduser("~/.sarbar")
        self.root = "/" if system else home
        self.bin = SYSTEM_BIN if system else os.path.join(home, "bin")
        self.etc = SYSTEM_ETC if system else os.path.join(home, "etc")
        self.data = SYSTEM_DATA if system else home

    @property
    def falco_etc(self) -> str:
        return os.path.join(self.etc, "falco")

    @property
    def local_bin(self) -> str:
        """Fallback layout only: where the PATH symlink goes."""
        return "/usr/local/bin" if self.system else os.path.expanduser("~/.local/bin")

    @property
    def local_share(self) -> str:
        return "/usr/share" if self.system else os.path.join(
            os.path.expanduser("~/.local"), "share")

    @property
    def share(self) -> str:
        """Where falco looks for its plugins.

        Falco loads libcontainer.so from a compiled-in list that starts at
        /usr/local/share/falco/plugins and /usr/share/falco/plugins. Missing
        the plugin produces "Plugin requirement not satisfied, must load one of:
        container", so this is not optional packaging.

        The fallback layout cannot place a plugin where falco looks, so there
        the sarbar plugins directory is passed to falco explicitly via -L.
        """
        return self.local_share

    @property
    def falco_share(self) -> str:
        return os.path.join(self.share, "falco")

    @property
    def falco_plugins(self) -> str:
        return os.path.join(self.falco_share, "plugins")

    @property
    def falcoctl_etc(self) -> str:
        return os.path.join(self.etc, "falcoctl")

    @property
    def history(self) -> str:
        """Run history lives with the user, per XDG_STATE_HOME.

        Installing sarbar as root does not move it to /var/lib: a root install
        shares one history, and separate users would overwrite each other.
        """
        from sarbar.history import db_path
        return db_path()

    def __str__(self) -> str:
        return f"{self.bin} (config {self.falco_etc})"

GITHUB_LATEST = "https://api.github.com/repos/aquasecurity/trivy/releases/latest"
FALCO_PACKAGES = ("https://download.falco.org/packages/deb/dists/stable/main/"
                  "binary-%s/Packages.gz")
FALCO_DEB_BASE = "https://download.falco.org/packages/deb/"

ARCH_ALIASES = {
    "x86_64": ("64bit", "amd64", "x86_64"),
    "aarch64": ("arm64", "aarch64"),
    "i386": ("32bit", "i386", "i686"),
}
SKIP_SUFFIXES = (".debug", ".sha256", ".sbom", ".asc", ".sig", ".json",
                 ".sigstore.json", ".md", ".txt")


# --------------------------------------------------------------------------
# platform
# --------------------------------------------------------------------------

def get_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    if m in ("i386", "i686", "x86"):
        return "i386"
    return "x86_64"


def get_os() -> str:
    return "darwin" if sys.platform == "darwin" else "linux"


def deb_arch() -> str:
    """dpkg architecture name for the Falco repository."""
    a = get_arch()
    return {"x86_64": "amd64", "aarch64": "arm64", "i386": "i386"}[a]


def layout(system: bool = False) -> Layout:
    return Layout(system)


def is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def require_root(action: str) -> bool:
    if is_root():
        return True
    print(f"  ! {action} needs root. Re-run with:  sudo sarbar setup{action and ''}")
    return False


# --------------------------------------------------------------------------
# download helpers
# --------------------------------------------------------------------------

def _get(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "sarbar-setup"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _fetch_json(url: str, timeout: int = 30) -> dict:
    return json.loads(_get(url, timeout).decode())


def _download(url: str, dest: str, timeout: int = 600) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "sarbar-setup"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, \
            open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)
    return dest


def _executable(path: str) -> None:
    mode = os.stat(path).st_mode
    os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def verify_binary(path: str) -> tuple[bool, str]:
    """Run `--version`. A file that cannot execute is not an installation."""
    try:
        p = subprocess.run([path, "--version"], capture_output=True,
                           text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as ex:
        return False, str(ex)
    if p.returncode != 0:
        return False, f"`--version` exited {p.returncode}"
    first = (p.stdout or p.stderr or "").strip().splitlines()
    return True, (first[0].strip() if first else "ok")


def _publish(binary: str, name: str, lay: "Layout") -> tuple[bool, str]:
    """Fallback layout only: link into a PATH directory so it works as a command.

    In the system layout the binary already sits in /usr/bin and needs nothing.
    The target comes from the layout, never from a bare expanduser call, so a test
    can redirect it without touching the real home directory.
    """
    if lay.system:
        return True, binary
    target_dir = lay.local_bin
    try:
        os.makedirs(target_dir, exist_ok=True)
    except OSError as ex:
        return False, f"cannot create {target_dir}: {ex}"
    link = os.path.join(target_dir, name)
    try:
        if os.path.islink(link) or os.path.exists(link):
            os.remove(link)
        os.symlink(binary, link)
    except OSError as ex:
        return False, f"cannot link into {target_dir}: {ex}"
    return True, link


# --------------------------------------------------------------------------
# trivy
# --------------------------------------------------------------------------

def trivy_asset() -> tuple[str, str] | None:
    """(url, version) of the trivy .tar.gz for this platform."""
    try:
        release = _fetch_json(GITHUB_LATEST)
    except Exception:
        return None
    version = str(release.get("tag_name", "")).lstrip("v") or "unknown"
    if get_os() == "darwin":
        os_tokens = ("macOS", "darwin")
    else:
        os_tokens = ("Linux", "linux")
    arch_tokens = ARCH_ALIASES[get_arch()]
    for asset in release.get("assets") or []:
        name = asset.get("name", "")
        low = name.lower()
        if name.endswith(SKIP_SUFFIXES) or not name.endswith(".tar.gz"):
            continue
        if not low.startswith("trivy"):
            continue
        # trivy spells the ARM asset "Linux-ARM64" but the amd64 one
        # "Linux-64bit", so the match has to be case-insensitive.
        if not any(t in low for t in os_tokens):
            continue
        if not any(t in low for t in arch_tokens):
            continue
        return asset["browser_download_url"], version
    return None


def install_trivy(lay: Layout, force: bool = False) -> str:
    _mkdirs(lay.bin)
    dest = os.path.join(lay.bin, "trivy")
    if os.path.exists(dest) and not force:
        good, detail = verify_binary(dest)
        if good:
            linked, where = _publish(dest, "trivy", lay)
            return "already" + ("" if linked else f" (no symlink: {where})")
        print(f"  trivy: {dest} is not runnable ({detail}); replacing")

    found = trivy_asset()
    if not found:
        return "failed: cannot reach the trivy release API"
    url, version = found
    print(f"  trivy: downloading {version} ({url.rsplit('/', 1)[-1]})")
    with tempfile.TemporaryDirectory() as tmp:
        archive = os.path.join(tmp, "trivy.tar.gz")
        try:
            _download(url, archive)
        except Exception as ex:
            return f"failed to download: {ex}"
        try:
            with tarfile.open(archive, "r:*") as tar:
                for member in tar.getmembers():
                    if os.path.basename(member.name) == "trivy" and member.isfile():
                        src = tar.extractfile(member)
                        if src is None:
                            continue
                        with open(dest, "wb") as out:
                            out.write(src.read())
                        _executable(dest)
                        break
                else:
                    return "failed: archive does not contain a 'trivy' binary"
        except (tarfile.TarError, OSError) as ex:
            return f"failed to unpack: {ex}"

    good, detail = verify_binary(dest)
    if not good:
        os.remove(dest)
        return f"broken: downloaded file is not runnable ({detail})"
    linked, where = _publish(dest, "trivy", lay)
    if not linked:
        return f"ok ({detail}) but could not publish: {where}"
    return f"ok: {detail} -> {where}"


# --------------------------------------------------------------------------
# falco
# --------------------------------------------------------------------------

def falco_deb() -> tuple[str, str] | None:
    """(url, version) of the newest Falco .deb that does not need dkms.

    Older entries in the repository declare `dkms` (the kernel-module build);
    those need root and a compiler. The modern releases are self-contained.
    """
    try:
        raw = _get(FALCO_PACKAGES % deb_arch(), timeout=60)
    except Exception:
        return None
    text = gzip.decompress(raw).decode("utf-8", "replace")

    best: tuple | None = None
    best_key: tuple = ()
    for stanza in text.split("\n\n"):
        fields = {}
        for line in stanza.splitlines():
            if line.startswith((" ", "\t")) or ":" not in line:
                continue
            key, _, value = line.partition(":")
            fields[key.strip()] = value.strip()
        if fields.get("Package") != "falco" or not fields.get("Filename"):
            continue
        if "dkms" in fields.get("Depends", ""):
            continue
        version = fields.get("Version", "0")
        key = _version_key(version)
        if key > best_key:
            best_key = key
            best = (FALCO_DEB_BASE + fields["Filename"], version)
    return best


def _version_key(v: str) -> tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.findall(r"\d+", v))


def _extract_deb(deb: str, dest_root: str) -> str | None:
    """Extract a .deb without installing it. Returns the binary path or None."""
    if shutil.which("dpkg-deb"):
        try:
            subprocess.run(["dpkg-deb", "-x", deb, dest_root], check=True,
                           capture_output=True, timeout=300)
            cand = os.path.join(dest_root, "usr", "bin", "falco")
            return cand if os.path.isfile(cand) else None
        except (subprocess.SubprocessError, OSError):
            pass
    # fallback: ar + tar
    if not shutil.which("ar"):
        return None
    with tempfile.TemporaryDirectory() as tmp:
        try:
            subprocess.run(["ar", "x", os.path.abspath(deb)], cwd=tmp, check=True,
                           capture_output=True, timeout=300)
            data = next((os.path.join(tmp, f) for f in os.listdir(tmp)
                         if f.startswith("data.tar")), None)
            if not data:
                return None
            with tarfile.open(data, "r:*") as tar:
                tar.extractall(dest_root)
        except (subprocess.SubprocessError, OSError, tarfile.TarError):
            return None
    cand = os.path.join(dest_root, "usr", "bin", "falco")
    return cand if os.path.isfile(cand) else None


def install_falco(lay: Layout, force: bool = False) -> str:
    _mkdirs(lay.bin)
    _mkdirs(lay.falco_etc)
    _mkdirs(lay.falco_plugins)
    dest = os.path.join(lay.bin, "falco")
    ctl = os.path.join(lay.bin, "falcoctl")
    conf = os.path.join(lay.falco_etc, "falco.yaml")

    # A complete falco is three things, not one: the binary, the driver manager
    # (falcoctl), and the container plugin. Any of them missing means falco
    # either cannot load a driver or cannot see containers, and reports the
    # result as "0 events" rather than as an error. So completeness is checked,
    # not just the presence of the binary.
    if os.path.exists(dest) and not force and _falco_complete(lay):
        good, detail = verify_binary(dest)
        if good:
            linked, where = _publish(dest, "falco", lay)
            return "already" + ("" if linked else f" (no command: {where})")
    elif os.path.exists(dest) and not force:
        print("  falco: installation is incomplete (missing falcoctl or the "
              "container plugin); reinstalling")

    found = falco_deb()
    if not found:
        return ("failed: cannot reach download.falco.org. Falco no longer "
                "ships runnable binaries on GitHub (only .debug since 0.40) "
                "and falco.org/script/install is deprecated.")
    url, version = found
    print(f"  falco: downloading official package {version} "
          f"({url.rsplit('/', 1)[-1]})")

    with tempfile.TemporaryDirectory() as tmp:
        deb = os.path.join(tmp, "falco.deb")
        try:
            _download(url, deb)
        except Exception as ex:
            return f"failed to download: {ex}"
        root = os.path.join(tmp, "root")
        binary = _extract_deb(deb, root)
        if not binary:
            return ("failed: could not extract usr/bin/falco from the package. "
                    "Need dpkg-deb or ar.")
        # The binary needs falco.yaml and the rule files next to it, otherwise
        # it refuses to start ("You must create a config file").
        src_etc = os.path.join(root, "etc", "falco")
        if os.path.isdir(src_etc):
            if os.path.isdir(lay.falco_etc):
                shutil.rmtree(lay.falco_etc)
            _mkdirs(os.path.dirname(lay.falco_etc))
            shutil.copytree(src_etc, lay.falco_etc)
        shutil.copyfile(binary, dest)
        _executable(dest)

        # falcoctl: without it there is no way to install the driver at all.
        src_ctl = os.path.join(root, "usr", "bin", "falcoctl")
        if os.path.isfile(src_ctl):
            shutil.copyfile(src_ctl, ctl)
            _executable(ctl)
        else:
            print("  ! this falco package ships no falcoctl; the driver cannot "
                  "be installed from it")

        # The container plugin. Without it falco exits with "Plugin requirement
        # not satisfied" and can never observe a container.
        src_plugins = os.path.join(root, "usr", "share", "falco", "plugins")
        if os.path.isdir(src_plugins):
            if os.path.isdir(lay.falco_plugins):
                shutil.rmtree(lay.falco_plugins)
            _mkdirs(os.path.dirname(lay.falco_plugins))
            shutil.copytree(src_plugins, lay.falco_plugins)
        else:
            print("  ! this falco package ships no plugins; falco will not be "
                  "able to watch containers")

        src_ctl_etc = os.path.join(root, "etc", "falcoctl")
        if os.path.isdir(src_ctl_etc) and lay.system:
            _mkdirs(lay.falcoctl_etc)
            for name in os.listdir(src_ctl_etc):
                shutil.copyfile(os.path.join(src_ctl_etc, name),
                                os.path.join(lay.falcoctl_etc, name))

    good, detail = verify_binary(dest)
    if not good:
        os.remove(dest)
        return f"broken: downloaded file is not runnable ({detail})"
    rules = os.path.join(lay.falco_etc, "falco_rules.yaml")
    if not os.path.isfile(conf) or not os.path.isfile(rules):
        return (f"ok ({detail}) but the falco config is incomplete, so `falco` "
                f"will still ask for /etc/falco/falco.yaml")
    missing = _falco_missing(lay)
    linked, where = _publish(dest, "falco", lay)
    # falcoctl is published as a command too: it is how a user loads or unloads
    # the driver, so hiding it in ~/.sarbar/bin would leave the only supported way
    # to manage the driver looking like a missing file.
    ctl_linked, _ = _publish(ctl, "falcoctl", lay)
    if not linked:
        return f"ok ({detail}) but could not publish: {where}"
    if not ctl_linked:
        return (f"ok ({detail}) but could not publish falcoctl; "
                f"`sarbar setup --driver` still works, it finds it in place")
    if missing:
        return (f"partial: {detail} -> {where}, but missing {', '.join(missing)}. "
                f"falco cannot fully watch containers without them")
    return f"ok: {detail} -> {where}"


def falco_plugin_files(lay: "Layout") -> list:
    """Plugin shared objects falco can actually load from this layout."""
    if not os.path.isdir(lay.falco_plugins):
        return []
    return sorted(f for f in os.listdir(lay.falco_plugins)
                  if f.endswith(".so")
                  and os.path.isfile(os.path.join(lay.falco_plugins, f)))


def _falco_missing(lay: "Layout") -> list:
    """What a working falco needs and this install does not have.

    Three separate things, and each missing one degrades silently: falcoctl
    means no driver can be installed, and a missing plugin means falco cannot
    follow containers — in both cases it reports "0 events" rather than an error.
    """
    out = []
    if not os.path.isfile(os.path.join(lay.bin, "falcoctl")):
        out.append("falcoctl (no way to install the driver)")
    if not falco_plugin_files(lay):
        out.append(f"a container plugin in {lay.falco_plugins}")
    return out


def _falco_complete(lay: "Layout") -> bool:
    return not _falco_missing(lay)


# --------------------------------------------------------------------------
# status
# --------------------------------------------------------------------------

def engine_status(name: str) -> tuple[str, str]:
    """(state, detail) for one scanner binary."""
    from sarbar.engines import resolve
    path = resolve(name)
    if not path:
        return "absent", "not installed"
    good, detail = verify_binary(path)
    if not good:
        return "broken", f"{path} does not run: {detail}"
    system = path.startswith("/usr/bin/") or path.startswith("/usr/local/bin/")
    where = "system-wide" if system else "per-user"
    return "ready", f"{path} — {detail} ({where})"


def falcoctl_path(lay: "Layout | None" = None) -> str | None:
    """Locate falcoctl: PATH first, then the layout we installed it into.

    PATH alone is not enough: a root install puts falcoctl in /usr/bin, which an
    unprivileged caller's PATH already covers, but a per-user install needs the
    fallback layout and the install may not have re-exported anything.
    """
    found = shutil.which("falcoctl")
    if found:
        return found
    for base in (lay.bin if lay else Layout(system=True).bin,
                 Layout(system=False).bin):
        cand = os.path.join(base, "falcoctl")
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def falco_driver_state(lay: "Layout | None" = None) -> tuple[bool, str]:
    """What can be said about falco's ability to see kernel events.

    Deliberately honest about the limits. falcoctl being installed says nothing
    about whether the driver is loaded; the truth is established per scan by
    running falco and reading what it reports. What we CAN check here is whether
    the pieces that make a scan possible are installed at all, because their
    absence is what caused the silent "0 events" failure.
    """
    ctl = falcoctl_path(lay)
    if not ctl:
        return False, ("falcoctl is not installed, so the driver cannot be "
                       "installed and falco cannot see anything")
    lay = lay or Layout(system=is_root())
    missing = _falco_missing(lay)
    if missing:
        return False, "falco is installed but incomplete, missing " + ", ".join(missing)
    return True, ("falcoctl present and the container plugin is in place; "
                  "whether the driver is loaded is reported per scan")


def install_falco_driver(lay: "Layout | None" = None) -> tuple[bool, str]:
    """Install the falco event driver. Needs root, hence it lives in setup."""
    if not is_root():
        return False, "needs root — run: sudo sarbar setup --driver"
    lay = lay or Layout(system=True)
    ctl = falcoctl_path(lay)
    if not ctl:
        return False, ("falcoctl is missing — run `sarbar setup` first so the "
                       "driver manager gets installed too")
    missing = _falco_missing(lay)
    if missing:
        return False, "install is incomplete: missing " + ", ".join(missing)

    print("  loading the falco eBPF driver "
          "(this loads a kernel program, it does not compile one)")
    try:
        done = subprocess.run([ctl, "container", "install"], timeout=900)
    except (OSError, subprocess.SubprocessError) as ex:
        return False, f"falcoctl could not run: {ex}"
    if done.returncode != 0:
        return False, (f"falcoctl container install exited {done.returncode}. "
                       f"The most usual cause on a live desktop is a locked or "
                       f"restricted kernel (signed modules only, or eBPF "
                       f"disabled). Nothing sarbar installs can change that.")
    return True, "driver installed"


def remove_falco_driver(lay: "Layout | None" = None) -> tuple[bool, str]:
    """Unload the driver. Needs root because a kernel driver does."""
    if not is_root():
        return False, "needs root — run: sudo sarbar setup --uninstall-driver"
    ctl = falcoctl_path(lay)
    if not ctl:
        return False, "falcoctl is not installed"
    try:
        done = subprocess.run([ctl, "container", "uninstall"], timeout=300)
    except (OSError, subprocess.SubprocessError) as ex:
        return False, f"falcoctl could not run: {ex}"
    if done.returncode != 0:
        return False, f"falcoctl container uninstall exited {done.returncode}"
    return True, "driver removed"


def _mkdirs(path: str) -> None:
    try:
        os.makedirs(path, exist_ok=True)
    except OSError as ex:
        print(f"  ! cannot create {path}: {ex}")


def run_setup(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sarbar setup",
        description="Install the scanners sarbar wraps (trivy, falco) and, "
                    "optionally, the falco event driver.")
    parser.add_argument("--system", action="store_true",
                        help="install system-wide into /usr/bin and /etc "
                             "(needs root). This is the proper Linux layout")
    parser.add_argument("--driver", action="store_true",
                        help="install the falco eBPF driver (needs root). "
                             "Only needed once, and only for runtime detection")
    parser.add_argument("--no-driver", action="store_true",
                        help="do not install the driver even when running as "
                             "root. Root installs do it by default")
    parser.add_argument("--uninstall-driver", action="store_true",
                        help="unload the falco driver again (needs root)")
    parser.add_argument("--force", action="store_true",
                        help="reinstall even if a working binary is present")
    parser.add_argument("--only", choices=["trivy", "falco"],
                        help="install just one scanner")
    parser.add_argument("--check", action="store_true",
                        help="only report the current state, install nothing")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    root = is_root()
    lay = Layout(system=args.system or root)

    if args.check:
        print(f"{'scanner':<9} {'state':<8} detail")
        for name in ("trivy", "falco"):
            state, detail = engine_status(name)
            print(f"{name:<9} {state:<8} {detail}")
        ok, detail = falco_driver_state(lay)
        # "installed", not "ready": whether the driver is actually loaded can only
        # be proven by running falco, and overstating it here would be the same
        # sin as a green light for a scanner that never ran.
        print(f"{'falco drv':<9} {'installed' if ok else 'absent':<8} {detail}")
        plugins = falco_plugin_files(lay)
        print(f"{'plugin':<9} {'installed' if plugins else 'absent':<8} "
              f"{', '.join(plugins) if plugins else 'no container plugin, falco cannot watch containers'}")
        print(f"{'docker':<9} {'ready' if _docker_ok() else 'absent':<8} "
              f"{'usable' if _docker_ok() else 'daemon not usable by this user'}")
        print(f"\nlayout:  {lay}")
        print(f"history:  {lay.history}")
        return 0

    if args.uninstall_driver:
        print("=" * 68)
        print(" sarbar setup — remove the falco event driver")
        print("=" * 68)
        ok, detail = remove_falco_driver(lay)
        print(f"  -> {'ok' if ok else 'not removed'}: {detail}")
        return 0 if ok else 1

    if args.driver:
        print("=" * 68)
        print(" sarbar setup — falco event driver")
        print("=" * 68)
        ok, detail = install_falco_driver(lay)
        print(f"  -> {'ok' if ok else 'not installed'}: {detail}")
        return 0 if ok else 1

    if args.system and not root:
        print("  ! --system writes to /usr/bin and /etc, which needs root.")
        print("    Re-run as:  sudo sarbar setup --system")
        return 1

    print("=" * 68)
    print(f" sarbar setup — layout: {lay}")
    print("=" * 68)

    results = {}
    if args.only != "falco":
        print("\n[1/2] trivy   (vulnerabilities, Dockerfile lint, secrets)")
        results["trivy"] = install_trivy(lay, force=args.force)
        print(f"  -> {results['trivy']}")
    if args.only != "trivy":
        print("\n[2/2] falco    (runtime behaviour from kernel events)")
        results["falco"] = install_falco(lay, force=args.force)
        print(f"  -> {results['falco']}")

    # Root installs finish the job. A half-installed falco looks working and is
    # worse than an absent one, because it reports "0 events" instead of an error.
    driver: tuple[bool, str] | None = None
    if root and not args.no_driver and args.only != "trivy":
        print("\n[3/3] falco driver  (so falco can see what containers do)")
        driver = install_falco_driver(lay)
        print(f"  -> {'ok' if driver[0] else 'not installed'}: {driver[1]}")
    elif not root and args.only != "trivy":
        print("\n[3/3] falco driver  skipped: needs root. Run it once with:")
        print("      sudo sarbar setup --driver")

    print("\n" + "-" * 68)
    print(" state:")
    for name in ("trivy", "falco"):
        state, detail = engine_status(name)
        print(f"   {name:<7} {state:<8} {detail}")
    ok, detail = falco_driver_state(lay)
    print(f"   driver   {'installed' if ok else 'absent':<8} {detail}")
    ok, detail = _docker_ok(), "daemon usable" if _docker_ok() else "daemon not usable"
    print(f"   docker   {'ready' if ok else 'absent':<8} {detail}")
    print("-" * 68)
    print(f" history: {lay.history}")

    if _docker_ok():
        print("""
 Docker is usable by this account, so `sarbar scan <running-container>` works
 end to end. If it is not, the account needs to be in the docker group:

    sudo usermod -aG docker $USER     # then log out and back in""")
    else:
        print("""
 Docker is NOT usable by this account, so running containers cannot be
 inspected yet. `sarbar scan <image>` and `sarbar scan .` work regardless. To
 enable container targets:

    sudo usermod -aG docker $USER     # then log out and back in""")

    print("""
 Checking a running container needs falco, which reads kernel events and so
 needs root. sarbar asks for your sudo password at that moment and reuses it
 for the rest of the session. To never be asked:

    sudo setcap cap_sys_admin,cap_perfmon,cap_sys_ptrace,cap_sys_resource+ep \
        /usr/bin/falco""")
    print("=" * 68)
    print(" Done. Verify with:   sarbar setup --check")
    print("=" * 68)
    return 0 if (driver is None or driver[0]) else 1


def _docker_ok() -> bool:
    from sarbar.orchestrator import docker_available
    return docker_available()


if __name__ == "__main__":
    raise SystemExit(run_setup())
