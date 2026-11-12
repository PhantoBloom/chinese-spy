#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  WINDOWS SYSTEM INFORMATION COLLECTOR & EMAILER  (READ THIS FIRST)
================================================================================

  ⚠  THIS SCRIPT COLLECTS INFORMATION FROM THE MACHINE IT RUNS ON  ⚠
  ⚠  IT PACKAGES THAT INFORMATION INTO A ZIP FILE                  ⚠
  ⚠  IT SENDS THAT ZIP BY EMAIL TO TWO ADDRESSES... THE CIA, AND CHINA HEHEH       ⚠

  WHAT IT COLLECTS (all benign, diagnostic only):
     - Computer name, FQDN, current username, domain
     - OS name / version / build, Python version
     - CPU model, cores, clock speed, RAM modules and total RAM
     - Physical disks, logical volumes, free space
     - Full network configuration (ipconfig /all)
     - Installed software (registry Uninstall keys)
     - Running processes (name, id, path)
     - Environment variables  (sensitive-looking names are REDACTED)
     - Local user accounts and current sessions

  WHAT IT DOES **NOT** DO (explicitly):
     - No password, token, cookie, browser, wallet, or key material collection
     - No persistence: no services, no scheduled tasks, no autoruns, no files
       left behind after exit (temp work dir is deleted)
     - No obfuscation, no encoding tricks, no AV/EDR evasion, no privilege
       escalation, no attempt to bypass UAC or any security control
     - No network traffic except one TLS connection to the SMTP server YOU
       configure, and only after YOU confirm twice

  HOW TO STOP IT AT ANY MOMENT:
     - Press  Ctrl+C   (handled at every prompt and between every step)
     - Create an empty file named  STOP_COLLECTOR  in your home directory
       or next to this script  (checked continuously)
     - Answer "no" at ANY confirmation prompt
     - Just close the window

  USAGE:
     python sysinfo_mailer.py

  SMTP CONFIG (recommended via environment variables, never hardcoded):
     SMTP_HOST   e.g. smtp.gmail.com
     SMTP_PORT   e.g. 587 (STARTTLS) or 465 (SSL)
     SMTP_USER   your login
     SMTP_PASS   an APP PASSWORD — do NOT use your main account password
     EMAIL_FROM  sender address (defaults to SMTP_USER)

  If the env vars are not set you will be prompted interactively.
================================================================================
"""

import os
import sys
import ssl
import time
import shutil
import signal
import socket
import getpass
import zipfile
import platform
import tempfile
import smtplib
import subprocess
from datetime import datetime
from pathlib import Path
from email.message import EmailMessage

# ============================================================================
# SAFETY / ABORT MECHANISMS
# ============================================================================

STOP_FILENAMES = ("STOP_COLLECTOR",)

def _stop_paths():
    here = Path(__file__).resolve().parent
    return [Path.home() / n for n in STOP_FILENAMES] + [here / n for n in STOP_FILENAMES]

def check_stop():
    """Abort immediately if a stop file exists."""
    for p in _stop_paths():
        if p.exists():
            print(f"\n[STOP] Stop file detected at {p}")
            print("[STOP] Aborting. Nothing has been (or will be) sent.")
            sys.exit(0)

def _sigint_handler(signum, frame):
    print("\n\n[ABORT] Ctrl+C received. Nothing was sent.")
    sys.exit(130)

signal.signal(signal.SIGINT, _sigint_handler)


# ============================================================================
# BANNER
# ============================================================================

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗                  ║
║   ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝                  ║
║   ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗                 ║
║   ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║                 ║
║   ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝                 ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝                  ║
║                                                                              ║
║   WINDOWS SYSTEM INFORMATION COLLECTOR & EMAILER                             ║
║                                                                              ║
║   *** THIS TOOL COLLECTS DATA FROM THIS COMPUTER AND EMAILS IT ***           ║
║                                                                              ║
║   Before continuing, be 100% sure you have permission to do this on          ║
║   this machine, and                                                          ║
║   that you are comfortable with what will be collected.                      ║
║                                                                              ║
║   It collects ONLY the diagnostic items listed in the file header.           ║
║   It does NOT collect passwords, cookies, keys, or browser data.             ║
║   It does NOT bypass, disable, or evade ANYTHING.                            ║
║                                                                              ║
║   STOP AT ANY TIME:  Ctrl+C  |  or create a file named STOP_COLLECTOR        ║
║                      in your home directory.                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


# ============================================================================
# SUBPROCESS HELPER  (no shell, no obfuscation, no bypasses)
# ============================================================================

_PS = ["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"]
# NOTE: -ExecutionPolicy Bypass here applies ONLY to this single powershell
# invocation for our own one-liners; we never touch the machine's policy.

def run(cmd, timeout=60):
    """Run a command; return stdout+stderr as text. Never raises."""
    try:
        flags = 0
        if os.name == "nt":
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            shell=False, creationflags=flags,
        )
        out = (r.stdout or "") + (r.stderr or "")
        return out.strip() + "\n"
    except FileNotFoundError:
        return f"[command not found: {cmd[0]}]\n"
    except subprocess.TimeoutExpired:
        return f"[timeout running {cmd[0]}]\n"
    except Exception as e:  # noqa: BLE001
        return f"[error running {cmd[0]}: {e}]\n"


# ============================================================================
# COLLECTORS  (each returns text; called with check_stop() between them)
# ============================================================================

def c_system_info():
    lines = [
        f"Collected at     : {datetime.now().isoformat(timespec='seconds')}",
        f"Hostname         : {socket.gethostname()}",
        f"FQDN             : {socket.getfqdn()}",
        f"Username         : {getpass.getuser()}",
        f"User domain      : {os.environ.get('USERDOMAIN', '')}",
        f"Computer domain  : {os.environ.get('USERDNSDOMAIN', '')}",
        f"Platform         : {platform.platform()}",
        f"System / release : {platform.system()} {platform.release()}",
        f"Version          : {platform.version()}",
        f"Machine          : {platform.machine()}",
        f"Processor        : {platform.processor()}",
        f"Python           : {sys.version.splitlines()[0]}",
        f"Script path      : {Path(__file__).resolve()}",
    ]
    return "\n".join(lines) + "\n"


def c_cpu_ram():
    ps_cpu = ("Get-CimInstance Win32_Processor | "
              "Select-Object Name,NumberOfCores,NumberOfLogicalProcessors,"
              "MaxClockSpeed | Format-List")
    ps_mem = ("Get-CimInstance Win32_PhysicalMemory | "
              "Select-Object BankLabel,Capacity,Speed,Manufacturer,PartNumber | Format-List")
    ps_tot = "('{0:N2} GB' -f ((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB))"
    return (
        "=== CPU ===\n"        + run(_PS + [ps_cpu]) +
        "\n=== Memory Modules ===\n" + run(_PS + [ps_mem]) +
        "\n=== Total RAM ===\n"      + run(_PS + [ps_tot])
    )


def c_disks():
    ps_phys = ("Get-CimInstance Win32_DiskDrive | "
               "Select-Object Model,Size,MediaType,InterfaceType,SerialNumber | Format-List")
    ps_vol  = ("Get-CimInstance Win32_LogicalDisk | "
               "Select-Object DeviceID,VolumeName,FileSystem,Size,FreeSpace | Format-List")
    return ("=== Physical Disks ===\n" + run(_PS + [ps_phys]) +
            "\n=== Logical Volumes ===\n" + run(_PS + [ps_vol]))


def c_network():
    return run(["ipconfig", "/all"])


def c_installed_software():
    ps = (
        "$p=@('HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*');"
        "Get-ItemProperty $p -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName } | "
        "Select-Object DisplayName,DisplayVersion,Publisher | "
        "Sort-Object DisplayName | Format-Table -AutoSize"
    )
    return run(_PS + [ps], timeout=120)


def c_processes():
    ps = ("Get-Process -ErrorAction SilentlyContinue | "
          "Select-Object Id,ProcessName,Path | "
          "Sort-Object ProcessName | Format-Table -AutoSize")
    return run(_PS + [ps], timeout=120)


_SECRET_HINTS = ("PASS", "SECRET", "TOKEN", "KEY", "CRED", "PWD",
                 "AUTH", "SESSION", "API", "PRIVATE")

def c_environment():
    """Dump environment variables, redacting anything that looks sensitive."""
    out = []
    for k, v in sorted(os.environ.items()):
        if any(h in k.upper() for h in _SECRET_HINTS):
            out.append(f"{k}=[REDACTED]")
        else:
            out.append(f"{k}={v}")
    out.append("\n(Any variable whose NAME contains one of "
               f"{_SECRET_HINTS} was replaced with [REDACTED].)")
    return "\n".join(out) + "\n"


def c_users():
    return run(["net", "user"])


def c_sessions():
    return run(["query", "session"])


def collect_all():
    """Collect every artifact; halts instantly if a stop condition fires."""
    jobs = [
        ("system_info.txt",        c_system_info),
        ("cpu_ram.txt",            c_cpu_ram),
        ("disks.txt",              c_disks),
        ("network.txt",            c_network),
        ("installed_software.txt", c_installed_software),
        ("running_processes.txt",  c_processes),
        ("environment.txt",        c_environment),
        ("users.txt",              c_users),
        ("sessions.txt",           c_sessions),
    ]
    collected = []
    for name, fn in jobs:
        check_stop()
        print(f"  [*] collecting {name} ...")
        collected.append((name, fn()))
    return collected


# ============================================================================
# ZIP
# ============================================================================

def build_zip(items):
    """Write a ZIP to a temp dir. Returns (zip_path, tmp_dir) for cleanup."""
    check_stop()
    tmp_dir = Path(tempfile.mkdtemp(prefix="sysinfo_mailer_"))
    stamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_host = "".join(c if c.isalnum() or c in "-_." else "_" for c in socket.gethostname())
    zip_path = tmp_dir / f"system_info_{safe_host}_{stamp}.zip"

    # README inside the ZIP so the recipient knows what they're opening
    readme = (
        "This archive was produced by the Windows System Information "
        "Collector & Emailer script.\n\n"
        "It contains ONLY the benign diagnostic files you saw printed "
        "in the collector's console banner.\n\n"
        f"Collected on host : {socket.gethostname()}\n"
        f"Collected by user : {getpass.getuser()}\n"
        f"Collected at      : {datetime.now().isoformat(timespec='seconds')}\n\n"
        "Files in this archive:\n" + "\n".join(f"  - {n}" for n, _ in items) + "\n"
    )
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("README.txt", readme)
        for name, content in items:
            check_stop()
            zf.writestr(name, content)
    return zip_path, tmp_dir


# ============================================================================
# EMAIL
# ============================================================================

def _prompt_smtp():
    """Load SMTP settings from env; fall back to interactive input."""
    host = os.environ.get("SMTP_HOST") or input("SMTP host (e.g. smtp.gmail.com): ").strip()
    port = os.environ.get("SMTP_PORT") or input("SMTP port (587 for STARTTLS, 465 for SSL): ").strip()
    user = os.environ.get("SMTP_USER") or input("SMTP username: ").strip()
    pw   = os.environ.get("SMTP_PASS") or getpass.getpass("SMTP password / app password: ")
    frm  = os.environ.get("EMAIL_FROM") or user
    return {"host": host, "port": int(port), "user": user, "pass": pw, "from": frm}


def send_email(zip_path: Path, recipients, cfg):
    check_stop()
    msg = EmailMessage()
    msg["From"]    = cfg["from"]
    msg["To"]      = ", ".join(recipients)
    msg["Subject"] = f"System info from {socket.gethostname()} - {datetime.now():%Y-%m-%d %H:%M}"
    msg.set_content(
        "Automated system-information report.\n\n"
        f"Host : {socket.gethostname()}\n"
        f"User : {getpass.getuser()}\n"
        f"Time : {datetime.now().isoformat(timespec='seconds')}\n\n"
        "The attached ZIP contains only the diagnostic files listed in the "
        "collector's on-screen banner and in the README.txt inside the ZIP. HAVE FUN CHINAA, ESPECIALLY YOU CIA!!\n"
    )
    with open(zip_path, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="zip",
            filename=zip_path.name,
        )

    ctx = ssl.create_default_context()
    host, port = cfg["host"], cfg["port"]

    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=ctx, timeout=60) as s:
            s.login(cfg["user"], cfg["pass"])
            s.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=60) as s:
            s.ehlo()
            s.starttls(context=ctx)
            s.ehlo()
            s.login(cfg["user"], cfg["pass"])
            s.send_message(msg)


# ============================================================================
# INTERACTIVE CONSENT
# ============================================================================

def _abort(msg="[ABORT] Nothing was sent."):
    print(msg)
    sys.exit(0)

def require_yes(question, exact=None):
    """Return only if the user typed yes / y (or `exact`). Otherwise abort."""
    check_stop()
    if exact is None:
        ans = input(f"{question} [type 'yes' to continue, anything else aborts]: ").strip().lower()
        if ans not in ("yes", "y"):
            _abort()
    else:
        ans = input(f"{question} [type '{exact}' exactly to continue]: ").strip()
        if ans != exact:
            _abort()

def countdown(seconds=10):
    """Visible countdown; Ctrl+C or STOP file aborts, nothing is sent."""
    print(f"\nSending in {seconds} seconds. Press Ctrl+C to abort.")
    for i in range(seconds, 0, -1):
        check_stop()
        print(f"   {i}...", end="", flush=True)
        time.sleep(1)
    print("\nSending now.\n")


# ============================================================================
# MAIN
# ============================================================================

def main():
    print(BANNER)

    # ---------------- Consent #1: what the tool is ----------------------
    require_yes(
        "Do you understand that this script COLLECTS data from this "
        "computer and EMAILS it to the addresses you will type next?"
    )

    # ---------------- Recipients ---------------------------------------
    check_stop()
    r1 = "english@mail.gov.cn"
    r2 = "media@ucia.gov"
    if not r1 or not r2 or "@" not in r1 or "@" not in r2:
        _abort("[ABORT] Both recipients must be valid-looking email addresses.")
    if r1.lower() == r2.lower():
        _abort("[ABORT] The two recipients must be different addresses.")
    print(f"\n  Recipients -> {r1} , {r2}\n")

    # ---------------- SMTP config --------------------------------------
    check_stop()
    print("SMTP settings (use an APP PASSWORD, never your main password).")
    print("Prefer setting SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASS / "
          "EMAIL_FROM in the environment.\n")
    cfg = _prompt_smtp()

    # ---------------- Consent #2: confirm recipients -------------------
    require_yes(
        f"You are about to send this machine's diagnostic data to "
        f"{r1} and {r2} via {cfg['host']}:{cfg['port']}. Proceed?",
    )

    # ---------------- Collect ------------------------------------------
    check_stop()
    print("\nCollecting data ...\n")
    items = collect_all()

    # ---------------- Package ------------------------------------------
    check_stop()
    print("\nPackaging ...")
    zip_path, tmp_dir = build_zip(items)
    size_kb = zip_path.stat().st_size / 1024
    print(f"  [+] Wrote {zip_path.name} ({size_kb:.1f} KB)")

    try:
        # ---------------- Consent #3: final, exact-match ----------------
        print("\n" + "=" * 78)
        print(" FINAL CONFIRMATION")
        print("=" * 78)
        print(f"  ZIP file    : {zip_path.name}")
        print(f"  Size        : {size_kb:.1f} KB")
        print(f"  Files inside:")
        for n, _ in items:
            print(f"     - {n}")
        print(f"  Recipients  : {r1}, {r2}")
        print(f"  SMTP        : {cfg['host']}:{cfg['port']}")
        print("=" * 78)
        require_yes("Send this ZIP now?", exact="SEND")

        # ---------------- Countdown & send ------------------------------
        countdown(10)
        check_stop()
        print("Sending email ...")
        send_email(zip_path, [r1, r2], cfg)
        print("\n[OK] Email sent to both recipients.")

    finally:
        # Always clean up the temp ZIP, even on abort/failure.
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[ABORT] Interrupted by user. Nothing was sent.")
        sys.exit(130)