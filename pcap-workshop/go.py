"""ONE STEP: install what's missing, check everyone's work, then start the website.

  python go.py          do everything (asks before starting the website)
  python go.py check    just install + check
  python go.py web      just install + start the website

On Windows you can simply double-click GO.bat instead.
"""
import importlib.util
import os
import subprocess
import sys
import threading
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))
URL = "http://127.0.0.1:8000"
PACKAGES = ["scapy", "flask"]  # same as requirements.txt


def install_missing():
    """Install scapy/flask into THIS Python if they aren't there yet.

    Using sys.executable means the packages always go into the Python that runs
    the workshop. Plain "pip install" can put them into a different Python
    (very common with Anaconda or several Pythons on one PC).
    """
    missing = [p for p in PACKAGES if importlib.util.find_spec(p) is None]
    if not missing:
        print("[OK] scapy and flask are installed.")
        return True

    print(f"Installing {', '.join(missing)} (one time only)...")
    base = [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check"]
    if subprocess.call(base + missing) != 0:
        print("Retrying for this user only (no admin rights needed)...")
        if subprocess.call(base + ["--user"] + missing) != 0:
            print("\n[X] Could not install the packages. Check your internet connection, or ask a coordinator.")
            return False
    importlib.invalidate_caches()
    print("[OK] Installed.")
    return True


def run_checks():
    print("\nChecking everyone's work...\n")
    subprocess.call([sys.executable, "check.py"], cwd=HERE)


def run_website():
    in_codespace = bool(os.environ.get("CODESPACES"))
    print(f"\nStarting the website at {URL}  (press Ctrl+C to stop)")
    if in_codespace:
        print("In Codespaces: click 'Open in Browser' when the pop-up appears (or use the Ports tab).")
    else:
        threading.Timer(2.5, webbrowser.open, [URL]).start()
    try:
        subprocess.call([sys.executable, "start.py"], cwd=HERE)
    except KeyboardInterrupt:
        pass
    print("\nWebsite stopped.")


def main():
    os.chdir(HERE)
    mode = sys.argv[1].lower() if len(sys.argv) > 1 else "all"
    if mode not in ("all", "check", "web"):
        print(__doc__)
        return

    print(f"Using Python {sys.version.split()[0]} at {sys.executable}\n")
    if not install_missing():
        sys.exit(1)

    if mode in ("all", "check"):
        run_checks()
    if mode == "web":
        run_website()
    elif mode == "all":
        try:
            answer = input("\nStart the website now? [Y/n] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer in ("", "y", "yes"):
            run_website()


if __name__ == "__main__":
    main()
