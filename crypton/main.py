import sys
import os

def _detect_initial_vault_dir() -> str:
    cwd = os.getcwd()
    if os.path.exists(os.path.join(cwd, ".crypton")):
        return cwd
    # If launched from USB file manager, sys.argv[0] is in the USB mount
    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    if os.path.exists(os.path.join(exe_dir, ".crypton")):
        return exe_dir
    return cwd


def main():
    # If no arguments provided, or explicitly requested --gui / -g, launch the GUI
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] in ("--gui", "-g")):
        from crypton.ui.gui import launch_gui
        launch_gui(_detect_initial_vault_dir())
    else:
        from crypton.ui.cli import app
        app()

if __name__ == "__main__":
    main()
