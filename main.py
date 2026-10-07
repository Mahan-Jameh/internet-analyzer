"""
main.py
=======
Entry point for the Internet Connectivity & Protocol Analyzer.

Run with:  python main.py
Build with: pyinstaller build.spec
"""

from __future__ import annotations

import sys
import traceback


def _install_global_exception_hook() -> None:
    """Ensure that any unexpected error shows a dialog instead of a silent crash."""

    def _hook(exc_type, exc_value, exc_traceback):
        from app.logger import get_logger

        log = get_logger("crash")
        log.critical(
            "Unhandled exception: %s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)),
        )
        try:
            from PySide6.QtWidgets import QApplication, QMessageBox

            if QApplication.instance() is not None:
                QMessageBox.critical(
                    None,
                    "Unexpected Error",
                    "An unexpected error occurred and has been logged.\n\n"
                    f"{exc_type.__name__}: {exc_value}",
                )
        except Exception:
            pass

    sys.excepthook = _hook


def main() -> int:
    _install_global_exception_hook()

    from PySide6.QtWidgets import QApplication

    from app.config import Paths
    from app.constants import APP_NAME, ORG_NAME
    from app.gui.main_window import MainWindow

    Paths.ensure_created()

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(ORG_NAME)

    from app.gui import fonts

    fonts.load_bundled_fonts()
    fonts.apply_default_font(app)

    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
