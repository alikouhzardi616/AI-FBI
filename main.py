from __future__ import annotations

import os
from importlib import import_module


def main() -> None:
    if "ANDROID_ARGUMENT" in os.environ:
        run = import_module("ui.kivy_app").run
    else:
        run = import_module("ui.desktop_app").run
    run()


if __name__ == "__main__":
    main()
