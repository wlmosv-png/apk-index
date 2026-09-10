"""``python3 -m apkindex`` == the ``apk-index`` executable."""
from .server import main

if __name__ == "__main__":
    raise SystemExit(main())
