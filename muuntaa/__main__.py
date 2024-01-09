import sys

from muuntaa.cli import app

if __name__ == '__main__':
    sys.exit(app(sys.argv[1:]))  # pragma: no cover
