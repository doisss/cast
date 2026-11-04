"""python -m cast — то же, что команда cast (так cast web перезапускает себя через sudo)."""

import sys

from cast.cli import entry_point

sys.exit(entry_point())
