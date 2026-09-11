import sys
from pathlib import Path

# workers/ root must be on sys.path so `import app...` resolves.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
