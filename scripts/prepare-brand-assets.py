"""Convert the approved official PNG into shell icon sizes without redrawing it."""
from pathlib import Path
from PIL import Image

root = Path(__file__).resolve().parents[1]
image = Image.open(root / ".local/downloads/anxin-icon.png").convert("RGBA")
target = root / "src/CodeSigner.App/Assets"
image.save(target / "CodeSigner.png")
image.save(target / "CodeSigner.ico", format="ICO",
           sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (192, 192)])
