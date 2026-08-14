import sys
from pathlib import Path


source_root = Path(sys.argv[1]).resolve()
output_path = Path(sys.argv[2]).resolve()

files = [
    Path("qml/Main.qml"),
    Path("assets/potions/catalog-01.png"),
    Path("assets/potions/catalog-02.png"),
    Path("assets/potions/catalog-03.png"),
    Path("assets/potions/catalog-04.png"),
    Path("assets/potions/catalog-05.png"),
    Path("assets/visuals/rapper-close.png"),
    Path("assets/visuals/rapper-cross.png"),
    Path("assets/visuals/mixtape.png"),
]
files.extend(sorted(Path("assets/potions/sprites").glob("*.png")))
files.extend(sorted(Path("assets/potions/lab_sprites").glob("*.png")))

entries = []
for relative_path in files:
    absolute_path = source_root / relative_path
    alias = relative_path.as_posix()
    entries.append(f'    <file alias="{alias}">{absolute_path.as_posix()}</file>')

qrc = '<RCC>\n  <qresource prefix="/Utopia">\n'
qrc += "\n".join(entries)
qrc += "\n  </qresource>\n</RCC>\n"
output_path.write_text(qrc, encoding="utf-8")
