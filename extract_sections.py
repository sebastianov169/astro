import sys

f = open('qml/Main.qml', 'r', encoding='utf-8')
content = f.read()
f.close()
lines = content.split('\n')

# Extract key sections
sections = [
    (535, 545, 'sidebar model'),
    (600, 625, 'page title + theme dots'),
    (650, 680, 'stats tiles'),
    (860, 940, 'Dashboard accounts delegate'),
    (1055, 1130, 'Accounts page delegate'),
]

with open('_sections.txt', 'w', encoding='utf-8') as out:
    for start, end, name in sections:
        out.write(f'\n{"="*60}\n=== {name} (lines {start}-{end}) ===\n{"="*60}\n')
        for i in range(start-1, min(end, len(lines))):
            out.write(f'{i+1:4d}: {lines[i]}\n')

print('Sections extracted')
