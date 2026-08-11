import sys

f = open('qml/Main.qml', 'r', encoding='utf-8')
content = f.read()
f.close()
lines = content.split('\n')

# Get Dashboard accounts section more completely
sections = [
    (830, 940, 'Dashboard accounts full'),
    (950, 1000, 'Accounts page header'),
    (1000, 1130, 'Accounts page delegate full'),
    (635, 658, 'stats row context'),
]

with open('_sections2.txt', 'w', encoding='utf-8') as out:
    for start, end, name in sections:
        out.write(f'\n{"="*60}\n=== {name} (lines {start}-{end}) ===\n{"="*60}\n')
        for i in range(start-1, min(end, len(lines))):
            out.write(f'{i+1:4d}: {lines[i]}\n')

print('Sections2 extracted')
