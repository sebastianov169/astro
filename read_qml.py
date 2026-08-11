import sys

f = open('qml/Main.qml', 'r', encoding='utf-8')
content = f.read()
f.close()

lines = content.split('\n')
with open('_temp_qml.txt', 'w', encoding='utf-8') as out:
    for i, line in enumerate(lines, 1):
        out.write(f'{i:4d}: {line}\n')

print(f'Total lines: {len(lines)}')
print('Written to _temp_qml.txt')
