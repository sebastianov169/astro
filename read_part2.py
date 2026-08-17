import sys

f = open('_temp_qml.txt', 'r', encoding='utf-8')
lines = f.readlines()
f.close()

with open('_part2.txt', 'w', encoding='utf-8') as out:
    for line in lines[200:400]:
        out.write(line)

print('Written lines 201-400')
