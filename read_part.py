import sys

f = open('_temp_qml.txt', 'r', encoding='utf-8')
lines = f.readlines()
f.close()

# Write first 200 lines to a separate file
with open('_part1.txt', 'w', encoding='utf-8') as out:
    for line in lines[:200]:
        out.write(line)

print(f'Written lines 1-200 to _part1.txt')
