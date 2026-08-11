import sys

f = open('qml/Main.qml', 'r', encoding='utf-8')
content = f.read()
f.close()
lines = content.split('\n')

# Find key patterns
patterns = [
    'ACTIVE SESSIONS', 'GEMS LOADED', 'DEATHS', 'EVENTS',
    'Dashboard', 'Accounts Progress', 'Activity',
    'themeDefs', 'sidebar', 'Repeater',
    'removeAreaAcc', 'removeAreaDash',
    'farmStatus', 'lastRefresh', 'GemSprite',
    'smallCaption', 'SmallCaption',
    'Panel', 'Panel.*preferredWidth.*245',
    'page:', 'StackLayout',
    'totalXpGained', 'farmsActive', 'farmRunning', 'farmSelection',
    'accountStartTimes', 'timerTick'
]

import re
with open('_search_results.txt', 'w', encoding='utf-8') as out:
    for pat in patterns:
        out.write(f'\n=== Pattern: {pat} ===\n')
        for i, line in enumerate(lines, 1):
            if re.search(pat, line, re.IGNORECASE):
                out.write(f'  {i:4d}: {line.rstrip()}\n')

print('Search done')
