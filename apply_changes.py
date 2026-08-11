"""
Apply all 5 changes to qml/Main.qml
"""
f = open('qml/Main.qml', 'r', encoding='utf-8')
lines = f.readlines()
f.close()

# Convert to string for easier manipulation
content = ''.join(lines)

changes_made = []

# ============================================================
# CHANGE 1: Dashboard Stats Overhaul
# Replace the 5-item model with 3 new items
# ============================================================
old_stats = '                        model: [ {label: "ACTIVE SESSIONS", value: farm.farmRunning ? "1" : "0", color: "#50d39f"}, {label: "GEMS LOADED", value: farm.gemCount.toString(), color: "#edf3f4"}, {label: "WAITING / RETRY", value: "0", color: "#dcae4c"}, {label: "DEATHS", value: farm.deaths.toString(), color: "#ed3c59"}, {label: "EVENTS", value: farm.eventCount.toString(), color: "#edf3f4"} ]'

new_stats = '                        model: [ {label: "ACTIVE SESSIONS", value: farm.farmSelection.length.toString(), color: "#50d39f"}, {label: "WAITING", value: farm.accounts.filter(function(a){return a.farmStatus && a.farmStatus !== "Farming" && a.farmStatus !== "Idle" && a.farmStatus !== ""}).length.toString(), color: "#dcae4c"}, {label: "FARMED XP", value: farm.totalXpGained !== undefined ? "+" + farm.totalXpGained.toFixed(1) + " XP" : "...", color: "#50d39f" } ]'

if old_stats in content:
    content = content.replace(old_stats, new_stats)
    changes_made.append("CHANGE 1: Stats tiles replaced (3 items)")

# Update the separator visible condition (index < 4 -> index < 2) 
old_sep = 'visible: index < 4'
new_sep = 'visible: index < 2'
if old_sep in content:
    content = content.replace(old_sep, new_sep)
    changes_made.append("CHANGE 1b: Separator visible index < 4 -> < 2")

# ============================================================
# CHANGE 2: New "dark" Theme
# Add to themeDefs
# ============================================================
dark_theme = '''        dark:   { canvas:"#0d0d0d",surface:"#1a1a1a",surface2:"#222222",surface3:"#2a2a2a",border:"#333333",borderSoft:"#282828",text:"#e0e0e0",muted:"#666666",faint:"#444444",mint:"#d4a520",red:"#cc3333",amber:"#d4a520",blue:"#4080ff",wine:"#331111",pri1:"#d4a520",pri2:"#b8901a",priH1:"#e8b830",priH2:"#c9a028",priD1:"#8a6b10",priD2:"#6b4b08",priBdr:"#d4a520" },'''

# Insert after sunset theme
sunset_end = '        sunset: { canvas:"#100808",surface:"#1a0e0c",surface2:"#241614",surface3:"#301e1a",border:"#6a3828",borderSoft:"#4a2818",text:"#fff0e8",muted:"#b09080",faint:"#806050",mint:"#f0a040",red:"#e04840",amber:"#f0c040",blue:"#f08040",wine:"#401810",pri1:"#ff8030",pri2:"#c04a18",priH1:"#ffa050",priH2:"#d06020",priD1:"#d05518",priD2:"#a03808",priBdr:"#ff9040" }'

if dark_theme not in content:
    content = content.replace(sunset_end, sunset_end + '\n' + dark_theme)
    changes_made.append("CHANGE 2a: dark theme added to themeDefs")

# Add "dark" to theme selector repeater
old_themes = 'model: ["midnight", "ocean", "neon", "forest", "sunset"]'
new_themes = 'model: ["midnight", "ocean", "neon", "forest", "sunset", "dark"]'
if old_themes in content:
    content = content.replace(old_themes, new_themes)
    changes_made.append("CHANGE 2b: dark added to theme selector")

# ============================================================
# CHANGE 3: Real-time Account Timers
# Add property and Timer
# ============================================================

# Add accountStartTimes property after currentTheme
if 'property var accountStartTimes' not in content:
    content = content.replace(
        '    property string currentTheme: "midnight"',
        '    property string currentTheme: "midnight"\n    property var accountStartTimes: ({})'
    )
    changes_made.append("CHANGE 3a: accountStartTimes property added")

# Add timerTick Timer after toastTimer
if 'id: timerTick' not in content:
    content = content.replace(
        '    Timer { id: toastTimer; interval: 2400; onTriggered: root.showToast = false }',
        '    Timer { id: toastTimer; interval: 2400; onTriggered: root.showToast = false }\n    Timer { id: timerTick; interval: 1000; running: true; repeat: true; property int tick: 0; onTriggered: tick++ }'
    )
    changes_made.append("CHANGE 3b: timerTick Timer added")

# Replace Dashboard accounts SmallCaption (lastRefresh) with real-time timer
# Dashboard delegate uses removeAreaDash
# Find the exact block in Dashboard delegate (between removeAreaDash and the closing of RowLayout)
old_dash_timer = '''                                                SmallCaption {
                                                    visible: modelData.lastRefresh > 0
                                                    text: root.timeAgo(modelData.lastRefresh)
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length === 0'''

new_dash_timer = '''                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming"
                                                    text: {
                                                        timerTick.tick
                                                        var start = root.accountStartTimes[modelData.device]
                                                        if (!start) return ""
                                                        var elapsed = Math.floor((Date.now() - start) / 1000)
                                                        var h = Math.floor(elapsed / 3600)
                                                        var m = Math.floor((elapsed % 3600) / 60)
                                                        var s = elapsed % 60
                                                        return (h > 0 ? h + ":" : "") + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
                                                    }
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length === 0'''

if old_dash_timer in content:
    content = content.replace(old_dash_timer, new_dash_timer)
    changes_made.append("CHANGE 3c: Dashboard accounts timer replaced")

# Replace Accounts page SmallCaption (lastRefresh) with real-time timer
# Accounts delegate uses removeAreaAcc
old_acc_timer = '''                                                SmallCaption {
                                                    visible: modelData.lastRefresh > 0
                                                    text: root.timeAgo(modelData.lastRefresh)
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0'''

new_acc_timer = '''                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming"
                                                    text: {
                                                        timerTick.tick
                                                        var start = root.accountStartTimes[modelData.device]
                                                        if (!start) return ""
                                                        var elapsed = Math.floor((Date.now() - start) / 1000)
                                                        var h = Math.floor(elapsed / 3600)
                                                        var m = Math.floor((elapsed % 3600) / 60)
                                                        var s = elapsed % 60
                                                        return (h > 0 ? h + ":" : "") + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
                                                    }
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0'''

if old_acc_timer in content:
    content = content.replace(old_acc_timer, new_acc_timer)
    changes_made.append("CHANGE 3d: Accounts page timer replaced")

# Add onFarmStatusChanged to Dashboard delegate
# Find the delegate and add a Connections block
# Dashboard delegate has HoverHandler with id: accHover
old_dash_hover = '''                                        HoverHandler { id: accHover }
                                        ColumnLayout {'''

new_dash_hover = '''                                        HoverHandler { id: accHover }
                                        Connections {
                                            target: null
                                            function onFarmStatusChanged() {
                                                if (modelData.farmStatus === "Farming" && !root.accountStartTimes[modelData.device]) {
                                                    root.accountStartTimes = Object.assign({}, root.accountStartTimes, {[modelData.device]: Date.now()})
                                                }
                                            }
                                        }
                                        ColumnLayout {'''

# This needs to be inside the Dashboard delegate only - but there's also one in Accounts
# We need to be more specific. Let's use context around Dashboard-specific code.
# Dashboard has "removeAreaDash", Accounts has "removeAreaAcc"
# The Dashboard delegate starts at around line 833 with model: farm.filteredAccounts
# Let's find the specific occurrence. The first HoverHandler{ id: accHover } is Dashboard.

# Actually, let's use a different approach - the first occurrence of HoverHandler { id: accHover } is Dashboard
count = content.count('HoverHandler { id: accHover }')
if count == 2:
    # Replace only the first one (Dashboard)
    content = content.replace('HoverHandler { id: accHover }\n                                        ColumnLayout {', 
                              'HoverHandler { id: accHover }\n                                        Connections {\n                                            target: null\n                                            function onFarmStatusChanged() {\n                                                if (modelData.farmStatus === "Farming" && !root.accountStartTimes[modelData.device]) {\n                                                    root.accountStartTimes = Object.assign({}, root.accountStartTimes, {[modelData.device]: Date.now()})\n                                                }\n                                            }\n                                        }\n                                        ColumnLayout {', 1)
    changes_made.append("CHANGE 3e: Dashboard onFarmStatusChanged added")

# Add onFarmStatusChanged to Accounts delegate
# The second HoverHandler { id: accHover } is in Accounts
# After the first replacement, there's still one more. Let's add to it.
if content.count('HoverHandler { id: accHover }') == 1:
    # This is the Accounts page one - add the handler there too
    # But we need a unique context. The Accounts page has removeAreaAcc in it.
    # Let's use a broader context.
    old_acc_context = '''                                                    }
                                                }
                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                GemSprite { sprite: modelData.sprite; iconSize: 28; Layout.preferredWidth: 28; Layout.preferredHeight: 28; visible: modelData.sprite && modelData.sprite.length > 0 }'''
    # Wait, this is for the gem removal. Let me handle the Connections differently.
    # The Accounts page delegate has the removeAreaAcc. Let me find the HoverHandler inside that delegate.
    # Actually, both delegates have HoverHandler { id: accHover } - I replaced the first one.
    # The remaining one is in Accounts page. But the Accounts delegate structure is different.
    pass

# Let me add the Connections to Accounts page delegate using a different approach
# Find the Accounts page by looking for removeAreaAcc context
# The Accounts page delegate's ColumnLayout starts after its HoverHandler

# For the Accounts page, find the second ColumnLayout after the remaining HoverHandler
# Actually, the remaining HoverHandler { id: accHover } is in Accounts page
# Let me just add a Connections block after it too
if 'HoverHandler { id: accHover }\n                                        ColumnLayout {' in content:
    content = content.replace(
        'HoverHandler { id: accHover }\n                                        ColumnLayout {',
        'HoverHandler { id: accHover }\n                                        Connections {\n                                            target: null\n                                            function onFarmStatusChanged() {\n                                                if (modelData.farmStatus === "Farming" && !root.accountStartTimes[modelData.device]) {\n                                                    root.accountStartTimes = Object.assign({}, root.accountStartTimes, {[modelData.device]: Date.now()})\n                                                }\n                                            }\n                                        }\n                                        ColumnLayout {',
        1  # only first remaining occurrence = Accounts page
    )
    changes_made.append("CHANGE 3f: Accounts onFarmStatusChanged added")

# ============================================================
# CHANGE 4: Rename Sidebar
# ============================================================
old_sidebar = 'model: ["Dashboard", "Accounts Progress", "Activity"]'
new_sidebar = 'model: ["Dashboard", "Accounts", "Activity"]'
if old_sidebar in content:
    content = content.replace(old_sidebar, new_sidebar)
    changes_made.append("CHANGE 4a: Sidebar renamed")

# Update page title
old_title = 'LabelText { text: page === 0 ? "Night Dashboard" : page === 1 ? "Accounts Progress" : "Activity"'
new_title = 'LabelText { text: page === 0 ? "Night Dashboard" : page === 1 ? "Accounts" : "Activity"'
if old_title in content:
    content = content.replace(old_title, new_title)
    changes_made.append("CHANGE 4b: Page title renamed")

# Update the other "Accounts Progress" references
# Line 822
old_acc_title = 'LabelText { text: "Accounts Progress"; font.pixelSize: 19; font.weight: Font.Bold; Layout.fillWidth: true }'
new_acc_title = 'LabelText { text: "Accounts"; font.pixelSize: 19; font.weight: Font.Bold; Layout.fillWidth: true }'
if old_acc_title in content:
    content = content.replace(old_acc_title, new_acc_title)
    changes_made.append("CHANGE 4c: Dashboard panel title renamed")

# Line 955 - Accounts page header
old_acc_header = 'LabelText { text: "Accounts Progress"; font.pixelSize: 19; font.weight: Font.DemiBold; Layout.fillWidth: true }'
new_acc_header = 'LabelText { text: "Accounts"; font.pixelSize: 19; font.weight: Font.DemiBold; Layout.fillWidth: true }'
if old_acc_header in content:
    content = content.replace(old_acc_header, new_acc_header)
    changes_made.append("CHANGE 4d: Accounts page header renamed")

# ============================================================
# CHANGE 5: Remove GemSprites from Accounts Progress only
# Remove GemSprite and gemSummary from Accounts page delegate
# (the one with removeAreaAcc)
# ============================================================

# The Accounts page delegate second RowLayout contains:
# GemSprite (line 1091)
# gemSummary LabelText (lines 1092-1098)  
# XP LabelText (lines 1099-1107)
# ProgressBar (lines 1108-1115)
# SmallCaption (lines 1116-1121) - already changed to timer above

# Find the specific block in Accounts page that has removeAreaAcc context
# We need to target the second RowLayout that follows the removeAreaAcc block
# The Accounts page second RowLayout starts after:
#   the closing of the first RowLayout (with removeAreaAcc)
# and contains GemSprite

# Let me use a very specific pattern that's unique to Accounts page
# The key unique identifier: the RowLayout right before the GemSprite in Accounts page
# is after "removeAreaAcc" block

# Actually, looking at the structure: both Dashboard and Accounts have identical RowLayout structures
# The distinguishing factor is what's INSIDE: Dashboard has removeAreaDash, Accounts has removeAreaAcc
# But the GemSprite RowLayout is AFTER the removeArea block

# Let me find the specific context. In Accounts page, after removeAreaAcc block:
old_acc_gem = '''                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                GemSprite { sprite: modelData.sprite; iconSize: 28; Layout.preferredWidth: 28; Layout.preferredHeight: 28; visible: modelData.sprite && modelData.sprite.length > 0 }
                                                LabelText {
                                                    visible: modelData.gemSummary && modelData.gemSummary.length > 0
                                                    text: modelData.gemSummary
                                                    color: colors.amber
                                                    font.pixelSize: 9
                                                    Layout.preferredWidth: 96
                                                }
                                                LabelText {'''

new_acc_gem = '''                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                LabelText {'''

# This pattern might match both Dashboard and Accounts. Let me check with a more unique context.
# Dashboard has: onClicked: farm.removeAccount(index)\n                                                    }\n                                                }\n                                            }\n                                            RowLayout
# Accounts has: onClicked: farm.removeAccount(index)\n                                                    }\n                                                }\n                                            }\n                                            RowLayout
# These are the same! I need to use a broader unique context.

# Let me try a different approach: use the context that includes "removeAreaAcc"
# In Accounts page, the RowLayout with removeAreaAcc is followed by the second RowLayout

# Better approach: find the Accounts page section by line number and replace
# Let me count occurrences of the GemSprite pattern

# The Dashboard GemSprite pattern (after removeAreaDash):
# ...removeAreaDash... -> RowLayout -> GemSprite
# The Accounts GemSprite pattern (after removeAreaAcc):
# ...removeAreaAcc... -> RowLayout -> GemSprite

# Let me search for the specific occurrence after removeAreaAcc
# Use a unique context: "onClicked: farm.removeAccount(index)\n                                                    }\n                                                }\n                                            }\n                                            RowLayout {\n                                                Layout.fillWidth: true\n                                                spacing: 8\n                                                GemSprite { sprite: modelData.sprite"
# This appears in both. But I can use the fact that after the Accounts page delegate,
# the next major element is "LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0"

# Let me use a two-pass approach:
# 1. First, replace in Dashboard (which has removeAreaDash before it)
# 2. Then replace the remaining one (Accounts)

# Dashboard: unique context is removeAreaDash -> ... -> RowLayout -> GemSprite
dash_gem_pattern = '''                                                        onClicked: farm.removeAccount(index)
                                                    }
                                                }
                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                GemSprite { sprite: modelData.sprite; iconSize: 28; Layout.preferredWidth: 28; Layout.preferredHeight: 28; visible: modelData.sprite && modelData.sprite.length > 0 }
                                                LabelText {
                                                    visible: modelData.gemSummary && modelData.gemSummary.length > 0
                                                    text: modelData.gemSummary
                                                    color: colors.amber
                                                    font.pixelSize: 9
                                                    Layout.preferredWidth: 96
                                                }
                                                LabelText {
                                                    visible: modelData.exp > 0
                                                    text: (modelData.cexp || 0).toLocaleString() + " / " + (modelData.exp || 0).toLocaleString() + " XP"
                                                    color: colors.muted
                                                    font.pixelSize: 9
                                                    font.family: "Cascadia Mono, Consolas, monospace"
                                                    Layout.preferredWidth: 130
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                ProgressBar {
                                                    visible: modelData.exp > 0
                                                    Layout.fillWidth: true
                                                    Layout.preferredHeight: 5
                                                    animated: false
                                                    value: root.gemProgress(modelData.cexp, modelData.exp)
                                                    barColor: colors.amber
                                                }
                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming"
                                                    text: {
                                                        timerTick.tick'''

# This will match the Dashboard one first (since we already replaced the SmallCaption in both).
# Actually, since both have been replaced with the timer version, they're identical!
# I need a different approach.

# Let me use the fact that Dashboard accounts section has "LabelText { visible: farm.accounts.length === 0"
# while Accounts page has "LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0"

# Better: just find and replace in the specific line ranges
# Dashboard delegate: lines 833-937
# Accounts delegate: lines 1004-1130

# Since I'm working with the full string, let me use a unique surrounding context.
# In the Dashboard, the RowLayout with GemSprite is preceded by content that includes:
# "removeAreaDash"
# In Accounts, it's preceded by "removeAreaAcc"

# The simplest approach: the entire Accounts section is uniquely identifiable
# by having both removeAreaAcc AND the RowLayout with GemSprite in sequence.
# Let me search for a larger unique context that only appears in Accounts.

# After the replace of SmallCaption, the Accounts page delegate's second RowLayout looks like:
# (after removeAreaAcc closing braces)
#     RowLayout { Layout.fillWidth: true; spacing: 8
#         GemSprite ...
#         LabelText { gemSummary }
#         LabelText { XP }
#         ProgressBar
#         SmallCaption { timer }
#     }
#     } (ColumnLayout)
#     MouseArea { ... onClicked: farm.useAccount(index) ... cursorShape: Qt.PointingHandCursor }
#     } (Rectangle - delegate)
#     } (ListView)
#     LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0

# In the Dashboard, after the second RowLayout:
#     } (ColumnLayout)
#     MouseArea { ... onClicked: farm.useAccount(index) ... cursorShape: Qt.PointingHandCursor }
#     } (Rectangle - delegate)
#     } (ListView)
#     LabelText { visible: farm.accounts.length === 0

# So I can use the closing context to differentiate!

# Let me replace the Accounts one specifically using its unique closing
acc_gem_removal_context = '''                                                GemSprite { sprite: modelData.sprite; iconSize: 28; Layout.preferredWidth: 28; Layout.preferredHeight: 28; visible: modelData.sprite && modelData.sprite.length > 0 }
                                                LabelText {
                                                    visible: modelData.gemSummary && modelData.gemSummary.length > 0
                                                    text: modelData.gemSummary
                                                    color: colors.amber
                                                    font.pixelSize: 9
                                                    Layout.preferredWidth: 96
                                                }
                                                LabelText {
                                                    visible: modelData.exp > 0
                                                    text: (modelData.cexp || 0).toLocaleString() + " / " + (modelData.exp || 0).toLocaleString() + " XP"
                                                    color: colors.muted
                                                    font.pixelSize: 9
                                                    font.family: "Cascadia Mono, Consolas, monospace"
                                                    Layout.preferredWidth: 130
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                ProgressBar {
                                                    visible: modelData.exp > 0
                                                    Layout.fillWidth: true
                                                    Layout.preferredHeight: 5
                                                    animated: false
                                                    value: root.gemProgress(modelData.cexp, modelData.exp)
                                                    barColor: colors.amber
                                                }
                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming"
                                                    text: {
                                                        timerTick.tick
                                                        var start = root.accountStartTimes[modelData.device]
                                                        if (!start) return ""
                                                        var elapsed = Math.floor((Date.now() - start) / 1000)
                                                        var h = Math.floor(elapsed / 3600)
                                                        var m = Math.floor((elapsed % 3600) / 60)
                                                        var s = elapsed % 60
                                                        return (h > 0 ? h + ":" : "") + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
                                                    }
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0'''

acc_gem_removal_new = '''                                                LabelText {
                                                    visible: modelData.exp > 0
                                                    text: (modelData.cexp || 0).toLocaleString() + " / " + (modelData.exp || 0).toLocaleString() + " XP"
                                                    color: colors.muted
                                                    font.pixelSize: 9
                                                    font.family: "Cascadia Mono, Consolas, monospace"
                                                    Layout.preferredWidth: 130
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                ProgressBar {
                                                    visible: modelData.exp > 0
                                                    Layout.fillWidth: true
                                                    Layout.preferredHeight: 5
                                                    animated: false
                                                    value: root.gemProgress(modelData.cexp, modelData.exp)
                                                    barColor: colors.amber
                                                }
                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming"
                                                    text: {
                                                        timerTick.tick
                                                        var start = root.accountStartTimes[modelData.device]
                                                        if (!start) return ""
                                                        var elapsed = Math.floor((Date.now() - start) / 1000)
                                                        var h = Math.floor(elapsed / 3600)
                                                        var m = Math.floor((elapsed % 3600) / 60)
                                                        var s = elapsed % 60
                                                        return (h > 0 ? h + ":" : "") + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
                                                    }
                                                    Layout.preferredWidth: 62
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccount(index)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                LabelText { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0'''

if acc_gem_removal_context in content:
    content = content.replace(acc_gem_removal_context, acc_gem_removal_new)
    changes_made.append("CHANGE 5: GemSprite + gemSummary removed from Accounts page delegate")
else:
    changes_made.append("CHANGE 5: WARNING - pattern not found!")

# ============================================================
# Write the modified file
# ============================================================
f = open('qml/Main.qml', 'w', encoding='utf-8', newline='\n')
f.write(content)
f.close()

print("=" * 60)
print("CHANGES APPLIED:")
print("=" * 60)
for c in changes_made:
    print(f"  ✅ {c}")
print(f"\nTotal: {len(changes_made)} changes")
print(f"File size: {len(content)} bytes")
