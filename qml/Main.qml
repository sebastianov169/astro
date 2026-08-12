import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import QtQuick.Window

ApplicationWindow {
    id: root
    width: 1440
    height: 900
    minimumWidth: 1100
    minimumHeight: 700
    visible: true
    title: "Astro"
    color: colors.canvas

    property int page: 0
    property bool priorityOpen: false
    // estado del click-to-swap del priority (gema seleccionada)
    property bool priorityDragActive: false
    property int priorityDragStart: -1
    property bool prioritySortOpen: false
    property bool shopOpen: false
    property bool qwsOpen: false
    property bool showToast: false
    property string toastText: ""
    property string currentTheme: savedTheme || "midnight"
    property var accountStartTimes: ({})
    // Auto-follow del log de Activity: true = el log se mantiene pegado al
    // final al llegar lineas nuevas. Se apaga cuando el usuario hace scroll
    // hacia arriba (leer historial) y se re-activa al volver al fondo. Con 9
    // farms escribiendo a la vez, forzar contentY en CADA linea (2000+ lineas)
    // relayoutizaba el TextEdit sin parar y congelaba la UI.
    property bool stickToBottom: true
    readonly property var themeDefs: ({
        midnight: { canvas:"#0a080a",surface:"#120e11",surface2:"#1a1318",surface3:"#251a21",border:"#49313a",borderSoft:"#2e2027",text:"#f5efe6",muted:"#aa9690",faint:"#6c555f",mint:"#c9a45c",red:"#b52c4c",amber:"#e0b65d",blue:"#a981ff",wine:"#5d172c",pri1:"#d24b67",pri2:"#7f1835",priH1:"#e05a76",priH2:"#a02a4a",priD1:"#8f1d3f",priD2:"#6b1230",priBdr:"#d05a72" },
        ocean:  { canvas:"#081018",surface:"#0d1825",surface2:"#132840",surface3:"#1a3550",border:"#2a5a8a",borderSoft:"#1a3a5a",text:"#e0f0ff",muted:"#7a9ab8",faint:"#4a6a8a",mint:"#40d8b0",red:"#ff5a6e",amber:"#40d8ff",blue:"#60e0ff",wine:"#1a2840",pri1:"#30c8e8",pri2:"#1080c8",priH1:"#50d8ff",priH2:"#20a0d8",priD1:"#20a0c0",priD2:"#0868a8",priBdr:"#40c0e0" },
        neon:   { canvas:"#0a080f",surface:"#120e18",surface2:"#1a1325",surface3:"#251a35",border:"#49315a",borderSoft:"#2e2040",text:"#f0e8ff",muted:"#aa90b0",faint:"#6c5580",mint:"#40f0a0",red:"#ff3080",amber:"#f0d030",blue:"#40c0ff",wine:"#401040",pri1:"#ff40a0",pri2:"#c02080",priH1:"#ff60c0",priH2:"#d03090",priD1:"#d02080",priD2:"#a01060",priBdr:"#ff50b0" },
        forest: { canvas:"#0a0e08",surface:"#101808",surface2:"#182210",surface3:"#203018",border:"#3a5020",borderSoft:"#2a3a18",text:"#e8f5e0",muted:"#8aaa80",faint:"#5a7a50",mint:"#80d040",red:"#e07050",amber:"#d0b030",blue:"#60d8a0",wine:"#1a3010",pri1:"#50b040",pri2:"#207020",priH1:"#60d050",priH2:"#288028",priD1:"#409030",priD2:"#186018",priBdr:"#50c040" },
        sunset: { canvas:"#100808",surface:"#1a0e0c",surface2:"#241614",surface3:"#301e1a",border:"#6a3828",borderSoft:"#4a2818",text:"#fff0e8",muted:"#b09080",faint:"#806050",mint:"#f0a040",red:"#e04840",amber:"#f0c040",blue:"#f08040",wine:"#401810",pri1:"#ff8030",pri2:"#c04a18",priH1:"#ffa050",priH2:"#d06020",priD1:"#d05518",priD2:"#a03808",priBdr:"#ff9040" },
        dark:   { canvas:"#060606",surface:"#0e0e0e",surface2:"#151515",surface3:"#1c1c1c",border:"#252525",borderSoft:"#1a1a1a",text:"#c8c8c8",muted:"#555555",faint:"#333333",mint:"#d4a520",red:"#cc3333",amber:"#d4a520",blue:"#4080ff",wine:"#220808",pri1:"#1a1a1a",pri2:"#0e0e0e",priH1:"#282828",priH2:"#1a1a1a",priD1:"#0a0a0a",priD2:"#060606",priBdr:"#d4a520" },
    })
    readonly property var t: themeDefs[currentTheme]

    QtObject {
        id: colors
        property color canvas: root.t.canvas
        property color surface: root.t.surface
        property color surface2: root.t.surface2
        property color surface3: root.t.surface3
        property color border: root.t.border
        property color borderSoft: root.t.borderSoft
        property color text: root.t.text
        property color muted: root.t.muted
        property color faint: root.t.faint
        property color mint: root.t.mint
        property color red: root.t.red
        property color amber: root.t.amber
        property color blue: root.t.blue
        property color wine: root.t.wine
        property color pri1: root.t.pri1
        property color pri2: root.t.pri2
        property color priH1: root.t.priH1
        property color priH2: root.t.priH2
        property color priD1: root.t.priD1
        property color priD2: root.t.priD2
        property color priBdr: root.t.priBdr
    }
    ListModel { id: logModel }
    ListModel { id: debugModel }
    ListModel { id: gemsQmlModel }
    ListModel { id: priorityQmlModel }

    function startQwsLoad(paths) {
        farm.loadQwsFiles(paths)
    }

    function syncGems() {
        gemsQmlModel.clear()
        var list = farm.gems
        for (var i = 0; i < list.length; i++) {
            var g = list[i]
            gemsQmlModel.append({
                id: g.id, name: g.name, label: g.name + "  ·  Nv " + g.level,
                color: g.color, level: g.level, sprite: g.sprite,
                exp: g.exp, cexp: g.cexp, durability: g.durability,
                maxDurability: g.maxDurability
            })
        }
    }

    function syncPriority() {
        priorityQmlModel.clear()
        var list = farm.priorityGems()
        for (var i = 0; i < list.length; i++) {
            var g = list[i]
            priorityQmlModel.append({
                id: g.id, name: g.name, sprite: g.sprite,
                level: g.level, account: g.account !== undefined ? g.account : ""
            })
        }
    }

    function gemProgress(cexp, exp) {
        if (!exp || exp <= 0) return 0
        return Math.min(1, Math.max(0, cexp / exp))
    }

    function timeAgo(ts) {
        if (!ts || ts <= 0) return ""
        var s = Math.floor(Date.now() / 1000 - ts)
        if (s < 0) return "just now"
        if (s < 60) return s + "s ago"
        if (s < 3600) return Math.floor(s / 60) + "m ago"
        if (s < 86400) return Math.floor(s / 3600) + "h ago"
        return Math.floor(s / 86400) + "d ago"
    }

    // Monedas de la cuenta activa (device === farm.deviceId). Se re-evalua
    // automaticamente cuando farm.accounts/deviceId cambian (accountsChanged).
    function currentAccountCoins() {
        var list = farm.accounts
        for (var i = 0; i < list.length; i++)
            if (list[i].device === farm.deviceId && list[i].coins > 0)
                return list[i].coins
        return 0
    }

    // Indice de la cuenta activa (device === farm.deviceId) para el selector.
    // Devuelve -1 si la cuenta activa no esta en farm.accounts.
    function activeAccountIndex() {
        var list = farm.accounts
        for (var i = 0; i < list.length; i++)
            if (list[i].device === farm.deviceId)
                return i
        return -1
    }

    // Sprite de la gema EQUIPADA de la cuenta activa (la que se va a farmear).
    function activeAccountSprite() {
        var list = farm.accounts
        for (var i = 0; i < list.length; i++)
            if (list[i].device === farm.deviceId && list[i].sprite)
                return list[i].sprite
        return ""
    }

    // Resumen de las gemas equipadas de TODAS las cuentas seleccionadas para
    // farmear (farm.farmSelection = devices). Por cada device busca la cuenta
    // en farm.accounts y junta su gemSummary con " · ". Sin seleccion cae a la
    // gema de la cuenta activa (selectedGemName).
    function farmTargetGems() {
        var sel = farm.farmSelection
        if (!sel || sel.length === 0)
            return farm.selectedGemName.length > 0 ? farm.selectedGemName : "—"
        var parts = []
        var accs = farm.accounts
        for (var i = 0; i < sel.length; i++) {
            var dev = sel[i]
            for (var j = 0; j < accs.length; j++) {
                if (accs[j].device === dev && accs[j].gemSummary) {
                    parts.push(accs[j].gemSummary)
                    break
                }
            }
        }
        return parts.length > 0 ? parts.join(" · ") : "—"
    }

    // Texto formateado del log (legacy — ListView lee directo del model).
    function buildLogText() { return "" }

    function toast(message) {
        root.toastText = message
        showToast = true
        toastTimer.restart()
    }

    // Cuentas en espera del FARMEO: solo las del workflow (workflowAccounts,
    // las seleccionadas con casilla / con farm activo), no TODAS las guardadas.
    // Bug 2026-08-08: contaba sobre farm.accounts (todas las guardadas) y los
    // status stale (p.ej. "Refreshing" de un refreshAll previo) inflaban el
    // contador -> "WAITING 10" con 8 cuentas mandadas a farmear.
    function waitingAccounts() {
        var list = farm.workflowAccounts
        if (list.length === 0)
            list = farm.activeSessions
        var n = 0
        for (var i = 0; i < list.length; i++) {
            var st = list[i].farmStatus
            if (st && st !== "Farming" && st !== "Idle" && st !== "")
                n++
        }
        return n
    }

    // Fallos detectados en el log de Activity: lineas que contienen
    // "fail"/"error" (case-insensitive). Derivado de logModel, no del backend.
    function countFailures() {
        var n = 0
        for (var i = 0; i < logModel.count; i++) {
            var low = logModel.get(i).line.toLowerCase()
            if (low.indexOf("fail") >= 0 || low.indexOf("error") >= 0)
                n++
        }
        return n
    }

    Timer { id: toastTimer; interval: 2400; onTriggered: root.showToast = false }
    Timer { id: timerTick; interval: 1000; running: true; repeat: true; property int tick: 0; onTriggered: tick++ }

    Component.onCompleted: {
        var t = farm.theme()
        if (t)
            root.currentTheme = t
    }

    Connections {
        target: farm
        function onLogLineAdded(line) {
            if (line.length > 0) {
                var ts = new Date().toTimeString().slice(0, 8)
                logModel.append({ line: line, time: ts })
            }
            if (logModel.count > 2000)
                logModel.remove(0, logModel.count - 2000)
        }
        function onDebugLineAdded(line) {
            if (line.length > 0) {
                debugModel.append({ line: line })
                var ts = new Date().toTimeString().slice(0, 8)
                logModel.append({ line: line, time: ts })
            }
            if (debugModel.count > 2000)
                debugModel.remove(0, debugModel.count - 2000)
            if (logModel.count > 2000)
                logModel.remove(0, logModel.count - 2000)
        }
        function onToastMessage(msg) { root.toast(msg) }
        function onGemsChanged() { root.syncGems() }
        function onGemPriorityChanged() { root.syncPriority() }
        function onQwsLoadingChanged() {
            if (!farm.qwsLoading && root.qwsOpen)
                root.qwsOpen = false
        }
        function onAccountsChanged() {
            root.syncPriority()
            // sincroniza accountStartTimes con el farmStatus real de cada
            // cuenta (el Connections { target: null } dentro de los delegates
            // nunca se disparaba, asi que el timer de duracion del farm no
            // aparecia). accountsChanged se emite en C++ cada vez que cambia
            // el status de un farm (onFarmState/onFarmXp/onFarmFinished).
            var accs = farm.accounts
            var start = root.accountStartTimes
            var changed = false
            for (var i = 0; i < accs.length; i++) {
                var dev = accs[i].device
                if (accs[i].farmStatus === "Farming" && !start[dev]) {
                    start = Object.assign({}, start, {[dev]: Date.now()})
                    changed = true
                } else if ((accs[i].farmStatus === "Idle" || accs[i].farmStatus === "") && start[dev]) {
                    // Solo se limpia cuando la cuenta para DE VERDAD (Idle/vacio).
                    // Estados intermedios (Refreshing/Connecting/Respawning) NO
                    // reinician el timer: el refresh marca "Refreshing" mientras
                    // corre y el farm sigue contando desde el mismo inicio.
                    var copy = Object.assign({}, start)
                    delete copy[dev]
                    start = copy
                    changed = true
                }
            }
            if (changed)
                root.accountStartTimes = start
        }
    }

    component LabelText: Label {
        color: colors.text
        font.family: "Bahnschrift"
        font.pixelSize: 13
        elide: Text.ElideRight
    }

    component SmallCaption: Label {
        color: colors.muted
        font.family: "Bahnschrift"
        font.pixelSize: 10
        font.weight: Font.DemiBold
        font.letterSpacing: 0.7
        elide: Text.ElideRight
    }

    component PrimaryButton: Button {
        id: button
        implicitHeight: 44
        leftPadding: 24
        rightPadding: 24
        // 2026-08-10 (pedido del usuario): cuando el farm esta corriendo, el
        // boton RUN se pinta de VERDE (gradiente mint) en vez del amarillo
        // default. El boton queda deshabilitado mientras corre, pero el color
        // verde + texto "RUNNING" dan el feedback visual pedido.
        property bool runningState: false
        // micro-interaccion: presion sutil
        scale: button.down ? 0.98 : 1.0
        Behavior on scale { NumberAnimation { duration: 90; easing.type: Easing.OutQuad } }
        contentItem: LabelText {
            text: button.text
            color: button.enabled ? "#ffffff" : colors.faint
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            font.pixelSize: 14
            font.weight: Font.Bold
        }
        background: Item {
            anchors.fill: parent
            Rectangle {
                anchors.fill: grad
                anchors.topMargin: 2
                anchors.leftMargin: 1
                radius: grad.radius + 1
                color: "black"
                opacity: 0.22
            }
            Rectangle {
                id: grad
                anchors.fill: parent
                radius: 10
                gradient: Gradient {
                    orientation: Gradient.Horizontal
                    GradientStop { position: 0.0; color: button.runningState ? (button.down ? Qt.darker(colors.mint, 1.3) : (button.hovered ? Qt.lighter(colors.mint, 1.15) : colors.mint)) : (button.down ? colors.priD1 : (button.hovered ? colors.priH1 : colors.pri1)) }
                    GradientStop { position: 1.0; color: button.runningState ? (button.down ? Qt.darker(colors.mint, 1.5) : (button.hovered ? Qt.lighter(colors.mint, 1.05) : Qt.darker(colors.mint, 1.15))) : (button.down ? colors.priD2 : (button.hovered ? colors.priH2 : colors.pri2)) }
                }
                border.color: button.runningState ? Qt.lighter(colors.mint, 1.4) : (button.hovered ? colors.priBdr : Qt.lighter(colors.pri1, 1.3))
                border.width: 1
            }
        }
    }

    component GhostButton: Button {
        id: button
        implicitHeight: 40
        leftPadding: 18
        rightPadding: 18
        // micro-interaccion: presion sutil
        scale: button.down ? 0.98 : 1.0
        Behavior on scale { NumberAnimation { duration: 90; easing.type: Easing.OutQuad } }
        contentItem: LabelText {
            text: button.text
            color: button.hovered ? colors.text : colors.muted
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            font.pixelSize: 15
            font.weight: Font.Bold
        }
        background: Rectangle {
            radius: 8
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.0; color: button.hovered ? colors.surface3 : colors.surface2 }
                GradientStop { position: 1.0; color: button.hovered ? colors.surface2 : colors.surface }
            }
            border.color: button.hovered ? colors.priBdr : colors.border
            border.width: 1
        }
    }

    component ArrowButton: Button {
        id: arrowBtn
        property string arrow: "\u25B2"
        implicitWidth: 34
        implicitHeight: 30
        contentItem: LabelText {
            text: arrowBtn.arrow
            color: arrowBtn.enabled ? (arrowBtn.hovered ? colors.text : colors.muted) : colors.faint
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
            font.pixelSize: 16
            font.weight: Font.Bold
        }
        background: Rectangle {
            radius: 6
            color: arrowBtn.hovered ? colors.surface3 : colors.surface2
            border.color: arrowBtn.enabled ? (arrowBtn.hovered ? colors.priBdr : colors.border) : "transparent"
            border.width: 1
        }
    }

    component StatusPill: Rectangle {
        id: pill
        property string value: "LIVE"
        property color accent: colors.mint
        implicitWidth: pillLabel.implicitWidth + 26
        implicitHeight: 26
        radius: 13
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.rgba(pill.accent.r, pill.accent.g, pill.accent.b, 0.06) }
            GradientStop { position: 1.0; color: Qt.rgba(pill.accent.r, pill.accent.g, pill.accent.b, 0.17) }
        }
        border.color: Qt.rgba(accent.r, accent.g, accent.b, 0.55)
        border.width: 1
        Rectangle {
            anchors.fill: parent
            radius: 13
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(pill.accent.r, pill.accent.g, pill.accent.b, 0.14) }
                GradientStop { position: 0.6; color: Qt.rgba(pill.accent.r, pill.accent.g, pill.accent.b, 0.03) }
                GradientStop { position: 1.0; color: "#00000000" }
            }
        }
        LabelText {
            id: pillLabel
            anchors.centerIn: parent
            text: pill.value
            // El pill nunca debe elidir: el badge del footer (LIVE/IDLE) se
            // cortaba a "IDE" porque LabelText hereda elide: ElideRight.
            elide: Text.ElideNone
            color: pill.accent
            font.pixelSize: 10
            font.weight: Font.DemiBold
        }
    }

    component GemSprite: Image {
        id: gemSprite
        property string sprite: ""
        property color gemColor: "#984bde"
        property int iconSize: 28
        property int spriteColumn: 1
        width: iconSize
        height: iconSize
        source: gemSprite.sprite.length > 0 ? gemSprite.sprite : "qrc:/Astro/assets/gems-sprite.png"
        sourceClipRect: gemSprite.sprite.length > 0 ? undefined
                       : Qt.rect(16 + gemSprite.spriteColumn * 42, 17 + 0 * 43, 40, 40)
        fillMode: Image.PreserveAspectFit
        smooth: true
        mipmap: true
    }

    component Panel: Rectangle {
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.35) }
            GradientStop { position: 0.45; color: colors.surface }
            GradientStop { position: 1.0; color: Qt.darker(colors.surface, 1.1) }
        }
        border.color: colors.border
        border.width: 1
        radius: 4
    }

    component ProgressBar: Item {
        id: progress
        property real value: 0.5
        property bool animated: true
        property color barColor: colors.red
        implicitHeight: 8
        implicitWidth: 120
        Rectangle {
            anchors.fill: parent
            radius: 4
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.darker(colors.canvas, 1.3) }
                GradientStop { position: 1.0; color: Qt.lighter(colors.canvas, 1.35) }
            }
            border.color: colors.borderSoft
        }
        Rectangle {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            radius: 4
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(progress.barColor, 1.45) }
                GradientStop { position: 1.0; color: progress.barColor }
            }
            width: fillWidthAnim.value
        }
        Item {
            id: fillWidthAnim
            property real value: Math.min(1, Math.max(0, progress.value)) * progress.width
            Behavior on value {
                enabled: progress.animated
                NumberAnimation { duration: 300; easing.type: Easing.OutQuad }
            }
        }
    }

    component Field: Rectangle {
        id: field
        property alias text: fieldInput.text
        signal accepted(string value)
        height: 38
        radius: 5
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.darker(colors.canvas, 1.1) }
            GradientStop { position: 1.0; color: colors.canvas }
        }
        border.color: fieldInput.activeFocus ? colors.amber : colors.border
        border.width: 1
        Rectangle {
            visible: fieldInput.activeFocus
            anchors.fill: parent
            radius: 5
            color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.08)
        }
        TextField {
            id: fieldInput
            anchors.fill: parent
            anchors.leftMargin: 12
            anchors.rightMargin: 12
            color: colors.text
            font.family: "Bahnschrift"
            font.pixelSize: 12
            background: Item {}
            padding: 0
            verticalAlignment: Text.AlignVCenter
            selectByMouse: true
            onEditingFinished: field.accepted(text)
        }
    }

    component SectionAccent: Rectangle {
        implicitWidth: 3
        implicitHeight: 16
        radius: 1.5
        gradient: Gradient {
            GradientStop { position: 0.0; color: colors.pri1 }
            GradientStop { position: 1.0; color: colors.amber }
        }
    }

    // Campo de texto estilizado compartido (reemplaza los TextField sueltos).
    component AppField: Rectangle {
        id: appField
        property alias text: appInput.text
        property alias placeholderText: appInput.placeholderText
        property alias inputMethodHints: appInput.inputMethodHints
        signal textEdited(string text)
        signal editingFinished()
        height: 30
        radius: 5
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.darker(colors.canvas, 1.1) }
            GradientStop { position: 1.0; color: colors.canvas }
        }
        border.color: appInput.activeFocus ? colors.amber : colors.border
        border.width: 1
        Rectangle {
            visible: appInput.activeFocus
            anchors.fill: parent
            radius: 5
            color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.08)
        }
        TextField {
            id: appInput
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 10
            color: colors.text
            font.family: "Bahnschrift"
            font.pixelSize: 11
            placeholderTextColor: colors.faint
            background: Item {}
            padding: 0
            verticalAlignment: Text.AlignVCenter
            selectByMouse: true
            onTextEdited: appField.textEdited(text)
            onEditingFinished: appField.editingFinished()
        }
    }

    // Cabecera de seccion: caption en mayusculas + linea de separacion.
    component SectionHeader: RowLayout {
        id: sectionHeader
        property string title: ""
        Layout.fillWidth: true
        spacing: 8
        SmallCaption {
            text: sectionHeader.title.toUpperCase()
            Layout.fillWidth: false
        }
        Rectangle {
            Layout.fillWidth: true
            Layout.topMargin: 2
            height: 1
            color: colors.borderSoft
        }
    }

    // Estado vacio con glifo.
    component EmptyState: ColumnLayout {
        id: emptyState
        property string icon: "\u25c7"
        property string text: ""
        Layout.alignment: Qt.AlignHCenter
        Layout.topMargin: 12
        spacing: 3
        LabelText {
            text: emptyState.icon
            color: colors.faint
            font.pixelSize: 15
            Layout.alignment: Qt.AlignHCenter
        }
        LabelText {
            text: emptyState.text
            color: colors.faint
            font.pixelSize: 11
            Layout.alignment: Qt.AlignHCenter
        }
    }

    // Scrollbar delgado con handle visible del theme.
    component ThemedScrollBar: ScrollBar {
        policy: ScrollBar.AsNeeded
        contentItem: Rectangle {
            implicitWidth: 6
            implicitHeight: 6
            radius: 3
            color: colors.faint
            opacity: 0.55
        }
    }

    Rectangle {
        anchors.fill: parent
        gradient: Gradient {
            GradientStop { position: 0.0; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.16) }
            GradientStop { position: 0.32; color: Qt.lighter(colors.surface, 1.25) }
            GradientStop { position: 0.72; color: colors.surface }
            GradientStop { position: 1.0; color: Qt.darker(colors.canvas, 1.05) }
        }

        // bandas laterales sutiles (estilo "after dark", adaptado al theme)
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                orientation: Gradient.Horizontal
                GradientStop { position: 0.0; color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.05) }
                GradientStop { position: 0.5; color: "#00000000" }
                GradientStop { position: 1.0; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.08) }
            }
            z: 0
        }

        // glow cenital rojo/ambar (radial simulado con rects apilados)
        Rectangle {
            anchors.top: parent.top
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.82
            height: parent.height * 0.42
            radius: parent.height * 0.24
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.17) }
                GradientStop { position: 0.55; color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.08) }
                GradientStop { position: 1.0; color: "#00000000" }
            }
            opacity: 0.9
            z: 1
        }
        Rectangle {
            anchors.top: parent.top
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width * 0.5
            height: parent.height * 0.24
            radius: parent.height * 0.14
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.2) }
                GradientStop { position: 1.0; color: "#00000000" }
            }
            opacity: 0.8
            z: 1
        }

        // vineta oscura para legibilidad
        Rectangle {
            anchors.fill: parent
            gradient: Gradient {
                GradientStop { position: 0.0; color: "#8a0a080a" }
                GradientStop { position: 0.55; color: "#520a080a" }
                GradientStop { position: 1.0; color: "#d60a080a" }
            }
            z: 1
        }

        RowLayout {
            anchors.fill: parent
            spacing: 0
            z: 2

            Rectangle {
                Layout.preferredWidth: 228
                Layout.fillHeight: true
                gradient: Gradient {
                    GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.1) }
                    GradientStop { position: 0.55; color: colors.surface }
                    GradientStop { position: 1.0; color: Qt.darker(colors.canvas, 1.1) }
                }
                border.color: colors.borderSoft
                border.width: 1

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 18
                    spacing: 0

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 9
                        LabelText { text: "+"; color: colors.amber; font.pixelSize: 34; font.bold: true }
                        LabelText { text: "ASTRO"; color: colors.text; font.pixelSize: 30; font.weight: Font.Black; font.letterSpacing: 2.4 }
                    }
                    LabelText { text: "Gem Farmer"; color: colors.amber; font.pixelSize: 10; font.letterSpacing: 1.5; Layout.topMargin: 4 }
                    Rectangle {
                        Layout.fillWidth: true
                        Layout.topMargin: 4
                        height: 2
                        radius: 1
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.5) }
                            GradientStop { position: 0.4; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.5) }
                            GradientStop { position: 1.0; color: "#00000000" }
                        }
                    }

                    Item { Layout.preferredHeight: 40 }

                    Panel {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 116
                        clip: true
                        border.color: Qt.lighter(colors.border, 1.25)
                        Image {
                            anchors.fill: parent
                            source: "qrc:/Astro/assets/visuals/trap-lounge.png"
                            fillMode: Image.PreserveAspectCrop
                            horizontalAlignment: Image.AlignHCenter
                            opacity: 0.48
                        }
                        Rectangle { anchors.fill: parent; gradient: Gradient { GradientStop { position: 0.35; color: "#600a080a" } GradientStop { position: 1.0; color: "#e60a080a" } } }
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 4
                            Item { Layout.fillHeight: true }
                            LabelText { text: "AFTER DARK"; color: colors.amber; font.pixelSize: 9; font.weight: Font.Black; font.letterSpacing: 1.4 }
                            LabelText { text: "ASTRO NIGHT SHIFT"; font.pixelSize: 12; font.weight: Font.Black; font.letterSpacing: 0.8 }
                            SmallCaption { text: "Quiet money. Loud results."; color: colors.text }
                        }
                    }

                    Repeater {
                        model: [
                            { icon: "\u25c8", label: "Dashboard" },
                            { icon: "\u25a4", label: "Accounts" },
                            { icon: "\u2263", label: "Activity" }
                        ]
                        delegate: Rectangle {
                            id: navItem
                            Layout.fillWidth: true
                            Layout.preferredHeight: 46
                            radius: 5
                            color: root.page === index ? Qt.lighter(colors.surface, 1.2) : (navHover.containsMouse ? colors.surface3 : "transparent")
                            border.color: root.page === index ? colors.priBdr : "transparent"
                            border.width: 1
                            Behavior on color { ColorAnimation { duration: 120 } }
                            // barra de acento del item activo
                            Rectangle {
                                visible: root.page === index
                                anchors.left: parent.left
                                anchors.top: parent.top
                                anchors.bottom: parent.bottom
                                anchors.topMargin: 9
                                anchors.bottomMargin: 9
                                width: 3
                                radius: 1.5
                                gradient: Gradient {
                                    GradientStop { position: 0.0; color: colors.pri1 }
                                    GradientStop { position: 1.0; color: colors.amber }
                                }
                            }
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 14
                                anchors.rightMargin: 10
                                spacing: 12
                                LabelText { text: modelData.icon; color: root.page === index ? colors.pri1 : colors.muted; font.pixelSize: 13; Layout.preferredWidth: 28 }
                                LabelText { text: modelData.label; color: root.page === index ? colors.text : colors.muted; font.pixelSize: 13; font.weight: root.page === index ? Font.DemiBold : Font.Normal; Layout.fillWidth: true }
                                Rectangle { visible: root.page === index; width: 5; height: 5; radius: 2.5; color: colors.red }
                            }
                            MouseArea {
                                id: navHover
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: root.page = index
                            }
                        }
                    }

                    Item { Layout.fillHeight: true }

                    Panel {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 60
                        color: colors.surface2
                        ColumnLayout {
                            anchors.fill: parent; anchors.margins: 12; spacing: 2
                            RowLayout { Layout.fillWidth: true; spacing: 6
                                LabelText { text: "ASTRO"; color: colors.mint; font.pixelSize: 14; font.weight: Font.Black; font.letterSpacing: 2; Layout.fillWidth: true }
                                StatusPill {
                                    value: farm.farmRunning ? "LIVE" : "IDLE"
                                    accent: farm.farmRunning ? colors.mint : colors.faint
                                    implicitHeight: 18
                                    radius: 9
                                }
                            }
                            LabelText { text: "v1.0 · by Ren"; color: colors.faint; font.pixelSize: 10 }
                        }
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 84
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.2) }
                        GradientStop { position: 1.0; color: colors.surface }
                    }
                    border.color: colors.borderSoft
                    border.width: 1
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: 1
                        gradient: Gradient {
                            GradientStop { position: 0.0; color: "#00000000" }
                            GradientStop { position: 0.5; color: Qt.rgba(colors.priBdr.r, colors.priBdr.g, colors.priBdr.b, 0.45) }
                            GradientStop { position: 1.0; color: "#00000000" }
                        }
                    }
                    RowLayout {
                        anchors.fill: parent
                        anchors.leftMargin: 26
                        anchors.rightMargin: 26
                        spacing: 18
                        ColumnLayout { spacing: 4; Layout.preferredWidth: 430
                            LabelText { text: page === 0 ? "Night Dashboard" : page === 1 ? "Accounts" : "Activity"; font.pixelSize: 22; font.weight: Font.Black; font.letterSpacing: 0.5; elide: Text.ElideRight }
                            LabelText { text: page === 0 ? "After-dark gem farm operations" : page === 1 ? "Gem inventory and farm loadout" : "Persistent chronological event history"; color: colors.muted; font.pixelSize: 11; elide: Text.ElideRight }
                        }
                        Item { Layout.fillWidth: true }
                        RowLayout { spacing: 10
                            SmallCaption { text: "THEME"; Layout.preferredWidth: 38 }
                            Repeater {
                                model: ["midnight", "ocean", "neon", "forest", "sunset", "dark"]
                                Rectangle {
                                    width: 22; height: 22; radius: 11
                                    gradient: Gradient { orientation: Gradient.Horizontal
                                        GradientStop { position: 0.0; color: root.themeDefs[modelData].pri1 }
                                        GradientStop { position: 1.0; color: root.themeDefs[modelData].pri2 }
                                    }
                                    border.color: root.currentTheme === modelData ? colors.text : Qt.rgba(colors.text.r, colors.text.g, colors.text.b, 0.15)
                                    border.width: 2
                                    Behavior on border.color { ColorAnimation { duration: 150 } }
                                    ToolTip.visible: themeDotHover.hovered
                                    ToolTip.text: modelData
                                    ToolTip.delay: 300
                                    MouseArea {
                                        id: themeDotHover
                                        anchors.fill: parent
                                        cursorShape: Qt.PointingHandCursor
                                        onClicked: { root.currentTheme = modelData; farm.saveTheme(modelData) }
                                    }
                                }
                            }
                        }
                        RowLayout { spacing: 14
                            StatusPill {
                                value: farm.farmRunning ? "RUNNING" : "READY"
                                accent: farm.farmRunning ? colors.mint : colors.muted
                                ToolTip.visible: runPillHover.hovered
                                ToolTip.text: farm.farmRunning ? "Farm activo: " + farm.activeSessions.length + " sesiones" : "Listo — pulsa RUN para arrancar el farm"
                                ToolTip.delay: 400
                                HoverHandler { id: runPillHover }
                            }
                            PrimaryButton {
                                text: farm.farmRunning ? "RUNNING" : (farm.spawning ? "STARTING..." : "RUN")
                                Layout.preferredWidth: 150
                                // farm.spawning cubre la ventana del pre-spawn
                                // (logins ~16-25s): sin esto un 2do clic duplicaba
                                // todos los farms (bug 2026-08-08, 13 sesiones).
                                enabled: !farm.farmRunning && !farm.spawning
                                // 2026-08-10 (pedido del usuario): verde mientras
                                // corre (el emit post-start de spawnOneFarm hace
                                // que farmRunning llegue a la UI).
                                runningState: farm.farmRunning
                                onClicked: { farm.spawn(); root.toast("Farm started") }
                            }
                            GhostButton {
                                text: farm.fetching ? "Fetching..." : "Fetch gems"
                                Layout.preferredWidth: 132
                                Layout.minimumWidth: 132
                                enabled: !farm.fetching
                                onClicked: farm.fetchGems()
                            }
                            GhostButton {
                                text: "STOP"
                                Layout.preferredWidth: 150
                                // 2026-08-10: habilitado tambien durante el
                                // pre-spawn (spawning) y con sesiones activas:
                                // antes dependia SOLO de farm.farmRunning que no
                                // se emitia tras el start -> STOP muerto.
                                enabled: farm.farmRunning || farm.spawning || farm.activeSessions.length > 0
                                onClicked: { farm.stopFarm(); root.toast("Farm stopped") }
                            }
                        }
                    }
                }

                RowLayout {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 96
                    Layout.minimumHeight: 96
                    Layout.maximumHeight: 96
                    Layout.leftMargin: 26
                    Layout.rightMargin: 26
                    spacing: 0
                    Repeater {
                        model: [ {label: "ACTIVE SESSIONS", value: farm.activeSessions.length.toString(), color: colors.mint}, {label: "WAITING", value: root.waitingAccounts().toString(), color: colors.amber } ]
                        delegate: Item {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 96
                            Layout.minimumHeight: 96
                            Layout.maximumHeight: 96
                            Rectangle {
                                anchors.fill: parent
                                radius: 3
                                gradient: Gradient {
                                GradientStop { position: 0.0; color: tileHover.hovered ? Qt.lighter(colors.surface3, 1.1) : Qt.lighter(colors.surface, 1.2) }
                                GradientStop { position: 1.0; color: tileHover.hovered ? colors.surface2 : colors.surface }
                                }
                            }
                            Rectangle { anchors.right: parent.right; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 1; color: colors.borderSoft; visible: index < 2 }
                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 18
                                anchors.rightMargin: 18
                                anchors.topMargin: 14
                                spacing: 14
                                // mini-icono: circulo de color con el numero
                                // (quitado 2026-08-08: el usuario lo pidio, el
                                // numero ya esta grande a la derecha)
                                ColumnLayout { Layout.fillWidth: true; Layout.alignment: Qt.AlignVCenter; spacing: 4
                                    SmallCaption { text: modelData.label }
                                    LabelText {
                                        text: modelData.value
                                        color: modelData.color
                                        font.pixelSize: 22
                                        font.weight: Font.DemiBold
                                        Behavior on color { ColorAnimation { duration: 300 } }
                                    }
                                }
                            }
                            HoverHandler { id: tileHover }
                        }
                    }
                }

                StackLayout {
                    id: pages
                    currentIndex: root.page
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.minimumHeight: 0
                    clip: true

                    // Transicion entre paginas: al cambiar root.page la pagina
                    // entrante hace fade-in con un leve desplazamiento lateral.
                    property real pageOpacity: 1.0
                    property real pageShift: 0.0
                    onCurrentIndexChanged: {
                        pageOpacity = 0.0
                        pageShift = 14.0
                        pageFadeIn.restart()
                    }
                    ParallelAnimation {
                        id: pageFadeIn
                        NumberAnimation { target: pages; property: "pageOpacity"; to: 1.0; duration: 200; easing.type: Easing.OutCubic }
                        NumberAnimation { target: pages; property: "pageShift"; to: 0.0; duration: 220; easing.type: Easing.OutCubic }
                    }

                    // ================= Dashboard =================
                    RowLayout {
                        opacity: pages.pageOpacity
                        transform: Translate { x: pages.pageShift }
                        spacing: 14
                        Layout.margins: 26
                        Layout.topMargin: 18
                        Layout.bottomMargin: 26

                        // ----- panel izquierdo: control del farm -----
                        Panel {
                            Layout.preferredWidth: 250
                            Layout.fillHeight: true
                            clip: true
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 14; spacing: 10
                                RowLayout { Layout.fillWidth: true
                                    SectionAccent { }
                                    LabelText { text: "Farm Control"; font.pixelSize: 19; font.weight: Font.Bold; Layout.fillWidth: true }
                                    StatusPill { value: farm.farmRunning ? "FARMING" : "READY"; accent: farm.farmRunning ? colors.mint : colors.muted }
                                }

                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 8
                                    GemSprite {
                                        sprite: root.activeAccountSprite()
                                        iconSize: 30
                                        visible: root.activeAccountSprite().length > 0
                                    }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 2
                                        LabelText {
                                            id: targetGemsLabel
                                            text: root.farmTargetGems()
                                            color: colors.amber
                                            font.pixelSize: 11
                                            font.weight: Font.DemiBold
                                            Layout.fillWidth: true
                                            elide: Text.ElideRight
                                            ToolTip.visible: targetGemsHover.hovered && targetGemsLabel.truncated
                                            ToolTip.text: root.farmTargetGems()
                                            ToolTip.delay: 400
                                            HoverHandler { id: targetGemsHover }
                                        }
                                    }
                                }
                                GhostButton {
                                    text: "Stop"
                                    Layout.fillWidth: true
                                    enabled: farm.farmRunning
                                    onClicked: farm.stopFarm()
                                }

                                Rectangle { Layout.fillWidth: true; height: 1; color: colors.borderSoft }

                                SectionHeader { title: "REFRESH" }
                                GhostButton {
                                    text: "Refresh All"
                                    Layout.fillWidth: true
                                    enabled: !farm.refreshingAll && farm.accounts.length > 0
                                    onClicked: farm.refreshAllAccounts()
                                }
                                Rectangle {
                                    visible: farm.refreshingAll
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 30
                                    color: colors.canvas
                                    border.color: colors.borderSoft
                                    radius: 4
                                    RowLayout { anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8; spacing: 8
                                        ProgressBar { Layout.fillWidth: true; value: farm.refreshAllProgress / 100; barColor: colors.red }
                                        LabelText { text: farm.refreshAllStatus; color: colors.mint; font.pixelSize: 9 }
                                    }
                                }

                                SectionHeader { title: "AUTO REFRESH" }
                                RowLayout { Layout.fillWidth: true; spacing: 8
                                    AppField {
                                        id: autoRefreshSec
                                        Layout.fillWidth: true
                                        placeholderText: "600"
                                        text: String(farm.autoRefreshInterval)
                                        inputMethodHints: Qt.ImhDigitsOnly
                                        onEditingFinished: farm.configureAutoRefresh(autoRefreshSw.checked, parseInt(autoRefreshSec.text.length > 0 ? autoRefreshSec.text : "600"))
                                    }
                                    SmallCaption { text: "seconds" }
                                    Switch {
                                        id: autoRefreshSw
                                        // refleja el estado persistido (QSettings)
                                        checked: farm.autoRefreshEnabled
                                        onToggled: {
                                            if (checked && autoRefreshSec.text.length === 0)
                                                autoRefreshSec.text = "600"
                                            farm.configureAutoRefresh(checked, parseInt(autoRefreshSec.text.length > 0 ? autoRefreshSec.text : "600"))
                                        }
                                    }
                                }

                                SectionHeader { title: "AUTO RESPAWN" }
                                RowLayout { Layout.fillWidth: true; spacing: 8
                                    LabelText { text: "Auto respawn"; Layout.fillWidth: true }
                                    Switch {
                                        checked: farm.autoRespawn
                                        onToggled: farm.setAutoRespawn(checked)
                                    }
                                }

                                SectionHeader { title: "AUTO REPAIR" }
                                RowLayout { Layout.fillWidth: true; spacing: 8
                                    LabelText { text: "Auto repair gems"; Layout.fillWidth: true }
                                    Switch {
                                        checked: farm.autoRepair
                                        onToggled: farm.autoRepair = checked
                                    }
                                }

                                SectionHeader { title: "AUTO-BUY X2" }
                                RowLayout { Layout.fillWidth: true; spacing: 8
                                    LabelText { text: "Auto-buy x2 gems"; Layout.fillWidth: true }
                                    Switch {
                                        checked: farm.autoBuyX2
                                        onToggled: farm.autoBuyX2 = checked
                                    }
                                }


                                Item { Layout.fillHeight: true }
                            }
                        }

                        // ----- panel derecho: cuentas guardadas -----
                        Panel {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            clip: true
                            ColumnLayout {
                                anchors.fill: parent; anchors.margins: 14; spacing: 8
                                RowLayout { Layout.fillWidth: true
                                    SectionAccent { }
                                    LabelText { text: "Workflow"; font.pixelSize: 19; font.weight: Font.Bold; Layout.fillWidth: true }
                                    StatusPill { value: farm.farmSelection.length + " SELECTED"; accent: farm.farmSelection.length > 0 ? colors.amber : colors.faint }
                                }
                                ListView {
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    Layout.minimumHeight: 120
                                    clip: true
                                    spacing: 4
                                    // Solo cuentas SELECCIONADAS: la desmarcada
                                    // desaparece del dashboard al instante
                                    model: farm.workflowAccounts
                                    ScrollBar.vertical: ThemedScrollBar { }
                                    delegate: Rectangle {
                                        width: ListView.view.width
                                        height: 72
                                        radius: 5
                                        gradient: Gradient {
                                            GradientStop { position: 0.0; color: modelData.device === farm.deviceId ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.15) : colors.surface2 }
                                            GradientStop { position: 1.0; color: modelData.device === farm.deviceId ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.08) : colors.surface }
                                        }
                                        border.color: modelData.device === farm.deviceId ? colors.amber : colors.borderSoft
                                        border.width: 1
                                        // hover con fade suave
                                        Rectangle {
                                            anchors.fill: parent
                                            radius: 5
                                            color: Qt.lighter(colors.surface3, 1.05)
                                            opacity: accHover.hovered ? 0.4 : 0
                                            Behavior on opacity { NumberAnimation { duration: 140 } }
                                        }
                                        HoverHandler { id: accHover }
                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 10
                                            anchors.rightMargin: 10
                                            anchors.topMargin: 6
                                            anchors.bottomMargin: 6
                                            spacing: 4
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                LabelText {
                                                    text: modelData.favorite ? "★" : "☆"
                                                    color: modelData.favorite ? colors.amber : colors.faint
                                                    font.pixelSize: 14
                                                    Layout.preferredWidth: 18
                                                    MouseArea {
                                                        anchors.fill: parent
                                                        cursorShape: Qt.PointingHandCursor
                                                        z: 1
                                                        onClicked: farm.toggleFavorite(index)
                                                    }
                                                }
                                                LabelText {
                                                    text: modelData.name
                                                    font.pixelSize: 13
                                                    font.weight: Font.Bold
                                                    Layout.fillWidth: true
                                                    elide: Text.ElideRight
                                                }
                                                LabelText {
                                                    visible: modelData.xpGained !== undefined && modelData.xpGained > 0
                                                    text: "\u00a4 +" + (modelData.xpGained || 0).toFixed(1) + " XP"
                                                    color: "#50d39f"
                                                    font.pixelSize: 11
                                                    font.weight: Font.Bold
                                                    Layout.preferredWidth: 80
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                LabelText {
                                                    visible: modelData.farmStatus !== undefined && modelData.farmStatus.length > 0
                                                    text: modelData.farmStatus || ""
                                                    color: modelData.farmStatus === "Farming" ? "#50d39f" : (modelData.farmStatus === "Respawning" ? "#e04840" : (modelData.farmStatus === "Refreshing" ? "#4080ff" : (modelData.farmStatus === "Connecting" ? "#dcae4c" : colors.muted)))
                                                    font.pixelSize: 10
                                                    font.weight: Font.DemiBold
                                                    Layout.preferredWidth: 72
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                SmallCaption {
                                                    visible: modelData.farmStatus === "Farming" && modelData.startedAt > 0
                                                    text: {
                                                        timerTick.tick
                                                        var start = modelData.startedAt
                                                        if (!start) return ""
                                                        var elapsed = Math.floor((Date.now() - start) / 1000)
                                                        var h = Math.floor(elapsed / 3600)
                                                        var m = Math.floor((elapsed % 3600) / 60)
                                                        var s = elapsed % 60
                                                        return (h > 0 ? h + ":" : "") + (m < 10 ? "0" : "") + m + ":" + (s < 10 ? "0" : "") + s
                                                    }
                                                    color: colors.muted
                                                    font.pixelSize: 9
                                                    font.family: "Cascadia Mono, Consolas, monospace"
                                                }
                                                // 2026-08-10 (pedido del usuario: "cuando este el x2
                                                // salga verde, y cuando no haya rojo"): BINARIO —
                                                // verde SOLO si x2State==1 (comprado/ya activo
                                                // verificado), rojo en TODO lo demas (pendiente,
                                                // sin coins, fallo, auto-buy off). Tooltip con la
                                                // razon exacta.
                                                Rectangle {
                                                    visible: modelData.x2State !== undefined
                                                    Layout.preferredWidth: 42
                                                    Layout.preferredHeight: 18
                                                    radius: 4
                                                    color: modelData.x2State === 1 ? Qt.rgba(colors.mint.r, colors.mint.g, colors.mint.b, 0.18)
                                                         : Qt.rgba(colors.red.r, colors.red.g, colors.red.b, 0.20)
                                                    border.color: modelData.x2State === 1 ? colors.mint : colors.red
                                                    border.width: 1
                                                    LabelText {
                                                        anchors.centerIn: parent
                                                        text: modelData.x2State === 1 ? "x2 \u2713" : "x2 \u2717"
                                                        color: modelData.x2State === 1 ? colors.mint : colors.red
                                                        font.pixelSize: 8
                                                        font.weight: Font.Bold
                                                    }
                                                    ToolTip.visible: x2Hover.hovered
                                                    ToolTip.text: modelData.x2State === 1 ? ("x2 activo: " + (modelData.x2Reason || "comprado"))
                                                         : ("x2 NO activo: " + (modelData.x2Reason || "sin x2"))
                                                    ToolTip.delay: 300
                                                    HoverHandler { id: x2Hover }
                                                }
                                                Rectangle {
                                                    Layout.preferredWidth: 24
                                                    Layout.preferredHeight: 24
                                                    radius: 5
                                                    color: removeAreaDash.containsMouse ? Qt.rgba(colors.red.r, colors.red.g, colors.red.b, 0.35) : Qt.rgba(colors.red.r, colors.red.g, colors.red.b, 0.10)
                                                    Behavior on color { ColorAnimation { duration: 120 } }
                                                    LabelText {
                                                        anchors.centerIn: parent
                                                        text: "\u2715"
                                                        color: removeAreaDash.containsMouse ? "#ffffff" : colors.faint
                                                        font.pixelSize: 11
                                                        opacity: 0.85
                                                        Behavior on color { ColorAnimation { duration: 120 } }
                                                    }
                                                    MouseArea {
                                                        id: removeAreaDash
                                                        anchors.fill: parent
                                                        hoverEnabled: true
                                                        cursorShape: Qt.PointingHandCursor
                                                        z: 1
                                                        onClicked: farm.removeAccount(index)
                                                    }
                                                }
                                            }
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                GemSprite { sprite: modelData.sprite; iconSize: 28; Layout.preferredWidth: 28; Layout.preferredHeight: 28; visible: modelData.sprite !== undefined && modelData.sprite.length > 0 }
                                                LabelText {
                                                    id: gemSumLabel
                                                    visible: modelData.gemSummary !== undefined && modelData.gemSummary.length > 0
                                                    text: modelData.gemSummary
                                                    color: colors.amber
                                                    font.pixelSize: 9
                                                    Layout.preferredWidth: 96
                                                    elide: Text.ElideRight
                                                    ToolTip.visible: gemSumHover.hovered && gemSumLabel.truncated
                                                    ToolTip.text: modelData.gemSummary
                                                    ToolTip.delay: 400
                                                    HoverHandler { id: gemSumHover }
                                                }
                                                // 2026-08-10 (pedido workflow): cuenta SIN gema en el
                                                // inventario — el pre-spawn compra la gema del color
                                                // priorizado (boughtByPriority=true). Mostrar la gema
                                                // comprada (icono/nombre/nivel/XP) con badge PRIORIDAD
                                                // en vez del mensaje "no gem in inventory".
                                                LabelText {
                                                    visible: (modelData.gemSummary === undefined || modelData.gemSummary.length === 0)
                                                             && (modelData.sprite === undefined || modelData.sprite.length === 0)
                                                             && (modelData.boughtByPriority === undefined || !modelData.boughtByPriority)
                                                    text: "no gem in inventory"
                                                    color: colors.faint
                                                    font.pixelSize: 9
                                                    font.italic: true
                                                    Layout.preferredWidth: 130
                                                    elide: Text.ElideRight
                                                }
                                                LabelText {
                                                    visible: modelData.exp !== undefined && modelData.exp > 0
                                                    text: (modelData.cexp || 0).toLocaleString() + " / " + (modelData.exp || 0).toLocaleString() + " XP"
                                                    color: colors.muted
                                                    font.pixelSize: 9
                                                    font.family: "Cascadia Mono, Consolas, monospace"
                                                    Layout.preferredWidth: 130
                                                    horizontalAlignment: Text.AlignRight
                                                }
                                                ProgressBar {
                                                    visible: modelData.exp !== undefined && modelData.exp > 0
                                                    Layout.fillWidth: true
                                                    Layout.preferredHeight: 5
                                                    animated: false
                                                    value: root.gemProgress(modelData.cexp, modelData.exp)
                                                    barColor: colors.amber
                                                }
                                                // v39 (pedido del usuario): bajo la barra de XP de cada
                                                // gema — XP ganado en el ultimo refresh, nombre de la
                                                // gema y coins de la cuenta.
                                                RowLayout {
                                                    Layout.fillWidth: true
                                                    spacing: 6
                                                    LabelText {
                                                        visible: modelData.xpGainRefresh !== undefined && modelData.xpGainRefresh > 0
                                                        text: modelData.xpGainRefresh !== undefined ? "+" + modelData.xpGainRefresh.toLocaleString() + " XP" : ""
                                                        color: "#50d39f"
                                                        font.pixelSize: 9
                                                        font.weight: Font.DemiBold
                                                        font.family: "Cascadia Mono, Consolas, monospace"
                                                        Layout.preferredWidth: 92
                                                    }
                                                    LabelText {
                                                        visible: modelData.gemSummary !== undefined && modelData.gemSummary.length > 0
                                                        text: modelData.gemSummary || ""
                                                        color: colors.muted
                                                        font.pixelSize: 9
                                                        Layout.fillWidth: true
                                                        elide: Text.ElideRight
                                                    }
                                                    LabelText {
                                                        visible: modelData.coins !== undefined && modelData.coins > 0
                                                        text: modelData.coins !== undefined ? "\u00a4 " + modelData.coins.toLocaleString() : ""
                                                        color: colors.amber
                                                        font.pixelSize: 9
                                                        font.family: "Cascadia Mono, Consolas, monospace"
                                                        Layout.preferredWidth: 90
                                                        horizontalAlignment: Text.AlignRight
                                                    }
                                                }
                                                // Badge PRIORIDAD (2026-08-10): la gema se compro del
                                                // shop por prioridad porque el inventario estaba vacio.
                                                Rectangle {
                                                    visible: modelData.boughtByPriority === true
                                                    Layout.preferredWidth: 74
                                                    Layout.preferredHeight: 18
                                                    radius: 4
                                                    color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.18)
                                                    border.color: colors.amber
                                                    border.width: 1
                                                    LabelText {
                                                        anchors.centerIn: parent
                                                        text: "PRIORIDAD"
                                                        color: colors.amber
                                                        font.pixelSize: 8
                                                        font.weight: Font.Bold
                                                    }
                                                }
                                            }
                                        }
                                        MouseArea {
                                            anchors.fill: parent
                                            z: -1
                                            onClicked: farm.useAccountByDevice(modelData.device)
                                            cursorShape: Qt.PointingHandCursor
                                        }
                                    }
                                }
                                EmptyState { visible: farm.accounts.length === 0 && !farm.qwsLoading; text: "No accounts" }
                                EmptyState { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0; text: "No accounts match" }
                            }
                        }
                    }

                    // ================= Accounts =================
                    RowLayout {
                        opacity: pages.pageOpacity
                        transform: Translate { x: pages.pageShift }
                        spacing: 14
                        Layout.margins: 26
                        Layout.topMargin: 18
                        Layout.bottomMargin: 26
                        Panel {
                            Layout.preferredWidth: 245
                            Layout.fillHeight: true
                            ColumnLayout { anchors.fill: parent; anchors.margins: 12; spacing: 8
                                RowLayout { Layout.fillWidth: true; SectionAccent { } LabelText { text: "Accounts"; font.pixelSize: 19; font.weight: Font.DemiBold; Layout.fillWidth: true } GhostButton { text: "Refresh All"; Layout.preferredWidth: 110; Layout.preferredHeight: 30; enabled: !farm.refreshingAll && farm.accounts.length > 0; onClicked: farm.refreshAllAccounts() } }
                                RowLayout { Layout.fillWidth: true; PrimaryButton { text: "Upload QWS"; Layout.fillWidth: true; enabled: !farm.qwsLoading; onClicked: root.qwsOpen = true } }
                                AppField {
                                    id: accountSearchField
                                    Layout.fillWidth: true
                                    placeholderText: "Search accounts..."
                                    onTextEdited: farm.setAccountSearch(text)
                                }
                                Rectangle {
                                    visible: farm.refreshingAll
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 30
                                    color: colors.canvas
                                    border.color: colors.borderSoft
                                    radius: 4
                                    RowLayout { anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8; spacing: 8
                                        ProgressBar { Layout.fillWidth: true; value: farm.refreshAllProgress / 100; barColor: colors.red }
                                        LabelText { text: farm.refreshAllStatus; color: colors.mint; font.pixelSize: 9 }
                                    }
                                }
                                Rectangle { Layout.fillWidth: true; height: 1; color: colors.borderSoft }
                                RowLayout { Layout.fillWidth: true
                                    SmallCaption { text: "SAVED ACCOUNTS (" + farm.accounts.length + ")"; Layout.fillWidth: true }
                                    LabelText { visible: farm.farmSelection.length > 0; text: farm.farmSelection.length + " sel"; color: colors.amber; font.pixelSize: 9; font.weight: Font.DemiBold }
                                    GhostButton { visible: farm.farmSelection.length > 0; text: "Clear"; Layout.preferredWidth: 52; Layout.preferredHeight: 22; onClicked: farm.clearFarmSelection() }
                                }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; Layout.minimumHeight: 120; clip: true; spacing: 3; model: farm.filteredAccounts; ScrollBar.vertical: ThemedScrollBar { }
                                    delegate: Rectangle {
                                        width: ListView.view.width
                                        height: 72
                                        radius: 5
                                        gradient: Gradient {
                                            GradientStop { position: 0.0; color: modelData.device === farm.deviceId ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.15) : colors.surface2 }
                                            GradientStop { position: 1.0; color: modelData.device === farm.deviceId ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.08) : colors.surface }
                                        }
                                        border.color: modelData.device === farm.deviceId ? colors.amber : colors.borderSoft
                                        border.width: 1
                                        // hover con fade suave
                                        Rectangle {
                                            anchors.fill: parent
                                            radius: 5
                                            color: Qt.lighter(colors.surface3, 1.05)
                                            opacity: accHoverAcc.hovered ? 0.4 : 0
                                            Behavior on opacity { NumberAnimation { duration: 140 } }
                                        }
                                        HoverHandler { id: accHoverAcc }
                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.leftMargin: 10
                                            anchors.rightMargin: 10
                                            anchors.topMargin: 6
                                            anchors.bottomMargin: 6
                                            spacing: 4
                                            RowLayout {
                                                Layout.fillWidth: true
                                                spacing: 8
                                                CheckBox {
                                                    id: farmChk
                                                    Layout.preferredWidth: 18
                                                    Layout.preferredHeight: 18
                                                    checked: farm.farmSelection.indexOf(modelData.device) >= 0
                                                    onToggled: farm.toggleFarmSelectionByDevice(modelData.device, checked)
                                                    indicator: Rectangle {
                                                        width: 16
                                                        height: 16
                                                        radius: 4
                                                        color: farmChk.checked ? colors.pri1 : colors.canvas
                                                        border.color: farmChk.checked ? colors.priBdr : colors.border
                                                        border.width: 1
                                                        LabelText {
                                                            anchors.centerIn: parent
                                                            text: farmChk.checked ? "\u2713" : ""
                                                            color: "#ffffff"
                                                            font.pixelSize: 11
                                                            font.weight: Font.Bold
                                                        }
                                                    }
                                                }
                                                LabelText {
                                                    text: modelData.favorite ? "★" : "☆"
                                                    color: modelData.favorite ? colors.amber : colors.faint
                                                    font.pixelSize: 14
                                                    Layout.preferredWidth: 18
                                                    MouseArea {
                                                        anchors.fill: parent
                                                        cursorShape: Qt.PointingHandCursor
                                                        z: 1
                                                        onClicked: farm.toggleFavorite(index)
                                                    }
                                                }
                                                LabelText {
                                                    text: modelData.name
                                                    font.pixelSize: 13
                                                    font.weight: Font.Bold
                                                    Layout.fillWidth: true
                                                    elide: Text.ElideRight
                                                }
                                                Rectangle {
                                                    Layout.preferredWidth: 22
                                                    Layout.preferredHeight: 22
                                                    radius: 5
                                                    color: removeAreaAcc.containsMouse ? Qt.rgba(colors.red.r, colors.red.g, colors.red.b, 0.28) : "transparent"
                                                    LabelText { anchors.centerIn: parent; text: "\u2715"; font.pixelSize: 11 }
                                                    MouseArea {
                                                        id: removeAreaAcc
                                                        anchors.fill: parent
                                                        hoverEnabled: true
                                                        cursorShape: Qt.PointingHandCursor
                                                        z: 1
                                                        onClicked: farm.removeAccount(index)
                                                    }
                                                }
                                        }
                                    }
                                    MouseArea {
                                        anchors.fill: parent
                                        z: -1
                                        onClicked: farm.useAccountByDevice(modelData.device)
                                        cursorShape: Qt.PointingHandCursor
                                    }
                                }
                            }
                            EmptyState { visible: farm.accounts.length === 0 && !farm.qwsLoading; text: "No saved accounts" }
                            EmptyState { visible: farm.accounts.length > 0 && farm.filteredAccounts.length === 0; text: "No accounts match" }
                            LabelText { visible: farm.qwsLoading; text: farm.qwsStatus; color: colors.mint; font.pixelSize: 10; Layout.alignment: Qt.AlignHCenter; Layout.topMargin: 4 }
                            }
                        }
                        Panel {
                            visible: farm.gemCount > 0
                            Layout.fillWidth: true; Layout.fillHeight: true
                            ColumnLayout { anchors.fill: parent; anchors.margins: 18; spacing: 0
                                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 42
                                    SectionAccent { Layout.preferredHeight: 18 }
                                    LabelText { text: farm.accountText; font.pixelSize: 21; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                    LabelText {
                                        visible: root.currentAccountCoins() > 0
                                        text: "¤ " + root.currentAccountCoins()
                                        color: colors.amber
                                        font.pixelSize: 14
                                        font.weight: Font.Bold
                                        Layout.preferredWidth: 100
                                    }
                                    SmallCaption { text: "SERVER" } LabelText { text: farm.serverText; font.pixelSize: 11; font.weight: Font.DemiBold; Layout.preferredWidth: 170 } StatusPill { value: farm.farmRunning ? "FARMING" : "READY"; accent: farm.farmRunning ? colors.mint : colors.muted } }
                                Rectangle { Layout.fillWidth: true; height: 1; color: colors.borderSoft }
                                SmallCaption { text: "CURRENT GEM PROGRESS"; Layout.topMargin: 14 }
                                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 92; spacing: 14
                                    GemSprite { sprite: farm.selectedGemIndex >= 0 && farm.selectedGemIndex < gemsQmlModel.count ? gemsQmlModel.get(farm.selectedGemIndex).sprite : ""; iconSize: 56 }
                                    ColumnLayout { Layout.preferredWidth: 380; spacing: 5
                                        LabelText { text: farm.selectedGemName; color: farm.selectedGemIndex >= 0 && farm.selectedGemIndex < gemsQmlModel.count ? gemsQmlModel.get(farm.selectedGemIndex).color : colors.faint; font.pixelSize: 16; font.weight: Font.DemiBold }
                                        ProgressBar { Layout.fillWidth: true; value: farm.selectedGemIndex >= 0 && farm.selectedGemIndex < gemsQmlModel.count ? root.gemProgress(gemsQmlModel.get(farm.selectedGemIndex).cexp, gemsQmlModel.get(farm.selectedGemIndex).exp) : 0; barColor: colors.amber }
                                        LabelText { text: farm.gemXpText; font.pixelSize: 11; color: colors.mint }
                                    }
                                    Item { Layout.fillWidth: true }
                                    ColumnLayout { Layout.preferredWidth: 260; spacing: 5
                                        RowLayout { Layout.fillWidth: true; SmallCaption { text: "XP SESSION"; Layout.fillWidth: true } }
                                        LabelText { text: farm.xpText; font.pixelSize: 11; color: colors.mint; wrapMode: Text.WordWrap }
                                        RowLayout { Layout.fillWidth: true; spacing: 8
                                            SmallCaption { text: "DEATHS: " + farm.deaths; color: farm.deaths > 0 ? colors.red : colors.muted }
                                            Item { Layout.fillWidth: true }
                                            SmallCaption { text: "COINS" }
                                            LabelText { visible: root.currentAccountCoins() > 0; text: "¤ " + root.currentAccountCoins(); color: colors.amber; font.pixelSize: 12; font.weight: Font.Bold }
                                        }
                                    }
                                }
                                // Cuenta activa SIN gemas en el inventario: leyenda
                                // en vez del panel de progreso vacio (pedido
                                // 2026-08-08: mostraba las gemas de otra cuenta).
                                LabelText {
                                    visible: farm.gemCount === 0
                                    text: "no gem in inventory"
                                    color: colors.faint
                                    font.pixelSize: 13
                                    font.italic: true
                                    Layout.topMargin: 6
                                    Layout.bottomMargin: 14
                                }
                                Rectangle { Layout.fillWidth: true; height: 1; color: colors.borderSoft }
                                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 46; SectionAccent { } LabelText { text: "Gem inventory"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true } GhostButton { text: "Gem Priority"; Layout.preferredHeight: 26; onClicked: root.prioritySortOpen = true } GhostButton { text: "Gem Shop"; Layout.preferredHeight: 26; onClicked: { farm.fetchShop(farm.deviceId); root.shopOpen = true } } SmallCaption { text: farm.gemCount + " gems" } }
                                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 28; Layout.leftMargin: 10; Layout.rightMargin: 10; SmallCaption { text: "GEM"; Layout.preferredWidth: 160 } SmallCaption { text: "LEVEL"; Layout.preferredWidth: 54 } SmallCaption { text: "XP PROGRESS"; Layout.fillWidth: true } SmallCaption { text: "XP CEXP / EXP"; Layout.preferredWidth: 140 } SmallCaption { text: "ACTION"; Layout.preferredWidth: 124 } }
                                Repeater { model: gemsQmlModel; delegate: Rectangle {
                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 58
                                    radius: 4
                                    gradient: Gradient {
                                        GradientStop { position: 0.0; color: index === farm.selectedGemIndex ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.15) : (index % 2 ? colors.surface2 : Qt.lighter(colors.surface, 1.1)) }
                                        GradientStop { position: 1.0; color: index === farm.selectedGemIndex ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.08) : (index % 2 ? Qt.lighter(colors.surface, 0.92) : Qt.darker(colors.surface, 1.05)) }
                                    }
                                    border.color: index === farm.selectedGemIndex ? colors.priBdr : colors.borderSoft
                                    // hover con fade suave
                                    Rectangle {
                                        anchors.fill: parent
                                        radius: 4
                                        color: Qt.lighter(colors.surface3, 1.1)
                                        opacity: invHover.hovered ? 0.5 : 0
                                        Behavior on opacity { NumberAnimation { duration: 140 } }
                                    }
                                    HoverHandler { id: invHover }
                                    RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                                        RowLayout { Layout.preferredWidth: 160; spacing: 8; GemSprite { sprite: model.sprite; iconSize: 34 } ColumnLayout { spacing: 2; LabelText { text: model.name; font.pixelSize: 11; font.weight: Font.DemiBold } } }
                                        LabelText { text: model.level; Layout.preferredWidth: 54; font.pixelSize: 11; font.weight: Font.DemiBold }
                                        ColumnLayout { Layout.fillWidth: true; spacing: 4; ProgressBar { Layout.fillWidth: true; value: root.gemProgress(model.cexp, model.exp); barColor: colors.amber } SmallCaption { text: Math.round(root.gemProgress(model.cexp, model.exp) * 100) + " pct" } }
                                        LabelText { text: model.cexp + " / " + model.exp; Layout.preferredWidth: 140; font.pixelSize: 10; color: colors.muted }
                                        GhostButton { text: index === farm.selectedGemIndex ? "Equipped" : "Farm"; Layout.preferredWidth: 124; Layout.preferredHeight: 31; onClicked: farm.equipGem(index) }
                                    }
                                } }
                                Item { Layout.fillHeight: true }
                            }
                        }
                        Panel {
                            visible: farm.gemCount === 0
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            Rectangle {
                                anchors.centerIn: parent
                                width: 460
                                height: 230
                                radius: 115
                                gradient: Gradient {
                                    GradientStop { position: 0.0; color: Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.09) }
                                    GradientStop { position: 0.6; color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.04) }
                                    GradientStop { position: 1.0; color: "#00000000" }
                                }
                            }
                            Rectangle {
                                anchors.centerIn: parent
                                width: 300
                                height: 150
                                radius: 75
                                gradient: Gradient {
                                    GradientStop { position: 0.0; color: Qt.rgba(colors.amber.r, colors.amber.g, colors.amber.b, 0.13) }
                                    GradientStop { position: 1.0; color: "#00000000" }
                                }
                            }
                            ColumnLayout {
                                anchors.centerIn: parent
                                spacing: 10
                                LabelText { text: farm.accounts.length === 0 ? "No account loaded" : "no gem in inventory"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.alignment: Qt.AlignHCenter }
                                SmallCaption { text: farm.accounts.length === 0 ? "Fetch gems to load the inventory" : "This account has no gems (inventory empty)"; Layout.alignment: Qt.AlignHCenter }
                                GhostButton { text: "Fetch gems"; Layout.preferredWidth: 170; Layout.alignment: Qt.AlignHCenter; onClicked: farm.fetchGems() }
                                RowLayout { visible: farm.accounts.length > 0; Layout.alignment: Qt.AlignHCenter; spacing: 8
                                    GhostButton { text: "Gem Shop"; Layout.preferredHeight: 28; onClicked: { farm.fetchShop(farm.deviceId); root.shopOpen = true } }
                                    GhostButton { text: "Gem Priority"; Layout.preferredHeight: 28; onClicked: root.prioritySortOpen = true }
                                }
                            }
                        }
                    }

                    // ================= Activity =================
                    RowLayout {
                        opacity: pages.pageOpacity
                        transform: Translate { x: pages.pageShift }
                        Layout.margins: 26
                        Layout.topMargin: 18
                        Layout.bottomMargin: 26
                        spacing: 14

                        // --- panel izquierdo: log (ListView virtualizado) ---
                        Panel { Layout.fillWidth: true; Layout.fillHeight: true
                            clip: true
                            ColumnLayout { anchors.fill: parent; anchors.margins: 14; spacing: 10
                                RowLayout { Layout.fillWidth: true
                                    SectionAccent { }
                                    LabelText { text: "Event timeline"; font.pixelSize: 20; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                    StatusPill { value: logModel.count + " LINES"; accent: colors.amber }
                                    GhostButton { text: "Copy All"; Layout.preferredWidth: 80; Layout.preferredHeight: 28
                                        onClicked: {
                                            var lines = []
                                            for (var i = 0; i < logModel.count; i++) {
                                                var e = logModel.get(i)
                                                lines.push(e.time + "  " + e.line)
                                            }
                                            farm.copyToClipboard(lines.join("\n"))
                                        }
                                    }
                                    GhostButton { text: "Clear"; Layout.preferredWidth: 56; Layout.preferredHeight: 28
                                        onClicked: logModel.clear() }
                                }
                                Rectangle {
                                    Layout.fillWidth: true; Layout.fillHeight: true
                                    color: colors.canvas; radius: 6; border.color: colors.borderSoft
                                    clip: true
                                    ListView {
                                        id: logView
                                        anchors.fill: parent
                                        anchors.margins: 4
                                        model: logModel
                                        clip: true
                                        spacing: 1
                                        // Solo virtualiza lo visible — no renderiza 2000+ items
                                        cacheBuffer: 200
                                        ScrollBar.vertical: ThemedScrollBar { }
                                        delegate: Rectangle {
                                            width: logView.width
                                            height: logText.implicitHeight + 6
                                            color: "transparent"
                                            Text {
                                                id: logText
                                                anchors.left: parent.left; anchors.right: parent.right
                                                anchors.verticalCenter: parent.verticalCenter
                                                leftPadding: 8; rightPadding: 8
                                                text: model.time + "  " + model.line
                                                // severidad: ERROR/fail en rojo, Spawn skip en amber, debug en faint
                                                color: {
                                                    var l = model.line
                                                    if (l.indexOf("ERROR") >= 0 || l.toLowerCase().indexOf("fail") >= 0)
                                                        return colors.red
                                                    if (l.toLowerCase().indexOf("spawn skip") >= 0)
                                                        return colors.amber
                                                    if (l.indexOf("[DBG]") >= 0)
                                                        return colors.faint
                                                    return colors.text
                                                }
                                                font.family: "Cascadia Mono, Consolas, Courier New, monospace"
                                                font.pixelSize: 12
                                                wrapMode: Text.WrapAtWordBoundaryOrAnywhere
                                            }
                                        }
                                        // Auto-follow: desplaza al fondo cuando hay lineas nuevas
                                        // (solo si el usuario ya estaba en el fondo)
                                        Connections {
                                            target: logModel
                                            function onCountChanged() {
                                                if (root.stickToBottom) {
                                                    Qt.callLater(function() {
                                                        logView.positionViewAtEnd()
                                                    })
                                                }
                                            }
                                        }
                                        // Detecta scroll del usuario: apaga auto-follow al subir
                                        onContentYChanged: {
                                            var maxY = contentHeight - height
                                            root.stickToBottom = (maxY <= 0 || contentY >= maxY - 4)
                                        }
                                    }
                                }
                            }
                        }

                        // --- panel derecho: run health ---
                        Panel { Layout.preferredWidth: 235; Layout.fillHeight: true
                            clip: true
                            ColumnLayout { anchors.fill: parent; anchors.margins: 14; spacing: 10
                                RowLayout { Layout.fillWidth: true
                                    SectionAccent { }
                                    LabelText { text: "Run health"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true }
                                    StatusPill { value: farm.activeSessions.length + " ACTIVE"; accent: farm.activeSessions.length > 0 ? colors.mint : colors.faint }
                                }
                                RowLayout { Layout.fillWidth: true; spacing: 6
                                    Panel { Layout.fillWidth: true; Layout.preferredHeight: 56; color: colors.canvas; gradient: null
                                        ColumnLayout { anchors.centerIn: parent; spacing: 2
                                            LabelText { text: farm.activeSessions.length; color: colors.mint; font.pixelSize: 19; font.weight: Font.DemiBold; horizontalAlignment: Text.AlignHCenter }
                                            SmallCaption { text: "LIVE"; Layout.alignment: Qt.AlignHCenter }
                                        }
                                    }
                                    Panel { Layout.fillWidth: true; Layout.preferredHeight: 56; color: colors.canvas; gradient: null
                                        ColumnLayout { anchors.centerIn: parent; spacing: 2
                                            LabelText { text: root.waitingAccounts(); color: colors.amber; font.pixelSize: 19; font.weight: Font.DemiBold; horizontalAlignment: Text.AlignHCenter }
                                            SmallCaption { text: "WAIT"; Layout.alignment: Qt.AlignHCenter }
                                        }
                                    }
                                    Panel {
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 56
                                        color: colors.canvas
                                        gradient: null
                                        ColumnLayout { anchors.centerIn: parent; spacing: 2
                                            LabelText { text: root.countFailures(); color: root.countFailures() > 0 ? colors.red : colors.muted; font.pixelSize: 19; font.weight: Font.DemiBold; horizontalAlignment: Text.AlignHCenter }
                                            SmallCaption { text: "FAIL"; Layout.alignment: Qt.AlignHCenter }
                                        }
                                        ToolTip.visible: failHover.hovered
                                        ToolTip.text: "Fallos de la corrida (lineas de log con ERROR/fail)"
                                        ToolTip.delay: 400
                                        HoverHandler { id: failHover }
                                    }
                                }
                                Panel { Layout.fillWidth: true; Layout.preferredHeight: 48; color: colors.surface2
                                    RowLayout { anchors.fill: parent; anchors.margins: 9
                                        ColumnLayout { Layout.fillWidth: true; spacing: 2
                                            LabelText { text: farm.farmRunning ? farm.accountText : "Core paused"; font.pixelSize: 11; font.weight: Font.DemiBold }
                                            SmallCaption { text: farm.serverText }
                                        }
                                        StatusPill { value: farm.farmRunning ? "Live" : "Idle"; accent: farm.farmRunning ? colors.mint : colors.faint }
                                    }
                                }
                                Item { Layout.fillHeight: true }
                            }
                        }
                    }
                }
            }
        }
    }

    // Toast con animacion: entrada slide-down + fade-in, salida fade-out.
    Item {
        id: toastWrap
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: 26
        width: toastLabel.implicitWidth + 34
        height: 40
        z: 24
        property real slide: root.showToast ? 0 : -16
        opacity: root.showToast ? 1 : 0
        visible: toastWrap.opacity > 0
        Behavior on opacity {
            NumberAnimation { duration: root.showToast ? 180 : 200; easing.type: root.showToast ? Easing.OutCubic : Easing.InQuad }
        }
        Behavior on slide {
            NumberAnimation { duration: 180; easing.type: Easing.OutCubic }
        }
        transform: Translate { y: toastWrap.slide }
        Rectangle {
            anchors.fill: parent
            anchors.topMargin: -2
            radius: 20
            color: "#59000000"
        }
        Rectangle {
            anchors.fill: parent
            radius: 20
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(colors.surface3, 1.15) }
                GradientStop { position: 1.0; color: colors.surface3 }
            }
            border.color: colors.mint
            LabelText { id: toastLabel; anchors.centerIn: parent; text: root.toastText; color: colors.text; font.weight: Font.DemiBold }
        }
    }

    Rectangle {
        visible: root.priorityOpen
        anchors.fill: parent
        color: "#99000000"
        z: 30
        MouseArea { anchors.fill: parent; onClicked: root.priorityOpen = false }
        Panel {
            id: priorityPanel
            anchors.centerIn: parent
            width: Math.min(parent.width - 80, 820)
            height: Math.min(parent.height - 80, 520)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.2) }
                GradientStop { position: 1.0; color: colors.surface }
            }
            border.color: colors.priBdr
            ColumnLayout { anchors.fill: parent; anchors.margins: 18; spacing: 12
                RowLayout { Layout.fillWidth: true; LabelText { text: "Gem farming priority"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true } StatusPill { value: "GEMS"; accent: colors.amber } }
                LabelText { text: "Click a gem to select the farm target"; color: colors.muted; font.pixelSize: 10 }
                GridLayout { Layout.fillWidth: true; Layout.preferredHeight: 300; Layout.minimumHeight: 300; Layout.maximumHeight: 300; columns: 5; columnSpacing: 6; rowSpacing: 6
                    Repeater { model: gemsQmlModel.count > 0 ? gemsQmlModel : ["Red", "Pink", "Forest", "Indigo", "Silver", "Gold", "Orange", "Blue", "Yellow", "Green", "White", "Black", "Gray", "Cyan", "Purple", "Magenta", "Brown", "Teal", "Maroon", "Rainbow"]
                        delegate: Panel {
                            Layout.fillWidth: true
                            Layout.preferredWidth: 150
                            Layout.minimumWidth: 0
                            Layout.preferredHeight: 58
                            Layout.minimumHeight: 58
                            Layout.maximumHeight: 58
                            color: root.priorityOpen && model.index === farm.selectedGemIndex ? Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.14) : (gemCellHover.containsMouse ? Qt.lighter(colors.surface2, 1.2) : colors.canvas)
                            Behavior on color { ColorAnimation { duration: 120 } }
                            gradient: null
                            border.color: root.priorityOpen && model.index === farm.selectedGemIndex ? colors.amber : (gemCellHover.containsMouse ? Qt.lighter(colors.pri1, 1.25) : Qt.rgba(colors.pri1.r, colors.pri1.g, colors.pri1.b, 0.35))
                            Behavior on border.color { ColorAnimation { duration: 120 } }
                            MouseArea {
                                id: gemCellHover
                                anchors.fill: parent
                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor
                                onClicked: {
                                    if (gemsQmlModel.count > 0) {
                                        farm.equipGem(index)
                                        root.priorityOpen = false
                                        root.toast("Gem selected: " + gemsQmlModel.get(index).name)
                                    }
                                }
                            }
                            RowLayout { anchors.fill: parent; anchors.margins: 8; spacing: 7
                                Rectangle { Layout.preferredWidth: 25; Layout.preferredHeight: 25; radius: 4; color: index === farm.selectedGemIndex ? colors.amber : colors.pri1; LabelText { anchors.centerIn: parent; text: (index + 1).toString().padStart(2, "0"); color: "#ffffff"; font.pixelSize: 9; font.bold: true } }
                                GemSprite { sprite: gemsQmlModel.count > 0 ? gemsQmlModel.get(index).sprite : ""; iconSize: 30 }
                                LabelText { text: (gemsQmlModel.count > 0 ? gemsQmlModel.get(index).name : modelData + " Gem"); font.pixelSize: 11; font.weight: Font.DemiBold; Layout.fillWidth: true }
                            }
                        }
                    }
                }
                RowLayout { Layout.fillWidth: true; spacing: 6; GhostButton { text: "Close"; Layout.fillWidth: true; Layout.preferredWidth: 250; onClicked: root.priorityOpen = false } }
            }
        }
    }

    // ============ PRIORITY (orden de gemas por drag & drop) ============
    Rectangle {
        visible: root.prioritySortOpen
        anchors.fill: parent
        color: "#99000000"
        z: 30
        MouseArea { anchors.fill: parent; onClicked: root.prioritySortOpen = false }
        Panel {
            id: prioritySortPanel
            anchors.centerIn: parent
            width: Math.min(parent.width - 80, 720)
            height: Math.min(parent.height - 80, 560)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.2) }
                GradientStop { position: 1.0; color: colors.surface }
            }
            border.color: colors.priBdr
            ColumnLayout { anchors.fill: parent; anchors.margins: 18; spacing: 12
                RowLayout { Layout.fillWidth: true
                    LabelText { text: "Gem farming priority"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    StatusPill { value: "ORDER"; accent: colors.amber }
                }
                LabelText { text: "Click a gem to select it, then click another to swap. Top = farmed first."; color: colors.muted; font.pixelSize: 10 }
                // cabecera
                RowLayout { Layout.fillWidth: true; Layout.preferredHeight: 22; Layout.leftMargin: 8; Layout.rightMargin: 8
                    SmallCaption { text: "#"; Layout.preferredWidth: 34 }
                    SmallCaption { text: "GEM"; Layout.fillWidth: true }
                    SmallCaption { text: "AUTO BUY"; Layout.preferredWidth: 92 }
                    SmallCaption { text: "ACTIONS"; Layout.preferredWidth: 64 }
                }
                RowLayout { Layout.fillWidth: true; Layout.leftMargin: 8; Layout.rightMargin: 8
                    LabelText { text: "Shop rotates 7pm/1am Colombia (UTC). Marked colors are bought 1 min after each rotation."; color: colors.faint; font.pixelSize: 9; Layout.fillWidth: true }
                    LabelText { text: "next: " + farm.nextStoreBuyTime(); color: colors.amber; font.pixelSize: 9 }
                }
                ListView {
                    id: priorityList
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    spacing: 4
                    model: priorityQmlModel
                    ScrollBar.vertical: ThemedScrollBar { }
                    // transicion suave cuando un item se desplaza al reordenar
                    displaced: Transition {
                        NumberAnimation { properties: "x,y"; duration: 140; easing.type: Easing.OutQuad }
                    }
                    delegate: Rectangle {
                        id: prioRow
                        required property int index
                        required property var modelData
                        width: ListView.view.width
                        height: 48
                        radius: 5
                        // sticky: la fila seleccionada (primer click) se resalta
                        color: root.priorityDragStart === prioRow.index ? Qt.lighter(colors.amber, 2.3) : (prioHover.containsMouse ? Qt.lighter(colors.surface2, 1.15) : colors.surface2)
                        Behavior on color { ColorAnimation { duration: 100 } }
                        border.color: root.priorityDragStart === prioRow.index ? colors.amber : "transparent"
                        border.width: 1
                        RowLayout { anchors.fill: parent; anchors.leftMargin: 8; anchors.rightMargin: 8; spacing: 8
                            LabelText { text: (prioRow.index + 1).toString().padStart(2, "0"); color: colors.faint; font.pixelSize: 11; Layout.preferredWidth: 34 }
                            GemSprite { sprite: modelData.sprite; iconSize: 32 }
                            LabelText { text: modelData.name; font.pixelSize: 13; font.weight: Font.DemiBold; Layout.fillWidth: true }
                            // 2026-08-10: boton "Auto buy" por color — marca el
                            // color para comprarlo en la tienda 1 min despues de
                            // cada rotacion (19:00/01:00 hora Colombia = 00:00/
                            // 06:00 UTC, compra a las 00:01/06:01 UTC).
                            Button {
                                id: autoBuyBtn
                                text: farm.isAutoBuyColor(modelData.id) ? "AUTO BUY ON" : "AUTO BUY"
                                Layout.preferredWidth: 88
                                Layout.preferredHeight: 24
                                font.pixelSize: 9
                                font.weight: Font.DemiBold
                                checkable: true
                                checked: farm.isAutoBuyColor(modelData.id)
                                background: Rectangle {
                                    radius: 4
                                    color: autoBuyBtn.checked ? colors.green : colors.surface3
                                    border.color: autoBuyBtn.checked ? colors.green : colors.faint
                                    border.width: 1
                                }
                                contentItem: Text {
                                    text: autoBuyBtn.text
                                    color: autoBuyBtn.checked ? "#0a0f0a" : colors.text
                                    font: autoBuyBtn.font
                                    horizontalAlignment: Text.AlignHCenter
                                    verticalAlignment: Text.AlignVCenter
                                }
                                onClicked: {
                                    // checkable:true ya invierte checked al
                                    // click; pasar el estado NUEVO directo (el
                                    // viejo invertia 2 veces -> estado al reves)
                                    farm.toggleAutoBuyColor(modelData.id, autoBuyBtn.checked)
                                }
                            }
                            RowLayout { Layout.preferredWidth: 64; spacing: 4; z: 2
                                ArrowButton {
                                    arrow: "\u25B2"
                                    enabled: prioRow.index > 0
                                    onClicked: farm.moveGemPriority(prioRow.index, prioRow.index - 1)
                                }
                                ArrowButton {
                                    arrow: "\u25BC"
                                    enabled: prioRow.index < priorityList.count - 1
                                    onClicked: farm.moveGemPriority(prioRow.index, prioRow.index + 1)
                                }
                            }
                        }
                        MouseArea {
                            id: dragArea
                            anchors.fill: parent
                            anchors.rightMargin: 172
                            cursorShape: Qt.PointingHandCursor
                            // CLICK-TO-SWAP 2026-08-11 (pedido del usuario):
                            // click en una gema la selecciona; click en otra
                            // las intercambia. El drag fisico se pelea con el
                            // ListView (sobreposicion) y el drag sin target no
                            // activa drag.active en Qt 6.8 -> el swap por clicks
                            // es robusto y simple.
                            onClicked: {
                                if (root.priorityDragStart < 0) {
                                    // primera seleccion
                                    root.priorityDragStart = prioRow.index
                                    root.priorityDragActive = true
                                } else if (root.priorityDragStart === prioRow.index) {
                                    // click en la misma -> deseleccionar
                                    root.priorityDragStart = -1
                                    root.priorityDragActive = false
                                } else {
                                    // click en otra -> intercambiar posiciones
                                    var from = root.priorityDragStart
                                    var to = prioRow.index
                                    // mueve el item de 'from' a 'to' (desplaza el resto)
                                    priorityQmlModel.move(from, to, 1)
                                    // sincroniza el backend con el orden final
                                    farm.applyPriorityOrder(priorityQmlModel)
                                    root.priorityDragStart = -1
                                    root.priorityDragActive = false
                                    root.toast("Priority updated")
                                }
                            }
                        }
                        HoverHandler { id: prioHover }
                    }
                }
                RowLayout { Layout.fillWidth: true; spacing: 6
                    LabelText { text: "Drag the rows or use the arrows. Order is saved automatically."; color: colors.faint; font.pixelSize: 9; Layout.fillWidth: true }
                    GhostButton { text: "Close"; Layout.preferredWidth: 120; onClicked: root.prioritySortOpen = false }
                }
            }
        }
    }

    // ============ SHOP (tienda de gemas por cuenta) ============
    Rectangle {
        visible: root.shopOpen
        anchors.fill: parent
        color: "#99000000"
        z: 30
        MouseArea { anchors.fill: parent; onClicked: root.shopOpen = false }
        Panel {
            id: shopPanel
            anchors.centerIn: parent
            width: Math.min(parent.width - 80, 860)
            height: Math.min(parent.height - 80, 560)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.2) }
                GradientStop { position: 1.0; color: colors.surface }
            }
            border.color: colors.priBdr
            ColumnLayout { anchors.fill: parent; anchors.margins: 18; spacing: 12
                RowLayout { Layout.fillWidth: true
                    LabelText { text: "Gem Shop"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    LabelText { text: farm.shopDeviceName; color: colors.mint; font.pixelSize: 12; font.weight: Font.Bold }
                    StatusPill { value: "¤ " + farm.shopCoins; accent: colors.amber }
                }
                LabelText { text: farm.shopStatus; color: colors.muted; font.pixelSize: 10 }
                // grid de tarjetas con sprite grande, attrs y precio
                GridView {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    clip: true
                    cellWidth: Math.max(200, (shopPanel.width - 60) / Math.max(2, Math.floor((shopPanel.width - 60) / 210)))
                    cellHeight: 240
                    model: farm.shopGems
                    ScrollBar.vertical: ThemedScrollBar { }
                    delegate: Rectangle {
                        required property int index
                        required property var modelData
                        width: GridView.view.cellWidth - 12
                        height: GridView.view.cellHeight - 12
                        radius: 10
                        color: modelData.owned ? Qt.rgba(colors.mint.r, colors.mint.g, colors.mint.b, 0.08) : colors.surface2
                        border.color: modelData.owned ? Qt.rgba(colors.mint.r, colors.mint.g, colors.mint.b, 0.4) : (shopCard.containsMouse ? colors.priBdr : colors.borderSoft)
                        border.width: modelData.owned ? 1.5 : 1
                        Behavior on border.color { ColorAnimation { duration: 160 } }
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 14
                            anchors.topMargin: 10
                            spacing: 2
                            // sprite grande centrado
                            Item { Layout.fillWidth: true; Layout.preferredHeight: 68
                                GemSprite { sprite: modelData.sprite; iconSize: 64; anchors.centerIn: parent }
                            }
                            LabelText { text: modelData.name; font.pixelSize: 13; font.weight: Font.DemiBold; Layout.alignment: Qt.AlignHCenter; elide: Text.ElideRight; Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter }
                            RowLayout { Layout.alignment: Qt.AlignHCenter; spacing: 6
                                Rectangle { radius: 6; width: 36; height: 18; color: Qt.rgba(colors.blue.r, colors.blue.g, colors.blue.b, 0.2)
                                    LabelText { anchors.centerIn: parent; text: "Lv" + modelData.level; font.pixelSize: 10; color: colors.blue; font.weight: Font.Bold } }
                                Rectangle { radius: 6; width: 60; height: 18; color: Qt.rgba(colors.mint.r, colors.mint.g, colors.mint.b, 0.15)
                                    LabelText { anchors.centerIn: parent; text: modelData.exp + "xp"; font.pixelSize: 10; color: colors.mint } }
                            }
                            Item { Layout.fillHeight: true }
                            RowLayout { Layout.alignment: Qt.AlignHCenter; spacing: 4
                                LabelText { text: "¤"; font.pixelSize: 14; color: colors.muted }
                                LabelText { text: modelData.price; font.pixelSize: 16; font.weight: Font.Bold; color: colors.amber }
                            }
                            RowLayout { Layout.alignment: Qt.AlignHCenter; spacing: 4
                                GhostButton {
                                    text: farm.shopBusy ? "..." : (modelData.owned ? "Owned" : "Buy")
                                    Layout.preferredWidth: 72
                                    Layout.preferredHeight: 28
                                    enabled: !farm.shopBusy && !modelData.owned && modelData.purchasable
                                    onClicked: farm.buyShopGem(modelData.id)
                                }
                                GhostButton {
                                    text: "x2"
                                    Layout.preferredWidth: 36
                                    Layout.preferredHeight: 28
                                    enabled: !farm.shopBusy && !modelData.owned && modelData.purchasable
                                    onClicked: farm.buyShopGemX2(modelData.id)
                                    visible: !modelData.owned && modelData.purchasable
                                }
                            }
                        }
                        HoverHandler { id: shopCard }
                    }
                }
                RowLayout { Layout.fillWidth: true; spacing: 6
                    LabelText { text: "Buying a gem spends coins from this account"; color: colors.faint; font.pixelSize: 9; Layout.fillWidth: true }
                    GhostButton { text: "Close"; Layout.preferredWidth: 120; onClicked: root.shopOpen = false }
                }
            }
        }
    }

    Rectangle {
        visible: root.qwsOpen
        anchors.fill: parent
        color: "#99000000"
        z: 31
        MouseArea { anchors.fill: parent; onClicked: { if (!farm.qwsLoading) root.qwsOpen = false } }
        Panel {
            id: qwsPanel
            anchors.centerIn: parent
            width: Math.min(parent.width - 80, 640)
            height: Math.min(parent.height - 80, 440)
            gradient: Gradient {
                GradientStop { position: 0.0; color: Qt.lighter(colors.surface, 1.2) }
                GradientStop { position: 1.0; color: colors.surface }
            }
            border.color: colors.priBdr
            ColumnLayout { anchors.fill: parent; anchors.margins: 18; spacing: 12
                RowLayout { Layout.fillWidth: true
                    LabelText { text: "Upload QWS accounts"; font.pixelSize: 18; font.weight: Font.DemiBold; Layout.fillWidth: true }
                    StatusPill { value: "QW.SOL"; accent: colors.amber }
                }
                LabelText { text: "Drag qw.sol files or folders here, or press Browse"; color: colors.muted; font.pixelSize: 10 }
                Rectangle {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.minimumHeight: 150
                    radius: 6
                    gradient: Gradient {
                        GradientStop { position: 0.0; color: qwsDrop.containsDrag ? Qt.lighter(colors.surface3, 1.1) : Qt.darker(colors.canvas, 1.1) }
                        GradientStop { position: 1.0; color: qwsDrop.containsDrag ? colors.surface2 : colors.canvas }
                    }
                    border.color: qwsDrop.containsDrag ? colors.amber : colors.border
                    border.width: 1
                    Behavior on border.color { ColorAnimation { duration: 150 } }
                    DropArea {
                        id: qwsDrop
                        anchors.fill: parent
                        onDropped: function(drop) {
                            var paths = []
                            for (var i = 0; i < drop.urls.length; i++)
                                paths.push(drop.urls[i].toString())
                            if (paths.length > 0)
                                root.startQwsLoad(paths)
                        }
                    }
                    ColumnLayout { anchors.centerIn: parent; spacing: 8
                        LabelText {
                            id: dropIcon
                            text: "\u21e9"
                            font.pixelSize: 26
                            font.weight: Font.DemiBold
                            color: qwsDrop.containsDrag ? colors.amber : colors.muted
                            Layout.alignment: Qt.AlignHCenter
                            scale: qwsDrop.containsDrag ? 1.15 : 1.0
                            Behavior on scale { NumberAnimation { duration: 160; easing.type: Easing.OutBack } }
                            Behavior on color { ColorAnimation { duration: 150 } }
                        }
                        LabelText { text: "DRAG or BROWSE"; font.pixelSize: 20; font.weight: Font.Black; color: qwsDrop.containsDrag ? colors.amber : colors.text; Layout.alignment: Qt.AlignHCenter; Behavior on color { ColorAnimation { duration: 150 } } }
                        SmallCaption { text: "Drop files or folders (each folder with its qw.sol)"; Layout.alignment: Qt.AlignHCenter }
                    }
                    // pulso del icono mientras hay un drag encima
                    SequentialAnimation {
                        running: qwsDrop.containsDrag
                        loops: Animation.Infinite
                        NumberAnimation { target: dropIcon; property: "opacity"; to: 0.45; duration: 450; easing.type: Easing.InOutQuad }
                        NumberAnimation { target: dropIcon; property: "opacity"; to: 1.0; duration: 450; easing.type: Easing.InOutQuad }
                    }
                }
                Rectangle {
                    visible: farm.qwsLoading
                    Layout.fillWidth: true
                    Layout.preferredHeight: 34
                    color: colors.canvas
                    border.color: colors.borderSoft
                    radius: 4
                    RowLayout { anchors.fill: parent; anchors.leftMargin: 10; anchors.rightMargin: 10; spacing: 10
                        ProgressBar { Layout.fillWidth: true; value: farm.qwsProgress / 100; barColor: colors.red }
                        LabelText { text: farm.qwsProgress + " pct"; color: colors.muted; font.pixelSize: 10; Layout.preferredWidth: 52 }
                    }
                }
                LabelText { visible: farm.qwsStatus.length > 0; text: farm.qwsStatus; color: colors.mint; font.pixelSize: 10; wrapMode: Text.WordWrap }
                RowLayout { Layout.fillWidth: true; spacing: 6
                    GhostButton { text: "Browse"; Layout.fillWidth: true; Layout.preferredWidth: 250; enabled: !farm.qwsLoading; onClicked: qwsFileDialog.open() }
                    GhostButton { text: "Cancel"; Layout.fillWidth: true; Layout.preferredWidth: 120; enabled: !farm.qwsLoading; onClicked: root.qwsOpen = false }
                }
            }
        }
    }

    FileDialog {
        id: qwsFileDialog
        title: "Upload qw.sol files"
        fileMode: FileDialog.OpenFiles
        nameFilters: ["QWS files (*.sol *.qws)"]
        currentFolder: "file:///C:/Users/ren/AppData/Roaming/Freakinware/QW Accounts"
        onAccepted: function() {
            var paths = []
            for (var i = 0; i < qwsFileDialog.selectedFiles.length; i++)
                paths.push(qwsFileDialog.selectedFiles[i].toString())
            if (paths.length > 0)
                root.startQwsLoad(paths)
        }
    }
}
