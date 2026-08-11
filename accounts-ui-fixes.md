# Accounts Panel UI Fixes

**Estado: TODOS APLICADOS Y VERIFICADOS (build 2026-08-07).**

## Iteración 2026-08-07 (velocidad de refresh + crash al cierre)

### Refresh 2.3x más rápido (requisito del usuario)
- `kSettlePollMs` 72000 → **30000** (tcp_farm.cpp): el settle aterriza ~6s tras el
  fin de sesión (verificado en vivo: 4/4 cambios en el poll 1). Las cuentas sin
  ganancia quedaban clavadas en "Refreshing" 75s haciendo 12 polls inútiles.
  Ahora: refreshAll completo de 9 cuentas en **~35s** (antes ~80s).
- Early-exit del poll: sin sesión que settlear (spawn FFA falló y sin farm
  activo) el poll se salta entero (delta 0 honesto) en vez de esperar 30s.

### Crash al cierre (AV 0xC0000005 en Qt6Core+0x1CE857, ~1 de cada 4 cierres)
- **Causa raíz**: `ExitProcess(0)` ejecuta el teardown de Qt (DllMain DETACH +
  TLS destructors de Qt6Core/Qt6Qml) con los hilos Qt moribundos → AV
  intermitente en la familia SHA-512 de QCryptographicHash + warnings
  QThreadStorage/QDxgiVSyncService/QWaitCondition en CADA cierre.
- **Fix**: `TerminateProcess(0)` en shutdown() y dtor — mata el proceso sin
  ejecutar el teardown de Qt. Cierre 100% limpio: 0 warnings, 0 SEH (7 runs
  consecutivos de estrés spawn+refreshAll+cierre sin crash).
- Data race eliminada: el status "Refreshing" se marcaba DESDE el hilo del
  refreshAll sobre `m_accounts` (QVariantList COW, no thread-safe) — corrupción
  de heap. Ahora se marca en el hilo GUI antes de lanzar el thread.
- HTTP/1.1 forzado en los 4 sitios de request (httpGetTcp/httpPostTcp/httpGet/
  httpPost): el stack h2 de Qt 6.10.3 tiene races con GOAWAY del server; con h1
  los warnings GOAWAY desaparecieron por completo.
- SEH handler: ahora vuelca los 17 registros del hilo que falló (rip/rsp/rax/
  rdx/r8-r15) para diagnosticar cualquier crash futuro.

### UI
- ★ favorito restaurado en ambos delegates (el C++ toggleFavorite existía pero
  el QML no lo llamaba).
- Tile "ACTIVE SESSIONS" muestra `farm.activeSessions.length` (sesiones vivas),
  no la cantidad de cuentas seleccionadas.
- Footer sidebar: "v1.0 · by Ren".
- Bindings QML endurecidos contra undefined (sprite/gemSummary/exp/
  accountStartTimes) + defaults `xpGained`/`farmStatus` en loadAccounts y el
  loader QWS; `saveAccounts()` persiste `xpGained`.

## Cambios evolutivos respecto a este doc (el diseño siguió avanzando):
- Sidebar top: en vez de "By Ren", el header muestra el branding actual
  "+ ASTRO / Gem Farmer"; "by Ren" se añadió al footer junto a la versión.
- El delegate actual conserva la fila de gema/XP del dashboard (información
  útil) y el Accounts page usa checkbox de selección para farmear (mejor UX
  que el "Use" por fila). La estrella ★ (favorito) quedó restaurada en AMBOS
  delegates (el C++ toggleFavorite ya existía pero el QML no la llamaba).
- "LOADED GEMS" no existe en la sección Accounts (el panel derecho es el
  inventory "Gem inventory", que este doc excluye explícitamente).

Fix de crash añadido en esta iteración (AV 0xC0000005 en Qt6Core.dll tras
ráfagas de "Unable to assign [undefined] to bool" durante refreshAll x10):
- `loadAccounts()` y el loader QWS ahora SIEMPRE insertan `xpGained` (0) y
  `farmStatus` ("") en cada cuenta; `saveAccounts()` persiste `xpGained`.
- Bindings QML sin guard endurecidos (`modelData.sprite && ...` →
  `modelData.sprite !== undefined && ...`; idem gemSummary y exp).
- Fix de formato `%.0f` → `%1` en "FFA dwell" y "Settle poll" (tcp_farm.cpp).
- Tile "ACTIVE SESSIONS" ahora muestra `farm.activeSessions.length` (sesiones
  vivas) en vez de la cantidad de cuentas seleccionadas.

## Archivos a modificar
- `qml/Main.qml` — Sidebar (lines 281, 333-346), Panel izquierdo Accounts (lines 705-782)

---

## 1. Sidebar top: reemplazar "NIGHT OPERATIONS" por "By Ren"

**Línea 281** — Cambiar `"NIGHT OPERATIONS"` → `"By Ren"`

---

## 2. Sidebar bottom: reemplazar SYSTEM HEALTH por "Astro 1.0"

**Eliminar** las líneas 333-346 (Panel SYSTEM HEALTH + "ASTRO // AFTER DARK").

**Reemplazar con:**

```qml
Panel {
    Layout.fillWidth: true
    Layout.preferredHeight: 60
    color: colors.surface2
    ColumnLayout {
        anchors.fill: parent; anchors.margins: 12; spacing: 2
        LabelText { text: "ASTRO"; color: colors.mint; font.pixelSize: 14; font.weight: Font.Black; font.letterSpacing: 2 }
        LabelText { text: "v1.0"; color: colors.faint; font.pixelSize: 10 }
    }
}
```

---

## 3. Accounts header: "Refresh All" texto completo

**Línea 715** — GhostButton `Layout.preferredWidth: 92` → `110`

---

## 4. Delegate de cuenta: nombre grande, sin device ID, sin botones Use/X

**Eliminar** las líneas 749-767 (ListView delegate actual).

**Reemplazar con:**

```qml
ListView {
    Layout.fillWidth: true
    Layout.fillHeight: true
    Layout.minimumHeight: 120
    clip: true
    spacing: 3
    model: farm.filteredAccounts
    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
    delegate: Rectangle {
        width: ListView.view.width
        height: 52
        radius: 5
        color: modelData.device === farm.deviceId ? "#32151e" : (modelData.favorite ? colors.surface3 : colors.surface2)
        border.color: modelData.device === farm.deviceId ? colors.amber : (modelData.favorite ? "#5a3a45" : colors.borderSoft)
        border.width: 1
        RowLayout {
            anchors.fill: parent
            anchors.leftMargin: 10
            anchors.rightMargin: 10
            spacing: 8
            LabelText {
                text: modelData.favorite ? "★" : "☆"
                color: modelData.favorite ? colors.amber : colors.faint
                font.pixelSize: 16
                Layout.preferredWidth: 18
                MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; z: 1; onClicked: farm.toggleFavorite(index) }
            }
            LabelText {
                text: modelData.name
                font.pixelSize: 14
                font.weight: Font.Bold
                Layout.fillWidth: true
                elide: Text.ElideRight
            }
            LabelText {
                visible: modelData.coins > 0
                text: "¤ " + modelData.coins
                color: colors.mint
                font.pixelSize: 11
            }
            Rectangle {
                Layout.preferredWidth: 26
                Layout.preferredHeight: 26
                radius: 5
                color: removeArea.containsMouse ? "#3d1520" : "transparent"
                LabelText { anchors.centerIn: parent; text: "🗑"; font.pixelSize: 13 }
                MouseArea {
                    id: removeArea
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    z: 1
                    onClicked: farm.removeAccount(index)
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
```

**Nota:** MouseArea de ★ y 🗑 tienen `z: 1` para interceptar clicks antes del MouseArea de la fila (`z: -1`).

---

## 5. Quitar "LOADED GEMS" de la sección Accounts

**Eliminar** las líneas 771-781:
```
Rectangle { ... height: 1 ... }
SmallCaption { text: "LOADED GEMS" }
ListView { ... gemsQmlModel ... }
```

---

## Cambios NO requeridos
- No se toca el panel derecho (gem inventory)
- No se modifica el header "Accounts"
- No se toca el search field
- No se modifica la lógica C++

## Verificación
- Build 0 errores (cmake --build)
- App abre (roots=1)
- Account click → nombre visible + gems cargadas en panel derecho
- ★ toggle → favorito arriba
- 🗑 remove → elimina cuenta
- "Refresh All" texto completo visible
- Sidebar muestra "ASTRO 1.0" y "By Ren"
