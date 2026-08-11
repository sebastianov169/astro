# Astro

Farm bot para MitosisOG — app de escritorio **Qt6 / QML (C++)** que mantiene
múltiples cuentas vivas farmeando gemas en **CTF público (gamemode 3)**.

## Requisitos

- **Visual Studio 2026** (MSVC x64, incluye CMake) — o cualquier VS con CMake
- **Qt 6.10+** (QML + Quick Controls) — el `CMakeLists.txt` usa
  `find_package(Qt6 ...)`; ajusta `CMAKE_PREFIX_PATH` si tu Qt no está en el
  path por defecto

## Build y ejecución

```bat
build_astro.bat
```

El script:
1. Cierra `Astro.exe` si está corriendo (el exe bloqueado impide el link)
2. Configura el proyecto con CMake la primera vez (`-S . -B build`)
3. Compila Release → `build\Release\Astro.exe`
4. Pregunta si quieres abrir la app

Alternativa manual:

```bat
cmake -S . -B build
cmake --build build --config Release
build\Release\Astro.exe
```

## Uso

1. **Upload QWS** — carga los archivos `qw.sol` de las cuentas
2. **Workflow** — marca las cuentas a farmear (casilla), activa auto-respawn,
   auto-repair y auto-buy x2
3. **Gem Priority** — ordena los colores de gemas por prioridad de farmeo y
   marca **AUTO BUY** en los colores que quieras comprar automáticamente en la
   tienda (rota 19:00/01:00 hora Colombia = 00:00/06:00 UTC, compra 1 min
   después)
4. **RUN** — spawnea todas las cuentas seleccionadas en CTF público

## Estructura

| Ruta | Contenido |
|------|-----------|
| `src/` | C++: `main.cpp`, `farm_controller.*` (orquestador), `login.*` (HTTP + M2XC), `tcp_farm.*` (sesión TCP desturple/AMF3), `crypto.*` |
| `qml/Main.qml` | Toda la UI (tema oscuro, acento amarillo) |
| `assets/gems/` | Sprites de las 20 gemas × 5 bandas |
| `build_astro.bat` | Script de build |

## Características

- **Multi-farm paralelo**: un QThread + FarmWorker por cuenta, sesión TCP
  propia (desturple + AMF3) y HTTP M2XC
- **Replicación del binario real** (validado con captura Frida): NATIVE_PLAY
  cada ~7s, mmm periódico con tag creciente, sin MOVE TCP proactivo
- **Reconexión robusta**: connect bajo lock de spawn (1 conexión por IP a la
  vez), stagger por cuenta, backoff adaptativo, server fresco por retry
- **Auto-repair** de gemas rotas en cada spawn/respawn
- **Auto-buy x2** con verificación real (respuesta del `buy` del server:
  ok / already_owned / sin coins)
- **Auto-buy de tienda por color** con timer UTC (funciona desde cualquier
  país)
- **Fuente única de verdad** para la gema equipada: `equippedGemId` — las 3
  vistas (Workflow, Current gem progress, inventario) derivan del mismo campo
- Dashboard con badges **PRIORIDAD** y **x2 ✓/✗** por cuenta

## Notas

- Las claves TPM fake por cuenta se generan en
  `%LOCALAPPDATA%\Astro\fake_tpm\` (una PEM por deviceId)
- `accounts.json` vive en `%LOCALAPPDATA%\Astro\` (no se versiona)
- Los logs de sesión van a `build/Release/astro_farm.log`
