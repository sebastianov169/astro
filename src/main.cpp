// main.cpp - ASTRO: dashboard Qt Quick + motor de farmeo MitosOG
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QWindow>
#include <QTimer>
#include <QDir>
#include <QFile>
#include <QStandardPaths>
#include <QCryptographicHash>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

#include <thread>
#include <chrono>

#include "farm_controller.h"

#ifdef Q_OS_WIN
// ---------------------------------------------------------------------------
// Crash handler C-only (sin Qt): un AV deja la direccion del fallo en
// astro_crash.txt y el proceso termina limpio. El filter previo usaba QFile/
// QTextStream dentro del SEH (inseguro tras corrupcion de heap) y devolvia
// EXCEPTION_CONTINUE_SEARCH (el unwind de Qt podia crashear encima).
// ---------------------------------------------------------------------------
#include <cstdio>
#include <cstring>

// Ruta del log de crash: siempre junto al exe (build\Release\astro_crash.txt).
// Se calcula UNA vez con la API de Windows, nunca dentro del handler se usa Qt.
static char g_crashLogPath[MAX_PATH] = {0};
static void initCrashLogPath()
{
    if (g_crashLogPath[0] != '\0')
        return;
    char exe[MAX_PATH] = {0};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    char *slash = strrchr(exe, '\\');
    if (slash)
        *(slash + 1) = '\0';
    strcat_s(exe, "astro_crash.txt");
    strcpy_s(g_crashLogPath, exe);
}

// Append de una linea al log de crash. Cada llamada abre su propio handle
// (FILE_APPEND_DATA) para que varios hilos puedan escribir sin crashear.
static bool appendCrashLine(const char *line)
{
    initCrashLogPath();
    HANDLE h = CreateFileA(g_crashLogPath, FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    DWORD w = 0;
    WriteFile(h, line, (DWORD)std::strlen(line), &w, nullptr);
    WriteFile(h, "\r\n", 2, &w, nullptr);
    CloseHandle(h);
    return true;
}

// UnhandledExceptionFilter: escribe codigo + direccion de fallo + parametros +
// modulo, y termina el proceso sin dejar que Qt intente unwinding (que es lo
// que producia el segundo crash sobre el primero).
static LONG WINAPI sehHandler(PEXCEPTION_POINTERS ep)
{
    char line[1024] = {0};
    int n = _snprintf_s(line, _TRUNCATE,
                        "[SEH] exception 0x%08lX at 0x%llX thread=%lu",
                        (unsigned long)ep->ExceptionRecord->ExceptionCode,
                        (unsigned long long)(uintptr_t)ep->ExceptionRecord->ExceptionAddress,
                        (unsigned long)GetCurrentThreadId());
    // Volcado de registros del hilo que fallo: con el contexto se identifica el
    // fault real (p.ej. un puntero NULL en un buffer -> la instruccion que lo
    // usa, no el RIP reportado por Windows cuando el stack esta corrupto).
    if (ep->ContextRecord) {
        char regs[640] = {0};
        const CONTEXT *c = ep->ContextRecord;
        _snprintf_s(regs, _TRUNCATE,
                    " rip=%llX rsp=%llX rbp=%llX rax=%llX rbx=%llX rcx=%llX rdx=%llX"
                    " rsi=%llX rdi=%llX r8=%llX r9=%llX r10=%llX r11=%llX r12=%llX r13=%llX r14=%llX r15=%llX",
                    (unsigned long long)c->Rip, (unsigned long long)c->Rsp,
                    (unsigned long long)c->Rbp, (unsigned long long)c->Rax,
                    (unsigned long long)c->Rbx, (unsigned long long)c->Rcx,
                    (unsigned long long)c->Rdx, (unsigned long long)c->Rsi,
                    (unsigned long long)c->Rdi, (unsigned long long)c->R8,
                    (unsigned long long)c->R9, (unsigned long long)c->R10,
                    (unsigned long long)c->R11, (unsigned long long)c->R12,
                    (unsigned long long)c->R13, (unsigned long long)c->R14,
                    (unsigned long long)c->R15);
        strncat_s(line, sizeof(line), regs, _TRUNCATE);
    }
    if (ep->ExceptionRecord->NumberParameters > 0) {
        char info[320] = {0};
        int m = 0;
        const ULONG nParams = ep->ExceptionRecord->NumberParameters > 4
            ? 4 : ep->ExceptionRecord->NumberParameters;
        for (ULONG i = 0; i < nParams; ++i) {
            const int r = _snprintf_s(info + m, sizeof(info) - m, _TRUNCATE, "%s0x%llX",
                                      i ? "," : " info=",
                                      (unsigned long long)ep->ExceptionRecord->ExceptionInformation[i]);
            if (r > 0)
                m += r;
        }
        strncat_s(line, sizeof(line), info, _TRUNCATE);
    }
    HMODULE mod = nullptr;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           reinterpret_cast<LPCSTR>(ep->ExceptionRecord->ExceptionAddress), &mod)) {
        char modName[MAX_PATH] = {0};
        GetModuleFileNameA(mod, modName, MAX_PATH);
        strncat_s(line, sizeof(line), " module=", _TRUNCATE);
        strncat_s(line, sizeof(line), modName, _TRUNCATE);
    }
    appendCrashLine(line);
    TerminateProcess(GetCurrentProcess(), 1);
    return EXCEPTION_EXECUTE_HANDLER; // inalcanzable: ya se termino el proceso
}

// captura qWarning/qCritical/qFatal de Qt (QWaitCondition "Destroyed while
// threads are still waiting", QThreadStorage, QThread dtor, etc.) con prefijo
// [Q] en el mismo astro_crash.txt.
static void qtMsgHandler(QtMsgType type, const QMessageLogContext &, const QString &msg)
{
    if (type != QtWarningMsg && type != QtCriticalMsg && type != QtFatalMsg)
        return;
    const char *tag = type == QtWarningMsg ? "warning"
                    : type == QtCriticalMsg ? "critical" : "fatal";
    const QByteArray utf8 = msg.toUtf8();
    const QByteArray line = QByteArray("[Q] ") + tag + ": " + utf8;
    appendCrashLine(line.constData());
    if (type == QtFatalMsg) {
        abort();
    }
}
#endif

namespace {
// Soporta "--flag valor" y "--flag=valor". Rechaza tomar OTRO flag como valor
// (--device --debug ya no devuelve "--debug" como device id).
QString argValue(const QStringList &args, const QString &flag)
{
    for (int i = 0; i < args.size(); ++i) {
        const QString a = args.at(i);
        if (a == flag && i + 1 < args.size()) {
            const QString v = args.at(i + 1);
            if (!v.startsWith(QLatin1String("--")))
                return v;
            return QString();
        }
        if (a.startsWith(flag + QStringLiteral("=")))
            return a.mid(flag.size() + 1);
    }
    return QString();
}
bool hasArg(const QStringList &args, const QString &flag)
{
    return args.contains(flag);
}
// Entero positivo con rango: --duration/--autospawn invalidos no deben
// convertirse en 0 (stop inmediato) ni desbordar (secs*1000).
int intArg(const QStringList &args, const QString &flag, int minV, int maxV, int defV)
{
    const QString v = argValue(args, flag);
    if (v.isEmpty())
        return defV;
    bool ok = false;
    const int n = v.toInt(&ok);
    if (!ok)
        return defV;
    return qBound(minV, n, maxV);
}
}

int main(int argc, char *argv[])
{
#ifdef Q_OS_WIN
    SetUnhandledExceptionFilter(sehHandler);
    qInstallMessageHandler(qtMsgHandler);
    // evidencia de que los handlers quedaron instalados (antes de cualquier crash)
    initCrashLogPath();
    appendCrashLine("[SEH] handler installed");
#endif
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Astro"));
    app.setApplicationVersion(QStringLiteral("1.0"));
    app.setOrganizationName(QStringLiteral("Astro Labs"));

    QQuickStyle::setStyle(QStringLiteral("Basic"));

    FarmController farm;
    // el cierre de la ventana con farm activo detiene el worker y espera a que
    // el thread termine antes de destruir el engine
    QObject::connect(&app, &QCoreApplication::aboutToQuit, &farm, &FarmController::shutdown);

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty(QStringLiteral("farm"), &farm);
    // Load saved theme
    QString savedTheme = farm.loadTheme();
    engine.rootContext()->setContextProperty(QStringLiteral("savedTheme"), savedTheme);
    const QUrl url(QStringLiteral("qrc:/Astro/qml/Main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
                     &app, [](const QUrl &) { QCoreApplication::exit(-1); },
                     Qt::QueuedConnection);
    engine.load(url);

    QFile dbgf(QCoreApplication::applicationDirPath() + QStringLiteral("/astro_crash.txt"));
    if (dbgf.open(QIODevice::Append | QIODevice::Text)) {
        dbgf.write(QStringLiteral("roots=%1\n").arg(engine.rootObjects().size()).toUtf8());
        dbgf.close();
    }

    // cuentas QWS guardadas (accounts.json en AppData/Astro)
    QTimer::singleShot(0, &farm, [&farm]() {
        farm.loadAccounts();
        // BUG 2026-08-10: loadFarmSelection corria en el CONSTRUCTOR, cuando
        // m_accounts estaba vacio -> la validacion "exists" descartaba TODAS
        // las casillas guardadas. Recargar la seleccion DESPUES de cargar las
        // cuentas para que las casillas marcadas sobrevivan al reinicio.
        farm.loadFarmSelection();
    });

    const auto roots = engine.rootObjects();
    if (!roots.isEmpty()) {
        if (auto *window = qobject_cast<QWindow *>(roots.constFirst())) {
            window->show();
            window->raise();
            window->requestActivate();
            if (auto *quickWindow = qobject_cast<QQuickWindow *>(window)) {
                QTimer::singleShot(1500, quickWindow, [quickWindow]() {
                    const auto image = quickWindow->grabWindow();
                    image.save(QDir::current().filePath(QStringLiteral("astro-preview.png")));
                });
            }
        }
    }

    const QStringList args = app.arguments();
    const QString deviceValue = argValue(args, QStringLiteral("--device"));
    if (!deviceValue.isEmpty())
        farm.setDeviceId(deviceValue);

    if (hasArg(args, QStringLiteral("--debug")))
        farm.setDebugEnabled(true);

    if (hasArg(args, QStringLiteral("--fetch"))) {
        QTimer::singleShot(2000, &farm, [&farm]() { farm.fetchGems(); });
    }

    // Al abrir la app en modo GUI (sin --autospawn/--duration/--fetch): login
    // HTTP automatico de TODAS las cuentas guardadas (no solo la activa ni las
    // seleccionadas con casilla) para actualizar el nombre real, coins, gemas
    // disponibles y su XP (fetchAllGems: loginifneeded + inventory slot 5).
    // Solo si hay cuentas guardadas (sin cuentas el login seria ruido).
    // En headless el autospawn ya hace fetchGems, asi que aqui se evita el
    // login duplicado.
    if (!hasArg(args, QStringLiteral("--autospawn"))
        && !hasArg(args, QStringLiteral("--duration"))
        && !hasArg(args, QStringLiteral("--fetch"))) {
        QTimer::singleShot(1500, &farm, [&farm]() {
            if (!farm.accounts().isEmpty())
                farm.fetchAllGems();
        });
    }

    if (hasArg(args, QStringLiteral("--select-all"))) {
        // Hook de prueba/CI: marca TODAS las cuentas guardadas con la casilla
        // del workflow (headless: --select-all --autospawn 0 --duration N)
        QTimer::singleShot(3000, &farm, [&farm]() {
            const auto accs = farm.accounts();
            for (int i = 0; i < accs.size(); ++i)
                farm.toggleFarmSelection(i, true);
        });
    }

    if (hasArg(args, QStringLiteral("--headless-run"))) {
        // Hook de prueba en vivo: marca TODAS las cuentas y las spawnea
        // (--headless-run --duration N). El spawn() arranca cuando la
        // seleccion ya esta persistida (3s) y las gemas cacheadas (5s).
        QTimer::singleShot(3000, &farm, [&farm]() {
            const auto accs = farm.accounts();
            for (int i = 0; i < accs.size(); ++i)
                farm.toggleFarmSelection(i, true);
            QTimer::singleShot(3000, &farm, [&farm]() { farm.spawn(); });
        });
    }

    const QString gemValue = argValue(args, QStringLiteral("--autospawn"));
    if (!gemValue.isEmpty()) {
        const int gemId = intArg(args, QStringLiteral("--autospawn"), 1, 100000, 0);
        if (gemId > 0) {
            QTimer::singleShot(2500, &farm, [&farm, gemId]() { farm.fetchGems(); });
            QObject::connect(&farm, &FarmController::gemsChanged, &farm, [&farm, gemId]() {
                farm.selectGemById(gemId);
                QTimer::singleShot(3000, &farm, [&farm]() { farm.spawn(); });
            });
        } else {
            qWarning("--autospawn: valor invalido, ignorado");
        }
    }

    // SONDEO TEMPORAL (probe_shop): --probe-shop <device> hace login HTTP de
    // esa cuenta y prueba comandos candidatos de tienda contra el server real.
    // Se elimina al cerrar la feature Shop.
    const QString probeDevice = argValue(args, QStringLiteral("--probe-shop"));
    if (!probeDevice.isEmpty()) {
        QTimer::singleShot(1500, &farm, [&farm, probeDevice]() {
            // ruta del PEM fake TPM: fake_tpm/<md5(device)16>.pem (misma
            // logica que fakeTpmPathForDevice del farm_controller)
            QString base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
            if (base.isEmpty())
                base = QCoreApplication::applicationDirPath();
            const QString pemPath = base + QStringLiteral("/Astro/fake_tpm/")
                + QCryptographicHash::hash(probeDevice.toUtf8(), QCryptographicHash::Md5).toHex().left(16)
                + QStringLiteral(".pem");
            LoginManager local;
            if (!pemPath.isEmpty()) {
                QFile pf(pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
            }
            const LoginResult r = local.login(probeDevice);
            if (!r.ok) {
                qWarning("probe-shop: login fallo: %s", qUtf8Printable(r.error));
                QCoreApplication::exit(2);
                return;
            }
            qInfo("probe-shop: login ok (sk len %d)", int(r.sessionKey.size()));
            const QStringList bodies = {
                QStringLiteral("{\"do\":\"store\",\"category\":10,\"evo\":false}"),
                QStringLiteral("{\"do\":\"buy\",\"item\":1048594}"),
                QStringLiteral("{\"do\":\"buy\",\"item\":1048622}"),
                // SONDEO REPARACION: el inventory expone repair_price por gema.
                // La rota equipada es id=3962 (Gema Roja, durability 29/100).
                QStringLiteral("{\"do\":\"inventory\",\"slot\":5}"),
                QStringLiteral("{\"do\":\"asdf_nonexistent\"}"),
                QStringLiteral("{\"do\":\"repair\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair\",\"id\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair_item\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"gemrepair\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repair\",\"item\":3962,\"slot\":5,\"price\":22}"),
                QStringLiteral("{\"do\":\"repair\",\"id\":3962}"),
                QStringLiteral("{\"do\":\"fix\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"restore\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"mend\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"repairgem\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"equip\",\"item\":3962,\"slot\":5}"),
                QStringLiteral("{\"do\":\"refreshgem\"}"),
            };
            for (const QString &b : bodies) {
                const QJsonObject resp = local.apiCall(b);
                qInfo("probe: %s -> %s", qUtf8Printable(b),
                      qUtf8Printable(QString::fromUtf8(QJsonDocument(resp).toJson(QJsonDocument::Compact)).left(300)));
            }
            QCoreApplication::exit(0);
        });
    }

    const int durationSecs = intArg(args, QStringLiteral("--duration"), 1, 3600, 0);
    if (durationSecs > 0) {
        QTimer::singleShot(durationSecs * 1000, &farm, [&farm]() { farm.stopFarm(); });
        QTimer::singleShot(durationSecs * 1000 + 8000, &farm, [&farm]() { farm.quitApp(); });
        // Watchdog de sistema: si el GUI esta saturado (render del log QML con
        // miles de lineas) el QTimer del quitApp se retrasa y el cierre se
        // cuelga (observado: proceso vivo 10+ min tras el duration). Este hilo
        // garantiza la salida pase lo que pase; el shutdown normal (quitApp a
        // secs+8 + waits con tope) termina antes en el caso sano. Margen
        // generoso (secs+60): el shutdown espera los farms y el refreshAll
        // secuencialmente, y un refresh largo (cuentas sin gema con flujo
        // completo + spawn serializado por g_spawnMutex) puede tardar ~45s
        // extra; con 25s el watchdog ganaba la carrera y un run sano
        // terminaba con exit code 1.
        // TerminateProcess con exit code 1 (no 0): un cierre forzado por
        // watchdog NO debe parecer un exito de la corrida en automation.
#ifdef Q_OS_WIN
        std::thread watchdog([durationSecs]() {
            std::this_thread::sleep_for(std::chrono::seconds(durationSecs + 60));
            TerminateProcess(GetCurrentProcess(), 1);
        });
        watchdog.detach();
#endif
    }

    // Hook de prueba/verificacion: dispara refreshAllAccounts() tras N ms
    // (ej. --refreshall 20000 con los farms ya spawneados).
    const int refreshAllMs = intArg(args, QStringLiteral("--refreshall"), 0, 3600000, -1);
    if (refreshAllMs >= 0) {
        QTimer::singleShot(refreshAllMs, &farm, [&farm]() { farm.refreshAllAccounts(); });
    }

    // Hook de prueba/verificacion: dispara refreshXp() (el boton Refresh
    // manual: settle real de la cuenta activa) tras N ms.
    const int refreshXpMs = intArg(args, QStringLiteral("--refreshxp"), 0, 3600000, -1);
    if (refreshXpMs >= 0) {
        QTimer::singleShot(refreshXpMs, &farm, [&farm]() { farm.refreshXp(); });
    }

    return app.exec();
}
