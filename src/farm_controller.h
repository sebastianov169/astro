// farm_controller.h - puente QML <-> FarmWorker para la dashboard Astro
#pragma once

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <QThread>
#include <QPointer>
#include <QStringList>
#include <QMutex>
#include <QSet>
#include <QTimer>
#include <atomic>

#include "login.h"
#include "tcp_farm.h"

class QTimer; // auto-refresh de cuentas (miembro puntero, QTimer incluido en el .cpp)

class FarmController : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool farmRunning READ farmRunning NOTIFY farmRunningChanged)
    Q_PROPERTY(bool spawning READ spawning NOTIFY spawningChanged)
    Q_PROPERTY(double totalXpGained READ totalXpGained NOTIFY totalXpGainedChanged)
    Q_PROPERTY(bool autoRespawn READ autoRespawn WRITE setAutoRespawn NOTIFY autoRespawnChanged)
    Q_PROPERTY(bool autoRefreshEnabled READ autoRefreshEnabled NOTIFY autoRefreshChanged)
    Q_PROPERTY(int autoRefreshInterval READ autoRefreshInterval NOTIFY autoRefreshChanged)
    Q_PROPERTY(bool debugEnabled READ debugEnabled WRITE setDebugEnabled NOTIFY debugEnabledChanged)
    Q_PROPERTY(bool autoRepair READ autoRepair WRITE setAutoRepair NOTIFY autoRepairChanged)
    Q_PROPERTY(bool autoBuyX2 READ autoBuyX2 WRITE setAutoBuyX2 NOTIFY autoBuyX2Changed)
    Q_PROPERTY(bool fetching READ fetching NOTIFY busyChanged)
    Q_PROPERTY(QString deviceId READ deviceId WRITE setDeviceId NOTIFY deviceIdChanged)
    Q_PROPERTY(QString accountText READ accountText NOTIFY accountTextChanged)
    Q_PROPERTY(QString stateText READ stateText NOTIFY stateTextChanged)
    Q_PROPERTY(QString serverText READ serverText NOTIFY serverTextChanged)
    Q_PROPERTY(QString xpText READ xpText NOTIFY xpTextChanged)
    Q_PROPERTY(QString gemXpText READ gemXpText NOTIFY gemXpTextChanged)
    Q_PROPERTY(int deaths READ deaths NOTIFY xpTextChanged)
    Q_PROPERTY(bool spawned READ spawned NOTIFY xpTextChanged)
    Q_PROPERTY(int eventCount READ eventCount NOTIFY logLineAdded)
    Q_PROPERTY(int gemCount READ gemCount NOTIFY gemsChanged)
    Q_PROPERTY(int selectedGemIndex READ selectedGemIndex NOTIFY selectedGemChanged)
    Q_PROPERTY(QString selectedGemName READ selectedGemName NOTIFY selectedGemChanged)
    Q_PROPERTY(QVariantList gems READ gems NOTIFY gemsChanged)
    Q_PROPERTY(QVariantList accounts READ accounts NOTIFY accountsChanged)
    Q_PROPERTY(QVariantList filteredAccounts READ filteredAccounts NOTIFY accountsChanged)
    Q_PROPERTY(QVariantList farmSelection READ farmSelection NOTIFY farmSelectionChanged)
    Q_PROPERTY(QString accountSearch READ accountSearch WRITE setAccountSearch NOTIFY accountSearchChanged)
    Q_PROPERTY(QVariantList workflowAccounts READ workflowAccounts NOTIFY farmSelectionChanged)
    Q_PROPERTY(bool qwsLoading READ qwsLoading NOTIFY qwsProgressChanged)
    Q_PROPERTY(int qwsProgress READ qwsProgress NOTIFY qwsProgressChanged)
    Q_PROPERTY(QString qwsStatus READ qwsStatus NOTIFY qwsProgressChanged)
    Q_PROPERTY(bool refreshingAll READ refreshingAll NOTIFY refreshAllProgressChanged)
    Q_PROPERTY(int refreshAllProgress READ refreshAllProgress NOTIFY refreshAllProgressChanged)
    Q_PROPERTY(QString refreshAllStatus READ refreshAllStatus NOTIFY refreshAllProgressChanged)
    Q_PROPERTY(QVariantList activeSessions READ activeSessions NOTIFY activeSessionsChanged)

    // ---- Shop por cuenta (tienda de gemas, pedido 2026-08-08) ----
    // fetchShop(index) hace login HTTP de la cuenta y rellena shopGems con
    // las gemas (id, name, sprite, level, price, cexp/exp) + shopCoins.
    // buyShopGem(id) compra con {"do":"buy","item":<id>} (formato verificado
    // contra el server real: devuelve funds_insufficient si faltan coins).
    Q_PROPERTY(QVariantList shopGems READ shopGems NOTIFY shopChanged)
    Q_PROPERTY(qlonglong shopCoins READ shopCoins NOTIFY shopChanged)
    Q_PROPERTY(QString shopStatus READ shopStatus NOTIFY shopChanged)
    Q_PROPERTY(bool shopBusy READ shopBusy NOTIFY shopChanged)
    Q_PROPERTY(QString shopDeviceName READ shopDeviceName NOTIFY shopChanged)

    // ---- Prioridad de gemas (pedido 2026-08-08) ----
    // Todas las gemas unicas de todas las cuentas, en orden de prioridad de
    // farmeo (drag & drop en la UI). Persistida en QSettings. priorityGems()
    // devuelve la lista ordenada; moveGemPriority(from,to) reordena.
    Q_PROPERTY(QVariantList gemPriority READ gemPriority NOTIFY gemPriorityChanged)

public:
    explicit FarmController(QObject *parent = nullptr);
    ~FarmController() override;

    bool farmRunning() const;
    double totalXpGained() const { return m_totalXpGained; }
    int farmRunningCount() const;
    bool spawning() const { return m_spawning.load(); }
    QString logName(const QString &device, const QString &knownName) const; // prefijo de log: nombre o device corto
    bool autoRespawn() const { return m_autoRespawn; }
    bool autoRefreshEnabled() const;
    int autoRefreshInterval() const;
    bool debugEnabled() const { return m_debugEnabled; }
    bool autoRepair() const { return m_autoRepair; }
    bool autoBuyX2() const { return m_autoBuyX2; }
    bool fetching() const { return m_fetching; }
    QString deviceId() const { return m_deviceId; }
    QString accountText() const { return m_accountText; }
    QString stateText() const { return m_stateText; }
    QString serverText() const { return m_serverText; }
    QString xpText() const { return m_xpText; }
    QString gemXpText() const { return m_gemXpText; }
    int deaths() const { return m_deaths; }
    bool spawned() const { return m_spawned; }
    int eventCount() const { return m_logLines.size(); }
    int gemCount() const { return m_gems.size(); }
    int selectedGemIndex() const { return m_selectedGem; }
    QString selectedGemName() const { return m_selectedGem >= 0 && m_selectedGem < m_gems.size() ? m_gems.at(m_selectedGem).toMap().value(QStringLiteral("name")).toString() : QString(); }
    QVariantList gems() const { return m_gems; }
    QVariantList accounts() const { return m_accounts; }
    QVariantList filteredAccounts() const;
    QVariantList workflowAccounts() const; // solo cuentas seleccionadas (dashboard)
    QVariantList farmSelection() const { return m_farmSelection; }
    QString accountSearch() const { return m_accountSearch; }
    bool qwsLoading() const { return m_qwsLoading; }
    int qwsProgress() const { return m_qwsProgress; }
    QString qwsStatus() const { return m_qwsStatus; }
    bool refreshingAll() const { return m_refreshingAll; }
    int refreshAllProgress() const { return m_refreshAllProgress; }
    QString refreshAllStatus() const { return m_refreshAllStatus; }
    QVariantList activeSessions() const { return m_activeSessions; }

    // shop
    QVariantList shopGems() const { return m_shopGems; }
    qlonglong shopCoins() const { return m_shopCoins; }
    QString shopStatus() const { return m_shopStatus; }
    bool shopBusy() const { return m_shopBusy; }
    QString shopDeviceName() const { return m_shopDeviceName; }

    // prioridad de gemas
    QVariantList gemPriority() const { QVariantList r; for (int i : m_gemPriority) r.append(i); return r; }

public slots:
    void setAutoRespawn(bool on);
    void setDebugEnabled(bool on);
    void setAutoRepair(bool on);
    void setAutoBuyX2(bool on);
    void setDeviceId(const QString &id);
    void fetchGems();                 // login + inventory (thread propio)
    void fetchAllGems();              // login HTTP + inventory de TODAS las cuentas guardadas (thread propio)
    void spawn();                     // lanza el farm CTF (thread propio)
    void stopFarm();
    void refreshXp();                 // refresh XP (thread separado con sesion del farm)
    void selectGemIndex(int index);
    void selectGemById(int gemId);
    void equipGem(int index);                 // equipa un gem de la cuenta activa y lo persiste en accounts.json
    void clearLogs();
    void shutdown();                  // detiene workers y espera threads (sin salir)
    void quitApp();                   // shutdown + salida de la app

    // ---- cuentas QWS (qw.sol) ----
    Q_INVOKABLE void loadQwsFiles(const QVariantList &paths); // extrae device + loginifneeded (thread propio)
    Q_INVOKABLE void useAccount(int index);                   // activa una cuenta guardada
    Q_INVOKABLE void removeAccount(int index);                // borra una cuenta guardada
    Q_INVOKABLE void loadAccounts();                          // lee accounts.json al arrancar
    Q_INVOKABLE void toggleFavorite(int index);               // estrella favorito (sube la cuenta arriba)
    Q_INVOKABLE bool toggleFarmSelection(int index, bool checked); // casilla "a farmear" (max 10)
    // variantes por deviceId (robustas al modelo filtrado/ordenado de la UI)
    Q_INVOKABLE void useAccountByDevice(const QString &device);
    Q_INVOKABLE bool toggleFarmSelectionByDevice(const QString &device, bool checked);
    Q_INVOKABLE void clearFarmSelection();
    void saveFarmSelection();
    void loadFarmSelection();
    Q_INVOKABLE void refreshAllAccounts();                    // login x10 en paralelo: nombre/status/coins
    // v38: refresh SIMPLE = STOP de los farms + login nuevo de todas + respawn
    // de las cuentas que estaban farmeando (pedido: "volver a hacer todo").
    void maybeStartRefreshAllLogin();                         // poll hasta que los farms terminen
    void respawnDevices(const QStringList &devices);          // re-spawn tras el refresh
    Q_INVOKABLE void configureAutoRefresh(bool enabled, int intervalSeconds); // timer auto-refresh (intervalo >= 10s)
    // 2026-08-10 (pedido del usuario: "detecta el x2 de las gemas para TODAS
    // las cuentas guardadas"): login secuencial de cada cuenta (aunque no
    // farmee) + lectura del inventario de consumibles (slots 3 y 4) +
    // deteccion del "Double Gem XP" (id=8590) con durability>0. El resultado
    // (x2State/x2Reason) se persiste en accounts.json para el badge.
    Q_INVOKABLE void scanAllX2();
    // persiste x2State/x2Reason en la cuenta index de m_accounts (scanAllX2)
    void updateAccountX2(int index, int state, const QString &reason);
    Q_INVOKABLE QString theme() const;                       // tema persistido (QSettings) o "midnight"
    Q_INVOKABLE void saveTheme(const QString &theme);
    Q_INVOKABLE QString loadTheme();        // persiste el tema elegido en QSettings
    Q_INVOKABLE bool copyToClipboard(const QString &text);   // copia texto al portapapeles (C++ robusto)
    void setAccountSearch(const QString &text);               // filtro de busqueda
    static bool isValidTheme(const QString &theme);           // validacion unica de temas (BUG-9)

    // ---- shop por cuenta ----
    Q_INVOKABLE void fetchShop(const QString &device);        // login HTTP + inventory de la cuenta (thread propio)
    Q_INVOKABLE void buyShopGem(int gemId);                   // compra {"do":"buy","item":<id>} + refresca el shop
    Q_INVOKABLE void buyShopGemX2(int gemId);                 // compra 2 gemas (x2): dos sequential buy + refresh
    Q_INVOKABLE void repairGem(int gemId);                    // repara gema rota {"do":"repair","item":id,"slot":5}
    // ---- prioridad de gemas ----
    Q_INVOKABLE void moveGemPriority(int from, int to);       // reordena la lista de prioridad (drag & drop)
    // Aplica el orden FINAL del modelo QML al backend (robusto al drag): el
    // modelo visual se reordena en vivo y este metodo sincroniza m_gemPriority.
    Q_INVOKABLE void applyPriorityOrder(const QVariantList &orderedIds);
    Q_INVOKABLE void loadGemPriority();                       // lee QSettings al arrancar
    Q_INVOKABLE void saveGemPriority();                       // persiste en QSettings
    Q_INVOKABLE QVariantList priorityGems() const;            // todas las gemas unicas de las cuentas, ordenadas por prioridad
    // ---- auto-buy por color de la tienda (2026-08-10) ----
    // La tienda de gemas rota 2x/dia: 19:00 y 01:00 hora Colombia (UTC-5 sin
    // DST) = 00:00 y 06:00 UTC. El auto-buy compra 1 min despues del reinicio
    // (00:01/06:01 UTC) las gemas del color marcado que esten a la venta.
    Q_INVOKABLE void toggleAutoBuyColor(int colorIdx, bool on); // boton "Auto buy" por color (persistido)
    Q_INVOKABLE bool isAutoBuyColor(int colorIdx) const;        // estado del boton para el QML
    Q_INVOKABLE QString nextStoreBuyTime() const;               // proximo reinicio de tienda en hora local

signals:
    void farmRunningChanged();
    void spawningChanged();
    void totalXpGainedChanged();
    void autoRespawnChanged();
    void autoRefreshChanged();
    void debugEnabledChanged();
    void autoRepairChanged();
    void autoBuyX2Changed();
    void busyChanged();
    void deviceIdChanged();
    void accountTextChanged();
    void stateTextChanged();
    void serverTextChanged();
    void xpTextChanged();
    void gemXpTextChanged();
    void selectedGemChanged();
    void gemsChanged();
    void logLineAdded(const QString &line);   // linea legible del farm (estado)
    void debugLineAdded(const QString &line); // linea tecnica del farm
    void toastMessage(const QString &msg);
    void accountsChanged();
    void qwsProgressChanged();
    void refreshAllProgressChanged();
    void accountSearchChanged();
    void farmSelectionChanged();
    void activeSessionsChanged();
    void shopChanged();
    void gemPriorityChanged();
    void autoBuyColorsChanged();   // 2026-08-10: boton Auto buy por color (tienda 19:00/01:00 COT)

private slots:
    void onFarmDebug(const QString &text);
    void onAccountState(const QString &mode, const QString &region);
    void onRegionChanged(const QString &region);

private:
    void appendLog(const QString &line);
    void appendDebug(const QString &line);
    void writeLogFile(const QString &line);
    int gemItemId() const;
    void spawnOneFarm(const QString &deviceId, int gemId, const QString &accountName,
                      const QString &sessionSk = QString(), const QString &sessionMagic = QString(),
                      int tpmGroup = -1);
    QVariantMap gemMap(const GemInfo &g) const;
    QString colorFor(const QString &name) const;
    // 2026-08-10 (fuente unica de verdad): carga m_gems desde el cache de la
    // cuenta y deriva m_selectedGem del equippedGemId (misma fila del
    // inventario) + m_gemXpText desde esa fila. applyAccount y la persistencia
    // del spawn la usan: TODAS las vistas coinciden con el inventario.
    void applyAccountCache(const QVariantMap &am);
    QString resolveDeviceId() const;
    QString shortDevice(const QString &d) const;
    void rebuildActiveSessions();
    void rebuildAggregate(); // suma XP/muertes/spawned de TODOS los farms
    void runStoreAutoBuy();  // 2026-08-10: timer 30s — compra colores marcados 1 min tras el reinicio de tienda (00:01/06:01 UTC)
    void saveAccounts();
    void sortAccounts();                       // favoritos primero, luego A-Z
    void applyRefreshResult(int index, const QVariantMap &result, bool emitChange = true);
    int accountIndexForFiltered(int filteredIndex) const; // indice real desde la lista filtrada
    void applyAccount(int real); // device + nombre + gemas cacheadas de una cuenta (indice real)
    void onFarmXp(FarmWorker *w, double xpGained, double lastXp, int deaths, bool spawned);
    void onGemXpRead(FarmWorker *w, qlonglong cexp, qlonglong exp); // XP de la gema SOLO por HTTP (inventory slot=5)
    void onFarmState(FarmWorker *w, const QString &text);
    void onFarmFinished(FarmWorker *w, bool ok, const QString &error);
    void onXpRefreshDone(FarmWorker *w, bool ok, qlonglong cexp, qlonglong exp, qlonglong delta, int lvl, const QString &error);

    QString m_deviceId;
    QString m_accountText = QStringLiteral("No account loaded");
    QString m_stateText = QStringLiteral("Select a gem and press Spawn CTF");
    QString m_serverText = QStringLiteral("State: -- | Server: --");
    QString m_xpText = QStringLiteral("XP gained: 0");
    QString m_gemXpText = QStringLiteral("Gem XP: --  |  Gained (delta): --  |  Level: --");
    int m_deaths = 0;
    bool m_spawned = false;
    double m_totalXpGained = 0;
    bool m_autoRespawn = true;
    std::atomic<bool> m_debugEnabled{false}; // leido desde hilos de login/refreshAll (race formal si es bool plano)
    bool m_autoRepair = false;
    bool m_autoBuyX2 = false;
    bool m_fetching = false;
    // anti-data-loss: true solo cuando loadAccounts() completo; saveAccounts()
    // no escribe antes (arranque con QML roto -> shutdown -> no tocar el JSON)
    bool m_accountsLoaded = false;

    QVariantList m_gems;
    int m_selectedGem = -1;
    // shop por cuenta: gemas del inventory + coins de la cuenta del shop
    QVariantList m_shopGems;
    qlonglong m_shopCoins = 0;
    QString m_shopStatus;
    bool m_shopBusy = false;
    QString m_shopDeviceName;
    QString m_shopDevice;
    // prioridad de gemas: lista de indices de color (0-19) en orden de farmeo.
    // El auto-buy del spawn compra primero el color que esta mas arriba.
    // Las 20 gemas son: black(0)..teal(19), misma matriz que gemSpritePath.
    QVector<int> m_gemPriority;
    // 2026-08-10: auto-buy de la TIENDA por color (boton "Auto buy" en la
    // seccion de prioridad). QSet de indices 0-19 con compra automatica.
    // La tienda rota 19:00 y 01:00 hora Colombia (UTC-5, sin DST) = 00:00 y
    // 06:00 UTC; la compra se dispara 1 min despues (00:01/06:01 UTC) para
    // que funcione desde cualquier zona horaria.
    QSet<int> m_autoBuyColors;
    QTimer *m_storeBuyTimer = nullptr;      // tick cada 30s: dispara la compra
    QString m_lastStoreBuySlot;             // "yyyy-MM-dd HH" UTC ya comprado
    qlonglong m_gemXpInitial = -1;
    QString m_farmRegion;
    QString m_accountMode;
    QVariantList m_activeSessions;
    QStringList m_logLines;
    QStringList m_debugLines;

    // cuentas QWS (qw.sol) guardadas en AppData/Astro/accounts.json
    QVariantList m_accounts;
    bool m_qwsLoading = false;
    int m_qwsProgress = 0;
    QString m_qwsStatus;
    QThread *m_qwsThread = nullptr;

    // Multi-farm: un handle por cuenta spawneada. Cada uno tiene su thread+worker.
    // QPointer (2026-08-12, crash STOP): el worker se destruye via deleteLater
    // cuando su thread termina (en el propio worker thread), y el GUI lo quita
    // de m_farms DESPUES (queued). Cualquier uso de un puntero crudo en esa
    // ventana es UB -> vtable NULL (SEH 0xC0000005 rip=0). QPointer se anula
    // solo al morir el objeto: todos los `if (fh.worker)` se vuelven seguros.
    struct FarmHandle {
        QPointer<QThread> thread;
        QPointer<FarmWorker> worker;
        QString deviceId;
        QString pemPath;
        QString accountName;
        QString gemName;
        double lastXp = 0;
        int deaths = 0;
        bool spawned = false;
        qlonglong lastGemCexp = -1;
        qint64 startedAt = 0; // epoch ms cuando el farm entro en modo "Farming"
    };
    QVector<FarmHandle> m_farms;
    FarmHandle* handleFor(FarmWorker *w);
    QThread *m_refreshThread = nullptr;
    bool m_refreshing = false;
    QThread *m_fetchThread = nullptr;

    // refresh all (login x10 en paralelo)
    bool m_refreshingAll = false;
    int m_refreshAllProgress = 0;
    QString m_refreshAllStatus;
    QThread *m_refreshAllThread = nullptr;
    bool m_refreshWaitingFarms = false;      // v38: esperando el STOP de los farms
    qint64 m_refreshWaitDeadline = 0;        // v40: timeout de 15s de la espera
    QStringList m_refreshRespawnDevices;     // v38: devices a re-spawnear al terminar
    QString m_accountSearch;
    QVariantList m_farmSelection; // devices seleccionados para farmear (max 10)
    QTimer *m_autoRefreshTimer = nullptr; // auto-refresh de cuentas (intervalo en ms)
    // Coalescing de updates de alta frecuencia (onFarmXp/onGemXpRead): con 9
    // farms cada xpUpdate/gemXpRead emitia accountsChanged + rebuilds, y la
    // GUI reconstruia los modelos QML a rafagas. Un QTimer de 300ms agrupa
    // los cambios pendientes en UNA emision (ESC-1).
    QTimer *m_uiFlushTimer = nullptr;
    bool m_uiDirty = false;
    void scheduleUiFlush();
    void flushUi();

    // Logs: appendDebug corre TAMBIEN desde los hilos de login del spawn
    // (linea "[DBG] spawnLogin ..." dentro del started lambda) - sin mutex eso
    // es una data race sobre QStringList cuando el switch Debug esta ON y el
    // multi-farm spawnea 10 cuentas a la vez (AV en RUN).
    QMutex m_debugMutex;
    // Threads de login del spawn() paralelo: no eran esperados en shutdown/dtor
    // (ExitProcess los mataba a mitad de un HTTP) -> "QWaitCondition: Destroyed
    // while threads are still waiting" / QThreadStorage al cerrar.
    QVector<QThread *> m_spawnThreads;
    // Orquestador del pre-spawn (tandas de 1): se guarda para poder abortarlo
    // y esperarlo en shutdown/dtor. El flag evita que re-arranque un hilo ya
    // esperado (UAF) cuando el usuario cierra durante el pre-spawn.
    QThread *m_spawnOrch = nullptr;
    std::atomic<bool> m_abortingSpawn{false};
    // BUG 2026-08-08: el guard de spawn() solo miraba farmRunning() (m_farms
    // vacio durante los logins del pre-spawn ~16-25s), asi un 2do clic en RUN
    // lanzaba OTRO juego de logins y duplicaba todos los farms (13 sesiones
    // con 7 cuentas, 2 lotes de "Spawning" en el log). m_spawning cubre la
    // ventana del pre-spawn: se setea al entrar a spawn() y se limpia cuando
    // el orquestador termina (o en stopFarm/shutdown).
    std::atomic<bool> m_spawning{false};
    // Aborto cooperativo del refreshAll (familia 0x1CE857, verificado 2026-08-08):
    // el SEH residual aparecia cuando el refreshAll (flujos completos con
    // login+spawn TCP de cuentas sin gema) seguia corriendo DURANTE los waits
    // del shutdown (los 2 flujos construyen QNAM/QJsonObject/QTcpSocket en
    // paralelo con la GUI esperando). shutdown() setea el flag; el lambda del
    // refreshAll lo checa entre tandas y los threads del batch entre cuentas.
    std::atomic<bool> m_abortingRefreshAll{false};
};
