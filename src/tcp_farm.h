// tcp_farm.h - protocolo TCP de Mitos.is (desturple/M2XC/AMF3) + worker de farmeo CTF
#pragma once

#include <QString>
#include <QByteArray>
#include <QJsonObject>
#include <QThread>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QScopedPointer>
#include <QRandomGenerator>
#include <QList>
#include <atomic>
#include <vector>
#include <cstdint>
#include <functional>

#include "crypto.h"

class QNetworkAccessManager;

// ================================================================
// Primitivas del protocolo TCP (portadas de mitosis_client.py)
// ================================================================
namespace tcp {

Bytes writeU29(std::uint32_t value);

// ---- AMF3 encode ----
Bytes amfNull();
Bytes amfBool(bool v);
Bytes amfInt(std::int32_t v);
Bytes amfDouble(double v);
Bytes amfString(const QString &v);
Bytes amfArray(const std::vector<Bytes> &values);

// ---- AMF3 decode (solo arrays/valores que usa el farm) ----
struct AmfValue {
    enum Type { Null, Bool, Int, Double, Str, Arr } type = Null;
    bool b = false;
    std::int64_t i = 0;
    double d = 0.0;
    QString s;
    std::vector<AmfValue> arr;
};
class Amf3Decoder {
public:
    explicit Amf3Decoder(const Bytes &data);
    AmfValue readValue();
    bool ok() const { return m_error.isEmpty(); }
    QString error() const { return m_error; }
private:
    Bytes m_data;
    size_t m_pos = 0;
    QString m_error;
    std::vector<QString> m_stringRefs;
    std::uint8_t readU8();
    Bytes readBytes(size_t n);
    std::uint32_t readU29();
    double readDouble();
    QString readStringData();
    AmfValue readArray();
};

// ---- Mersenne Twister (idéntico al binario) ----
class MersenneTwister {
public:
    explicit MersenneTwister(std::uint32_t seed);
    std::uint32_t nextVal();
    void saveState(std::uint32_t out[624], int &outIndex) const;
    void restoreState(const std::uint32_t in[624], int index);
private:
    std::uint32_t m_mt[624];
    int m_index = 624;
};

std::uint32_t getStrKey(const QString &text);
std::int32_t getByteKey(const Bytes &data);

// ---- M2XC TCP wire ----
std::uint32_t xorshift32(std::uint32_t state);
Bytes m2xcTcpEnc(const Bytes &data, std::uint32_t seed, std::uint32_t ts = 100);
Bytes m2xcTcpDec(const Bytes &data, std::uint32_t seed, std::uint32_t ts = 100);
Bytes xorStep(const Bytes &data, std::uint32_t seed);
Bytes xorUnstep(const Bytes &data, std::uint32_t seed);
Bytes interleave(const Bytes &data, int half, int parity);
Bytes interleaveInv(const Bytes &data, int half, int parity);
Bytes bytearrayResturple(const Bytes &decoded, std::uint32_t seed);
Bytes bytearrayDesturple(const Bytes &data, std::uint32_t seed);

// ---- Frames C->S ----
Bytes makeClientFrame(const Bytes &amfPayload, int originalLen, std::uint8_t checksum, std::uint32_t seed);
Bytes makeAuthFrame(const QString &host, const QString &suffix, const QString &token,
                    int mode, const QString &invite, QString *bodyHttpOut);
Bytes makePongFrame(std::uint32_t seed, double nowMs);
Bytes makeReadyFrame(std::uint32_t seed);
Bytes makeClear10034();
Bytes makeTcpMove(double moveFirst, double angle, double power);
Bytes makeNativePlayFrame(std::uint32_t seed, const QString &nonce, const QString &suffix);
// NATIVE_PLAY con flag explicito: el binario envia [5,[challenge,true]] y luego [5,[challenge,false]]
Bytes makeNativePlayFrameFlag(std::uint32_t seed, const QString &nonce, const QString &suffix, bool flag);
Bytes makeNativePlayFrameKeyed(std::uint32_t seed, const QString &nonce, const Bytes &key, bool flag);
Bytes makeNativePlayFrameKeyedRaw(std::uint32_t seed, const Bytes &toEncrypt, const Bytes &key, bool flag);
// v92 (CAPTURA 2026-08-14): JOIN op5 con el TOKEN PLANO (b64 de 52 chars
// "00000008TTJYQ...") como challenge del frame [5,[token,false]] — SIN AES
// del contenido. El binario re-cifra el token solo con el cifrado del WIRE
// (seed), no con eb(suffix): el string del frame del binario mide lo MISMO
// que el op53 (52 chars, no 84+ del m2xc con AES).
Bytes makeJoinFramePlain(std::uint32_t seed, const QString &token, bool flag);
// NATIVE_PLAY de SPAWN real del juego: [5, [false]] + 3 ceros + resturple(seed)
Bytes makeNativePlaySpawnFrame(std::uint32_t seed);
// CLIENT_ENTITIES_INFO [10002, [0]] + CLIENT_EQUIPMENT_DATA [10037, []]
Bytes makeEntityInfoFrame(std::uint32_t seed);
Bytes makeEquipmentDataFrame(std::uint32_t seed);
// CLIENT_CONFIRM_UDP [10033] - respuesta al op 51 del server
Bytes makeConfirmUdpFrame(std::uint32_t seed);
// Frame IRC (el chat va por el MISMO socket del juego): [wlen][olen][chk=0][texto\r\n]
Bytes makeIrcFrame(const QString &text);
Bytes makeProofFrame(const QString &challenge, const QString &suffix, const QString &deviceId,
                     std::uint32_t seedMt, const QString &attestPem, QString *proofStrOut,
                     const QString &nonceOverride = QString());

QString decryptChallenge(const QString &challenge, const QString &suffix);

} // namespace tcp

// ================================================================
// FarmWorker - spawn en CTF Europa + loop de farmeo (QThread)
// ================================================================
class FarmWorker : public QObject
{
    Q_OBJECT
public:
    explicit FarmWorker(QObject *parent = nullptr);
    ~FarmWorker() override;

    void configure(const QString &deviceId, const QString &pemPath, int gemItem);
    // Lista de prioridad de gemas (ids de color 0-19, orden de farmeo): si la
    // gema actual esta rota (durability 0 y sin repair), el worker cambia a la
    // siguiente disponible de esta lista (tarea del amigo 2026-08-11).
    void setGemPriorityList(const QVector<int> &priority) { m_gemPriorityList = priority; }
    // Cambia a la siguiente gema de la prioridad cuando la actual esta rota.
    void switchToNextGem(QNetworkAccessManager *net, const QString &sk, const QString &magic,
                         const QJsonArray &items);
    // Jitter de reconexion ampliado + sesgo por deviceId: des-sincroniza los
    // reintentos cuando varias cuentas caen a la vez (farm inestable 2026-08-11).
    int reconnectJitterMs() const { return QRandomGenerator::global()->bounded(4000); }
    void setUseRoom(bool useRoom) { m_useRoom = useRoom; }
    void setAutoRespawn(bool on) { m_autoRespawn.store(on); }
    void setAutoRepair(bool on) { m_autoRepair.store(on); }
    void setAutoBuyX2(bool on) { m_autoBuyX2.store(on); }
    // 2026-08-10: estado REAL del auto-buy x2 para el dashboard (indicador
    // "x2 ✓/✗" por cuenta): 0=sin intento, 1=comprado, 2=fallo, 3=sin coins.
    int x2State() const { return m_x2State.load(); }
    QString x2Reason() const { return m_x2Reason; }
    void setX2State(int s, const QString &r) { m_x2State.store(s); m_x2Reason = r; }
    // 2026-08-10 (pedido del usuario: deteccion binaria verde/rojo): consulta
    // el store cat=6 + userinfo y actualiza el estado REAL del x2. Se llama
    // INMEDIATO en postSpawn (no esperar 60s) y cada 5 min en el loop.
    // La senal real del server es la respuesta del buy: ok=comprado,
    // already_owned=ya activo (verde); sin coins/fallo=no hay x2 (rojo).
    void checkX2(QNetworkAccessManager *net, const QString &sk, const QString &magic);
    // Aborto cooperativo EXTERNO (verificado 2026-08-08, familia 0x1CE857):
    // el refreshXp del worker local del refreshAll pollea el settle hasta
    // 60s; si el shutdown empieza mientras, el poll seguira y los QJsonObject/
    // QHash de ese flujo se solapan con el teardown -> SEH [r13+0x78..0x84].
    // El controller setea m_abortPtr = &m_abortingRefreshAll y refreshXp()
    // corta los loops largos (spawn, dwell, poll) en <=1 iteracion.
    void setAbortFlag(std::atomic<bool> *f) { m_abortPtr = f; }
    bool aborted() const { return m_abortPtr && m_abortPtr->load(); }
    // region CTF del farm (europe/central_america/south_america/australia): se elige
    // random al inicio de cada run/restart_session. El refresh la usa para cambiar a
    // una region distinta y para volver a CTF.
    void setRegion(const QString &region) { QMutexLocker lk(&m_sessionMutex); m_region = region; }
    QString region() const { QMutexLocker lk(&m_sessionMutex); return m_region; }
    // Sesion del farm activo: un worker de refresh en thread SEPARADO copia
    // sk/magic/indice de connect y la XP inicial ANTES de moverse al thread y
    // hace su propio flujo FFA/HvZ/CTF sin tocar el socket del farm.
    void setSession(const QString &sk, const QString &magic, int connectIndex,
                    qlonglong gemExpInicial, qlonglong gemCexpInicial)
    {
        QMutexLocker lk(&m_sessionMutex);
        m_sk = sk;
        m_magic = magic;
        m_connectIndex = connectIndex;
        m_gemExpInicial = gemExpInicial;
        m_gemCexpInicial = gemCexpInicial;
    }
    QString sessionSk() const { QMutexLocker lk(&m_sessionMutex); return m_sk; }
    QString sessionMagic() const { QMutexLocker lk(&m_sessionMutex); return m_magic; }
    int gemItem() const { return m_gemItem; }
    // Equip verificada en el pre-connect (2026-08-10): si es true, el
    // postSpawnSequence salta el bloque inventory/news/equip (5 HTTP que se
    // serializan en el g_loginMutex global — con 10 farms el postSpawn tardaba
    // 13s y el server cortaba a los ~12s del [20] sin PONGs).
    bool m_gemEquipped = false;
    int connectIndex() const { QMutexLocker lk(&m_sessionMutex); return m_connectIndex; }
    qlonglong gemExpInicial() const { QMutexLocker lk(&m_sessionMutex); return m_gemExpInicial; }
    qlonglong gemCexpInicial() const { QMutexLocker lk(&m_sessionMutex); return m_gemCexpInicial; }
    // El refresh (thread separado) activa esto mientras corre: el loop del farm
    // sigue atendiendo su socket, y si el server lo kickea por el cambio de modo,
    // espera a que el refresh termine antes de reconectar (sin pelear con el
    // spawn FFA del refresh).
    void setRefreshInProgress(bool on) { m_refreshInProgress.store(on); }
    bool refreshInProgress() const { return m_refreshInProgress.load(); }
    // Aborta la sesion TCP actual SIN parar el worker: el loop del farm detecta
    // el flag (atomico), cierra el socket y reconecta solo al terminar el
    // refresh. El refresh la usa para forzar el settle de la XP de la sesion
    // DENTRO de su ventana de poll (el kick HTTP del modo NO mata la sesion del
    // farm de forma fiable: la XP quedaba sin contabilizar y el delta salia 0).
    void abortSession() { m_abortSession.store(true); }
    // Skip del spawn TCP CTF FINAL del refresh (cuenta con farm activo): el
    // farm esta pausado durante el refresh (setRefreshInProgress) y re-spawnea
    // CTF por su cuenta justo despues; un segundo spawn CTF concurrente desde
    // el refresh (a) pelearia con el farm, (b) quemaria 2x30s de timeout cuando
    // el matchmaking lo encola (visto en el run 03:51: 6/9 cuentas con timeout
    // doble). El path del refresh CON farm NO corre spawn TCP FFA: el cambio de
    // modo HTTP kickea la sesion del farm y la XP de la gema se materializa al
    // terminar ESA sesion (settle ~10-60s, capturado con el poll de refreshXp).
    // Cuentas SIN farm mantienen el spawn CTF final (quedan spawneadas en CTF,
    // no en lobby).
    void setSkipFinalCtfSpawn(bool on) { m_skipFinalCtfSpawn = on; }
    // Refresh SOLO LECTURA (cuenta con farm activo): el refresh NO toca la
    // sesion TCP del farm (sin kick FFA, sin abortSession, sin spawns ni
    // restore de modo). Solo loginifneeded + inventory slot=5 + updateexp
    // para actualizar nombre/coins/cexp/exp/lvl en la DB. El farm sigue
    // corriendo y su XP se ve en vivo por el op 24 TCP.
    void setReadOnly(bool on) { m_readOnly = on; }
    bool readOnly() const { return m_readOnly; }
    // Deadline del [20] SPAWNED dentro de spawnSession. 30s por defecto (path
    // del refresh: evita el cuelgue infinito). El farm (run) lo sube a 120s:
    // espera paciente cuando el matchmaking tarda con varios accounts
    // reconectando a la vez.
    void setSpawnDeadlineMs(int ms) { m_spawnDeadlineMs = ms; }
    void stop();

public slots:
    void run();
    void refreshXp();

signals:
    void stateChanged(const QString &text);                 // log de progreso legible (estado del farm)
    void debugLog(const QString &text);                     // detalle tecnico: opcodes, seeds, frames, hex
    void xpUpdate(double xpGained, double lastXp, int deaths, bool spawned);
    // Lectura HTTP EXCLUSIVA de la XP de la gema (inventory slot=5). El op 24
    // TCP es XP del jugador/partida y NO se usa para las gemas: el controller
    // acumula el label verde solo con esta senal (baseline = primer valor,
    // delta = max(0, cexp - ultimo)). cexp = XP del nivel actual, exp = total.
    void gemXpRead(qlonglong cexp, qlonglong exp);
    // cexp = XP del nivel actual de la gema, exp = XP total, delta = ganancia real
    // (max entre la variacion de exp y la de cexp: el server acredita la XP de la
    // gema en cexp y exp queda congelada entre level-ups)
    void xpRefreshDone(bool ok, qlonglong cexp, qlonglong exp, qlonglong delta, int lvl, const QString &error);
    void finishedOk(bool ok, const QString &error);
    void regionChanged(const QString &region);              // region CTF elegida (por sesion)
    void accountState(const QString &mode, const QString &region); // modo actual (CTF/FFA) + region

private:
    // XP total acumulada por el worker a traves de reconexiones: el FarmState
    // se recrea en cada intento TCP y perderia el contador (bug reportado:
    // "como funciona el contador de xp?").
    double m_sessionXpTotal = 0.0;
    struct FarmState {
        QString suffix;
        // 2026-08-11 v14: host del server (para la key del op5 JOIN =
        // host + suffix, igual que el ACK del binario).
        QString host;
        std::unique_ptr<tcp::MersenneTwister> mt;
        std::uint32_t seed = 0;
        int pingCount = 0;
        QString playerId;
        // 2026-08-11 v9+v28: el spawn token del op53 (el server lo envia si la
        // identidad es correcta; el op5 JOIN debe re-cifrarlo, no un nonce
        // aleatorio — el amigo: "the client turns the spawn token into a
        // join request, re-encrypting op53 under a fixed key").
        QString spawnToken;
        // v28: payload CRUDO del frame op53 (el JOIN re-cifra el op53
        // completo, no el string decodificado — el string tenia un prefijo
        // '00000008' que el Amf3Decoder malinterpretaba).
        Bytes spawnTokenRaw;
        // v78 (captura del binario real 2026-08-13): el play HTTP responde
        // con un NONCE de 8 chars ("PhudtAu3"); el binario lo cifra con
        // eb(suffix) y ESE blob es el challenge del op5 JOIN. El v28
        // cifraba el op53 completo -> el server descifraba un array AMF3,
        // no 8 chars -> JOIN invalido -> dejaba de pinguear -> corte ~30s.
        QString playNonce;
        double xpTotal = 0.0;
        double xpLast = 0.0;
        double coinsTotal = 0.0;
        int deaths = 0;
        bool spawned = false;
    };

    bool recvFrame(QTcpSocket *sock, int timeoutMs, int *length, int *flag, Bytes *payload);
    bool sendFrame(QTcpSocket *sock, const Bytes &data);
    bool decodeFrame(const Bytes &payload, std::uint32_t seed, tcp::AmfValue *out);
    void doLogin(QString *sk, QString *magic, QString *accountName, QByteArray *sessionCookies);
    QJsonObject httpApi(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload, int timeoutMs = 8000);
    // Version best-effort del httpApi para el postSpawn/respawn: tryLock
    // 350ms del g_loginMutex global. Si la cola de los otros farms esta
    // ocupada, SALTAR el HTTP (devolver vacio) en vez de esperar 5-14s sin
    // PONGs (el server corta a los ~12s del [20]). Los frames NATIVE_PLAY se
    // mandan igual (sendFrame no depende del mutex).
    QJsonObject httpApiFast(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload);
    // Cuerpo del httpApi SIN lock (el caller decide el lock; ver httpApi()).
    QJsonObject httpApiLocked(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload);
    // Cuerpo con timeout configurable (el postSpawn usa 1500ms; el resto 8000ms).
    QJsonObject httpApiLockedTmo(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload, int timeoutMs);
    void emitLog(const QString &text);
    // Escritura directa del log al archivo desde el hilo del worker (los
    // stateChanged via cola del hilo principal se saturaban con 10 farms).
    void writeWorkerLog(const QString &line);                 // clasifica legible/tecnico y emite la senal correcta
    int gemCurrent(const QJsonObject &invResp) const;
    bool gemEquipped(const QJsonObject &invResp) const;
    // Lee cexp/exp de la gema m_gemItem del response de inventory(slot=5).
    // Busca por id == m_gemItem; si la gema no aparece en items, cae al item
    // activo (data.current). Devuelve false si no hay ningun valor.
    bool readGemXp(const QJsonObject &invResp, qlonglong *cexpOut, qlonglong *expOut);
    void restoreCtfMode(QNetworkAccessManager *net, const QString &sk, const QString &magic, const QString &avoidRegion);
    void backToCtfSameRegion(QNetworkAccessManager *net, const QString &sk, const QString &magic);
    // Connect response del ultimo restore a CTF (server+token): el refresh lo
    // usa para el spawn TCP final ("spawneas again") despues de volver a CTF.
    QJsonObject m_ctfConnect;
    void pickRandomRegion();
    // chat IRC: drena los frames del socket del chat (talk003) y devuelve las lineas
    // completas (usada por spawnSession y por el loop del run)
    QString drainIrc(QTcpSocket *ircSock, QByteArray *ircBuf);
    // Secuencia post-SPAWNED del binario (ctf_full.log): inventory slot=5 -> news ->
    // equip verificado (current == m_gemItem) -> play + NATIVE_PLAY [true] -> play +
    // NATIVE_PLAY [false] -> gamemode. Usada por run (spawn inicial y respawn).
    void sendJoinFrame(QTcpSocket *sock, FarmState &st);
    void postSpawnSequence(QTcpSocket *sock, QNetworkAccessManager *net, const QString &sk,
                           const QString &magic, FarmState *state, const QString &suffix);
    // Handshake de spawn completo sobre un socket YA conectado: greeting -> suffix ->
    // AUTH M2XC (+HTTP) -> LISTENER v5oh2 -> IRC -> [4] -> [52]+PROOF TPM -> [53] ->
    // inventory(ingame) + READY -> [40] -> [20] SPAWNED. Devuelve true si llego al
    // [20]; *err lleva el fallo. El chat IRC queda vivo en ircSock/ircBuf (run lo
    // conserva para el loop del farm; refreshXp los destruye al terminar). mode es
    // el modo del AUTH (3 CTF, 0 FFA). Compartida por run() y refreshXp().
    bool spawnSession(QTcpSocket *sock, QNetworkAccessManager *net, const QString &sk,
                      const QString &magic, QString host, int port, QString token,
                      const QString &invite,
                      const QString &uid, const QString &ctToken,
                      int mode, QString *err, FarmState *state,
                      QTcpSocket *ircSock, QByteArray *ircBuf,
                      bool doUdpInit = false,
                      std::function<void(QString&, int&, QString&)> refreshServer = {});

    std::atomic<bool> m_stop{false};
    std::atomic<bool> m_autoRespawn{true};
    std::atomic<bool> m_autoRepair{false};
    std::atomic<bool> m_autoBuyX2{false};
    // 2026-08-10: estado REAL del auto-buy x2 (indicador del dashboard).
    // m_x2Reason se escribe SOLO desde el hilo del worker (sin race).
    std::atomic<int> m_x2State{0}; // 0=sin intento 1=comprado 2=fallo 3=sin coins
    QString m_x2Reason;
    std::atomic<bool> m_refreshInProgress{false};
    std::atomic<bool> m_abortSession{false};
    // Backoff ADAPTATIVO de reconexion (modelo del multi_test Python validado
    // 9/9 a 300s, room_keepalive.py:1216-1227): si la sesion duro <2s el
    // server rechazo casi de inmediato -> doblar la espera (4->8->16->32->60s
    // max) para dejar entrar a las demas; si duro >=10s la cuenta entro bien
    // -> reset a 4s. El C++ usaba 2-5s fijo: cuando TODAS caen a la vez
    // (fin de partida global) reintentaban juntas y el server cortaba los
    // handshakes. Protegido por m_sessionMutex.
    int m_sessionBackoffMs = 4000;
    // EXPERIMENTO UDP KEEPALIVE (2026-08-14, pedido del usuario): la skill dice
    // que el binario NO envia UDP (0 datagramas), pero se prueba como flag para
    // medir si mantiene mas cuentas en partida. Formato = make_udp_afk_packet
    // del Python: prefix(9B) + seq BE + opcode 0x002726 + 3 floats + ffffffff00000000.
    static const bool kUdpKeepalive = true;
    // Keepalive de partida del CTF publico (headless_bot.py validado): el
    // server corta a los ~7-12s si el cliente no envia MOVE. TCP MOVE [10022]
    // cada 1s + UDP MOVE (puerto 3724, opcode 0x002726) cada 1s, con valores
    // AFK (34.0, -3.084, 0.9309: no mueven, no disparan). Socket UDP creado
    // en run() tras el connect; NULL si falla (el TCP MOVE sigue solo).
QScopedPointer<QUdpSocket> m_udpSock{nullptr};
QByteArray m_udpPrefix;   // 9 bytes: 0x80|rand + 8 chars del charset del binario
quint32 m_udpSeq = 0;     // secuencia del UDP MOVE (incrementa por envio)
// coordenadas pseudo-aleatorias del UDP MOVE (simulan movimiento de jugador)
    double m_udpX = 34.0, m_udpY = -3.084, m_udpZ = 0.9309;
    qint64 m_udpNextDrift = 0; // v97ah: proximo paso del random walk del jugador
    QString m_udpIp;          // IP resuelta del server (QHostAddress NO resuelve nombres)
    // Aborto cooperativo EXTERNO (verificado 2026-08-08, familia 0x1CE857):
    // el refreshXp del worker local del refreshAll pollea el settle hasta
    // 60s; si el shutdown empieza mientras, el poll seguira y los QJsonObject/
    // QHash de ese flujo se solapan con el teardown -> SEH [r13+0x78..0x84].
    // El controller setea m_abortPtr = &m_abortingRefreshAll y refreshXp()
    // corta los loops largos (spawn, dwell, poll) en <=1 iteracion.
    std::atomic<bool> *m_abortPtr = nullptr;
    bool m_readOnly = false;          // refreshXp: solo lecturas HTTP, sin tocar sesiones
    bool m_skipFinalCtfSpawn = false; // refreshXp: omite solo el spawn CTF final (el farm re-spawnea)
    int m_spawnDeadlineMs = 30000;    // spawnSession: deadline del [20] SPAWNED (15s refresh, 120s farm)
    int m_greetingTimeoutMs = 8000;  // spawnSession: tope del greeting/suffix (10s refresh, 8s farm; 20s hacia que el retry tardara minutos)
    bool m_useRoom = false; // v33: CTF PUBLICO (la sala privada no da XP - dato del usuario; el joinroom era de pruebas)publico corta por anti-multibox.
    QString m_deviceId;
    QString m_pemPath;
    QString m_authToken;      // token del connect (para el re-AUTH del respawn)
    // v77b+v78: nonce de 8 chars que el play HTTP responde (captura del
    // binario 29025ms: "PhudtAu3"). El binario lo cifra con eb(suffix) y ESE
    // blob es el challenge del op5 JOIN. Se limpia tras cada JOIN.
    QString m_lastPlayToken;
    // v92 (CAPTURA 2026-08-14): el "PgiLmpnC" que el binario reenvia plano
    // tras CADA play es el nonceRt del roundtrip del op52 (derivado de la key
    // del device, constante). El server mint el token del JOIN solo si recibe
    // play + este eco. Se guarda al resolver el op52 y se ecosea en cada play.
    QString m_nonceRt;
    bool m_lastPlayEchoSent = false; // v92: 1 eco por ciclo de play (el binario ecosea t
    // v97ab: uid/chattoken del ultimo pre-flow — en la reconexion se saltan
    // los 3 HTTPs del pre-flow (i18n/loginifneeded/chattoken ~3s).
    QString m_lastUid;
    QString m_lastCtToken;
    // v97al (CAPTURA cap_reconexion.log 2026-08-15): el binario intenta
    // RESUMIR la sesion al reconectar (HTTP "resume::<key>" + frame TCP con
    // seed=0). La key viene del op40 (RESUME_KEY) de la sesion anterior.
    QString m_resumeKey;
    QString m_lastSuffix; // suffix del greeting de la sesion anterior (para el resume)
    // v97as: reconexion directa a la MISMA partida (TCP al mismo server con el
    // mismo token, sin login ni connect HTTP). El flag evita reintentar el
    // directo en bucle: si falla, el siguiente ciclo hace el connect fresco.
    bool m_directReconnectTried = false;
    // v97bs: el directo intenta UNA vez tras el corte; si el spawn falla, el
    // flag marca el fallback al connect fresco (se resetea al spawnear OK).
    bool m_directReconnectFailed = false;
    // v97db: timestamps de las muertes recientes (deteccion de sala hostil:
    // 3 muertes en <120s -> cambio de sala por disconnected + re-matchmake).
    QVector<qint64> m_recentDeathTimes;
    // v97dj: true cuando el spawnSession corre en modo directo (reconexion
    // del binario) — el [40] completa el spawn sin esperar el [20].
    bool m_directSpawnMode = false;
    // 2026-08-11 v14: host del server actual (key del op5 JOIN = host+suffix)
    QString m_currentHost;
    QString m_inviteString;   // invite de la sala (para el AUTH del respawn)
    int m_connectIndex = 0;   // indice "i" del connect (se incrementa con cada reconnect, como el binario)
    QString m_region;         // region CTF actual (random por sesion, ver pickRandomRegion)
    qlonglong m_gemExpInicial = -1; // exp total de la gema al iniciar la sesion (base del delta del refresh)
    qlonglong m_gemCexpInicial = -1; // cexp (XP del nivel) al iniciar la sesion (idem; el server mueve cexp, no exp)
    qint64 nextGemXpRead = 0; // proxima lectura HTTP de la XP de la gema (cadencia 60s, la misma del updateexp)
    int m_gemItem = 0;
    QVector<int> m_gemPriorityList; // prioridad de gemas (ids de color), vacia = solo la actual
    QString m_sk;             // session key del login (para el refresh de XP sin re-login)
    QString m_magic;          // magic del login (idem)
    // Mutex de sesion (THR-2): m_sk/m_magic/m_connectIndex/m_gemExpInicial/
    // m_gemCexpInicial/m_region se escriben en run() (hilo del worker) y se
    // leen desde el GUI (refreshXp copia la sesion para su worker). QString
    // no es atomico: la race COW corrompe el heap. Los setters previos al
    // moveToThread (setSession/configure/setRegion) tambien pasan por aqui.
    mutable QMutex m_sessionMutex;
    // Socket activo del farm: permite a stop() abortar el socket desde el
    // hilo principal sin esperar que el worker lo haga (UAF fix STOP).
    QTcpSocket *m_activeSock = nullptr;
    // v43: descriptor como int puro (stop() lo usa desde el GUI thread sin
    // tocar el objeto Qt — socketDescriptor() cross-thread era UB).
    qintptr m_activeFd = -1;
    // v58: intentos de play+JOIN en el mismo socket del watchdog de actividad
    // (max 3, luego reconectar) — la solucion de la conexion.
    int m_sameSocketPlayAttempts = 0;
    mutable QMutex m_socketMutex;
    // QNetworkAccessManager UNICO del worker, creado LAZY en run()/refreshXp()
    // bajo g_loginMutex: los ctor/dtor de QNAM concurrentes (9 farms a la vez)
    // tocan el registro global de Qt Network (QHash) -> race de Qt 6.10.3.
    QNetworkAccessManager *m_net = nullptr;
    // Contador de frames no decodificados (log de los primeros 10 por run).
    // MIEMBRO del worker (antes static en spawnSession/run): los 9 farms
    // comparten proceso y el static era una data race. Se resetea al iniciar
    // cada run().
    int m_undecCount = 0;
    // 2026-08-11 (deteccion de muerte): timestamps (reloj real ms) de los
    // frames 0x64 recientes (formato interno de entidades del server). >=3
    // en 5s = muerte del jugador -> respawn minimo como el binario.
    QList<qint64> m_undecBurstAt;
    // 2026-08-11 v3: ultimo respawn por muerte 0x641b (cooldown 8s).
    qint64 m_lastRespawnAt = 0;
    // 2026-08-11 v5: ultima reply CLIENT_EQUIPMENT_DATA a los frames 0x64
    // (el server pide el equip en el spawn/respawn; cooldown 3s).
    qint64 m_lastEquipReplyAt = 0;
    // 2026-08-11 v13+v17: tag GLOBAL del mmm PERSISTENTE entre workers,
    // con mutex (data race corrompia los tags y el server cortaba por tag
    // bajo). Getter/setter seguros por deviceId.
    static int mmmTagGet(const QString &deviceId);
    static void mmmTagSet(const QString &deviceId, int value);
    // 2026-08-10 (bug auto-buy): los timers largos (updateexp/autoBuyX2) usaban
    // t0.elapsed() que se REINICIA en cada reconexion (continue del run()); el
    // CTF mata la partida cada ~40s asi que el chequeo de 60s nunca alcanzaba.
    // m_nextAutoBuyX2 usa RELOJ REAL y persiste entre sesiones (miembro).
    qint64 m_nextAutoBuyX2 = -1; // -1 = programar al primer SPAWNED
    // v35: refresh completo cada 600s (pedido del usuario): verifica XP ganada
    // (inventory slot=5), repara gema rota por durabilidad, re-equipa si la
    // gema desaparecio (gem priority) y re-compra x2 si expiro. RELOJ REAL.
    qint64 m_nextFullRefresh = -1; // -1 = programar al primer SPAWNED
    // v36: refresco al terminar cada partida (deteccion de fin de partida sin
    // corte TCP): el server deja de enviar op24/op35 pero NO corta. Este flag
    // marca que la partida termino y el loop debe reconectar al instante.
    bool m_matchFinished = false;
};
