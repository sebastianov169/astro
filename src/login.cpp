// login.cpp - LoginManager: KNOCK/LIM/EH + API
#include "login.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QTimer>
#include <QUrl>
#include <QUrlQuery>
#include <QEventLoop>
#include <QFile>
#include <QMutex>
#include <QElapsedTimer>
#include <QThread>
#include <QCoreApplication>
#include <QRandomGenerator>
#include <QDateTime>

#include <windows.h>

namespace {
const QString kEngine = "https://app.mitos.is/engine_beta.php";
const QString kVersion = "10.1.8";
const QStringList kDesktopPool = {
    QStringLiteral("Dell Inc.;XPS 15 9530;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;2560;1440"),
    QStringLiteral("HP Inc.;OMEN 17;Microsoft Windows 11 Home;Windows;10.0.22631;x64;2560;1440"),
    QStringLiteral("Lenovo;Legion Pro 7 16IRX8h;Microsoft Windows 11 Pro;Windows;10.0.22621;x64;2560;1600"),
    QStringLiteral("ASUSTeK Computer INC.;ROG Strix G16;Microsoft Windows 11 Home;Windows;10.0.22631;x64;1920;1200"),
    QStringLiteral("MSI;Raider GE78 HX;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;2560;1600"),
    QStringLiteral("Acer;Predator Helios 16;Microsoft Windows 11 Home;Windows;10.0.22621;x64;2560;1600"),
    QStringLiteral("Razer;Blade 16;Microsoft Windows 11 Home;Windows;10.0.22631;x64;2560;1600"),
    QStringLiteral("Alienware;m18 R2;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;2560;1600"),
    QStringLiteral("Samsung;Galaxy Book3 Ultra;Microsoft Windows 11 Home;Windows;10.0.22621;x64;2880;1800"),
    QStringLiteral("GIGABYTE;AORUS 17X;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;1920;1080"),
};

QString randomDesktop() {
    return kDesktopPool.at(
        QRandomGenerator::global()->bounded(kDesktopPool.size()));
}

QString urlEncode(const QString &s, bool plusForSpace)
{
    QByteArray in = s.toUtf8();
    QString out;
    for (char c : in) {
        unsigned char ch = unsigned char(c);
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            out += QChar(ch);
        else if (ch == ' ' && plusForSpace)
            out += '+';
        else
            out += QString("%%1").arg(int(ch), 2, 16, QLatin1Char('0')).toUpper();
    }
    return out;
}

// Redacta el _sid (credencial de sesion) de una URL para logs/debug: solo se
// dejan los primeros 16 chars del valor. Definida FUERA del namespace (la usan
// httpGet/httpPost, que estan fuera; antes estaba dentro y no compilaba).
QString redactSidUrl(const QString &url)
{
    QString out = url;
    const int sidPos = out.indexOf(QStringLiteral("_sid="));
    if (sidPos >= 0) {
        int end = sidPos + 5;
        while (end < out.size() && out.at(end) != '&')
            ++end;
        const QString val = out.mid(sidPos + 5, end - sidPos - 5);
        out.replace(sidPos + 5, val.size(), val.left(16) + QStringLiteral("..."));
    }
    return out;
}

QByteArray httpGet(const QUrl &url, QNetworkAccessManager *mgr)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    // HTTP/1.1 forzado: ver httpGetTcp (race h2/GOAWAY de Qt 6.10.3)
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    // debug: bytes exactos que Qt enviara (QUrl::toEncoded); URL redactada
    // (el _sid completo es la credencial de sesion, no se imprime en claro)
    std::printf("[httpEnc] %.200s\n", redactSidUrl(QString::fromUtf8(url.toEncoded())).toUtf8().constData()); fflush(stdout);
    std::printf("[httpEncT] %.200s\n", redactSidUrl(url.toString()).toUtf8().constData()); fflush(stdout);
    QNetworkReply *reply = mgr->get(req);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(8000);
    loop.exec();
    QByteArray data = reply->isFinished() ? reply->readAll() : QByteArray();
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QNetworkReply::NetworkError err = reply->error();
    std::printf("[httpGet] %.120s status=%d err=%d len=%d\n", redactSidUrl(url.toString()).toUtf8().constData(), status, int(err), int(data.size()));
    // delete DIRECTO, no deleteLater: el hilo del refreshAll/spawn destruye el
    // QNAM (y muere) justo despues de esta llamada; el DeferredDelete pendiente
    // del deleteLater se procesa al teardown del hilo sobre un reply YA borrado
    // por el dtor del QNAM -> use-after-free -> vtable corrupto -> AV 0xC0000005
    // en Qt6Core+0x1CE857 (los 9 logins paralelos lo hacian ~1 de cada 4 runs).
    // Despues del loop.exec el reply esta idle: delete directo es seguro.
    delete reply;
    return data;
}

QByteArray httpPost(const QUrl &url, const QByteArray &body, QNetworkAccessManager *mgr)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    // HTTP/1.1 forzado: ver httpGetTcp (race h2/GOAWAY de Qt 6.10.3)
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    QNetworkReply *reply = mgr->post(req, body);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(8000);
    loop.exec();
    QByteArray data = reply->isFinished() ? reply->readAll() : QByteArray();
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    std::printf("[httpPost] %.120s status=%d len=%d\n", redactSidUrl(url.toString()).toUtf8().constData(), status, int(data.size()));
    // delete directo (ver httpGet: deleteLater + teardown del hilo = UAF)
    delete reply;
    return data;
}

QJsonObject parseJsonObject(const QByteArray &data)
{
    // Mutex global: QJsonDocument::fromJson y los QHash internos de Qt 6.10.3
    // (qHashBits -> SHA-512) tienen race con N hilos parseando a la vez (AV
    // 0xC0000005 en Qt6Core+0x1CE857 con los 9 logins del refreshAll).
    QMutexLocker locker(&g_jsonParseMutex);
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return {};
    return doc.object();
}

QString makeQuery(const QVector<QPair<QString, QString>> &pairs, bool plus = true)
{
    QStringList parts;
    for (const auto &p : pairs)
        parts << urlEncode(p.first, plus) + "=" + urlEncode(p.second, plus);
    return parts.join('&');
}
} // namespace

LoginManager::LoginManager(QObject *parent) : QObject(parent)
{
    // El QNetworkAccessManager (m_net) se construye AQUI, en el ctor, desde el
    // hilo del caller (pre-spawn/refreshAll/QWS): su ctor toca el registro
    // global de Qt Network (QHash) y crashea Qt 6.10.3 si N hilos construyen
    // LoginManager a la vez. Serializado con g_loginMutex (ver crypto.h).
    QMutexLocker locker(&g_loginMutex);
}

LoginManager::~LoginManager()
{
    // El dtor destruye el QNAM (cierra conexiones keep-alive): serializado por
    // la misma razon que el ctor.
    QMutexLocker locker(&g_loginMutex);
}

void LoginManager::setAttestPem(const QString &pem)
{
    m_attestPem = pem;
}

LoginResult LoginManager::login(const QString &deviceId)
{
    LoginResult result;
    // sesion fresca SIEMPRE: un login fallido a medias nunca puede dejar estado
    // (sk/magic/coins/nombre del intento anterior) para una llamada posterior
    m_sessionKey.clear();
    m_magic.clear();
    m_lastCoins = 0;
    m_accountName.clear();
    m_deviceId = deviceId.isEmpty() ? readDeviceId() : deviceId;
    if (m_deviceId.isEmpty()) {
        result.error = "Could not read device id";
        return result;
    }

    try {
        // Serializado con g_loginMutex: Qt 6.10.3 crashea (AV 0xC0000005 en
        // Qt6Core, familia qHashBits/SHA-512, RVAs 0x1CE857/0x1CF461/0x1C8A4E,
        // NULL-base r12=0 + [r12+0x7C]) cuando VARIOS hilos hacen KNOCK/LIM/EH
        // a la vez: las CONSTRUCCIONES de QJsonObject/QVariantMap hashean y no
        // pasan por los mutex de parseo/hash. Verificado en vivo: los crashes
        // caen siempre dentro de LIM (entre los warnings TOKEN/SD1/EDID de
        // distintos hilos), incluso con tandas de 3 logins.
        QMutexLocker loginLocker(&g_loginMutex);
        // ---- KNOCK ----
        std::printf("[C++] KNOCK...\n"); fflush(stdout);
        QString chk = md5Hex("_chk91822" + m_deviceId + "l.o.x");
        QString q = makeQuery({{"do", "knock"}, {"rndx", rndx()}});
        QJsonObject knock = parseJsonObject(httpGet(QUrl(kEngine + "?" + q), &m_net));
        QString token = knock.value("data").toObject().value("token").toString();
        if (token.isEmpty()) {
            result.error = "KNOCK failed: " + QString::fromUtf8(QJsonDocument(knock).toJson()).left(120);
            return result;
        }
        std::printf("[C++] LIM... token=%.16s...\n", token.toUtf8().constData()); fflush(stdout);

        // ---- LIM ----
        auto parts = stringDesturple(token);
        Bytes edidBlob = m2xcEncryptFull(bytesOf(m_deviceId), bytesOf(parts.first),
                                         0xBC461A49, 0x7C2359AB);
        QString edid = m2xcFmt(edidBlob);
        qWarning("TOKEN: %.16s...", token.toUtf8().constData());
        qWarning("SD1: %.16s...", parts.first.toUtf8().constData());
        qWarning("EDID: %.16s...", edid.toUtf8().constData());
        // UN solo desktop por login: antes se llamaba randomDesktop() dos veces
        // (ddd del LIM y di del EH) y el mismo login reportaba equipos distintos
        const QString desktop = randomDesktop();
        QVector<QPair<QString, QString>> limParams = {
            {"rus", "1"}, {"loc", "es_CO"}, {"ver", kVersion}, {"dds", "1920x1080"},
            {"do", "lim"}, {"t", token}, {"ddd", desktop}, {"fmt", "tbt"},
            {"chk", chk}, {"did", edid}, {"rndx", rndx()},
        };
        QJsonObject lim = parseJsonObject(httpGet(QUrl(kEngine + "?" + makeQuery(limParams)), &m_net));
        if (lim.value("result").toString() != "ok") {
            result.error = "LIM failed: " + lim.value("message").toString() + " (reset_did?)";
            return result;
        }
        QString dk = lim.value("data").toObject().value("dk").toString();
        QString dm = lim.value("data").toObject().value("dm").toString();
        std::printf("[C++] TOKEN: %.16s...\n", token.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DK FULL: %.16s...\n", dk.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DM FULL: %.16s...\n", dm.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] SD1: %.16s...\n", parts.first.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] EDID FULL: %.16s...\n", edid.toUtf8().constData()); fflush(stdout);
        QString dkKey = md5Hex(token + m_deviceId);
        QString dmKey = md5Hex(m_deviceId + token);
        Bytes skBlob = m2xcDecryptFull(parseM2xcBlob(dk), bytesOf(dkKey));
        Bytes rkBlob = m2xcDecryptFull(parseM2xcBlob(dm), bytesOf(dmKey));
        if (skBlob.empty() || rkBlob.empty()) {
            result.error = "LIM: could not decrypt sk/rk";
            return result;
        }
        m_sessionKey = QString::fromUtf8(reinterpret_cast<const char *>(skBlob.data()), int(skBlob.size()));
        std::printf("[C++] SK: %.16s... len=%d\n", m_sessionKey.toUtf8().constData(), int(m_sessionKey.size())); fflush(stdout);
        QString rsaPublicKey = QString::fromUtf8(reinterpret_cast<const char *>(rkBlob.data()), int(rkBlob.size()));

        // ---- EH ----
        // Serializado con mutex global: los 9 logins paralelos del refreshAll
        // (y del spawn) ejecutan este bloque (RSA sign + buildMidPem + m2xc +
        // EH HTTP) simultaneamente y Qt 6.10.3 crashea (AV 0xC0000005 en
        // Qt6Core+0x1CE857, familia SHA-512 de QCryptographicHash) ~1 de cada
        // 4 runs con 9 hilos concurrentes. El costo: ~1-2s por cuenta, solo en
        // este bloque; el resto del refresh sigue en paralelo.
        static QMutex g_attestMutex;
        QMutexLocker attestLocker(&g_attestMutex);
        m_magic = genMagic(64);
        QString dtf = buildDtf(m_sessionKey);
        // proof con la clave PEM de atestacion FAKE del device (setAttestPem).
        // JAMAS se cae a la clave embebida compartida: el server identifica la
        // atestacion por mid+proof y una clave compartida entre cuentas hace
        // que corte la conexion (limite ~4 conexiones simultaneas). Sin clave
        // propia, el EH falla con error claro en vez de usar la embebida.
        const QString attestPem = m_attestPem;
        if (attestPem.isEmpty()) {
            result.error = "Attestation key missing (setAttestPem)";
            return result;
        }
        QByteArray chMsg = (dtf + "|" + m_deviceId + "|100").toUtf8();
        Bytes sig = rsaSignPkcs1Sha256(attestPem, chMsg);
        QString proof = urlB64EncodeNoPad(sig);
        QString mid = buildMidPem(attestPem);
        // evidencia TPM del EH de pre-spawn: cada device debe loguear un mid
        // DISTINTO (el mismo mid en varias cuentas = atestacion compartida).
        qWarning("TPM eh device=%.16s mid=%.12s", m_deviceId.left(16).toUtf8().constData(),
                 mid.left(12).toUtf8().constData());
        std::printf("[C++] PROOF: %.16s...\n", proof.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] MID FULL: %.16s...\n", mid.toUtf8().constData()); fflush(stdout);

        QString ddJson = QString("{\"proof\":\"%1\",\"mid\":\"%2\",\"ver\":\"%3\",\"host\":\"app.mitos.is\"}")
                             .arg(proof, mid, kVersion);
        u32 R10 = u32(quint64(QDateTime::currentMSecsSinceEpoch()) ^ quint64(QRandomGenerator::global()->generate()));
        u32 ddH2 = u32(QRandomGenerator::global()->generate());
        std::printf("[C++] R10: %08x H2: %08x\n", R10, ddH2); fflush(stdout);
        Bytes ddBlob = m2xcEncryptFull(bytesOf(ddJson),
                                       bytesOf(m_magic), R10,
                                       ddH2);
        QString dd = m2xcFmt(ddBlob);
        std::printf("[C++] RK: %.16s...\n", rsaPublicKey.left(16).toUtf8().constData()); fflush(stdout);
        QString ms = rsaEncryptPkcs1Base64(rsaPublicKey, m_magic);
        std::printf("[C++] MS: %.16s... len=%d\n", ms.toUtf8().constData(), int(ms.size())); fflush(stdout);
        std::printf("[C++] RK FULL: %.16s...\n", rsaPublicKey.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] MAGIC: %.16s...\n", m_magic.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DTF FULL: %.16s...\n", dtf.toUtf8().constData()); fflush(stdout);

        QVector<QPair<QString, QString>> ehParams = {
            {"go", "0"}, {"dd", dd}, {"de", "desktop"}, {"gi", "0"},
            {"ver", kVersion}, {"it", "1"}, {"do", "eh"}, {"im", "0"},
            {"di", desktop}, {"dtf", dtf}, {"ms", ms}, {"rndx", rndx()},
        };
        QString ehUrl = kEngine + "?" + makeQuery(ehParams, true);
        // URL del EH truncada: dd/ms/dtf son blobs largos (cifrados/derivados),
        // no hace falta imprimirlos completos en stdout
        std::printf("[C++] EH URL: %.160s\n", ehUrl.toUtf8().constData()); fflush(stdout);
        QByteArray eh;
        bool ehSkipped = false;
        if (qEnvironmentVariableIsSet("GEMXP_SKIP_EH")) {
            std::printf("[C++] SKIP_EH: no se envia el EH\n"); fflush(stdout);
            eh = QByteArray("{}");
            // debug: con GEMXP_SKIP_EH el login se da por EXITOSO sin EH real
            // (antes eh="{}" y el check contains("ok") fallaba SIEMPRE)
            ehSkipped = true;
        } else {
            eh = httpGet(QUrl(ehUrl), &m_net);
        }
        std::printf("[C++] EH response: %.200s\n", eh.constData()); fflush(stdout);
        if (!ehSkipped) {
            // Respuesta del EH: si es JSON valido se exige result=="ok"
            // explicito (contains("ok") aceptaria {"ok":false,...}); si es
            // texto plano (mensajes URL-encoded del server en las capturas)
            // se conserva el check original que funciona contra el server real.
            QJsonObject ehObj = parseJsonObject(eh);
            const bool ehOk = ehObj.isEmpty()
                ? QString::fromUtf8(eh).contains("ok")
                : (ehObj.value("result").toString() == "ok");
            if (!ehOk) {
                result.error = "EH failed: " + QString::fromUtf8(eh).left(120);
                return result;
            }
        }

        result.ok = true;
        result.sessionKey = m_sessionKey;
        result.magic = m_magic;
        result.deviceId = m_deviceId;
        result.accountName = m_accountName;
        return result;
    } catch (const std::exception &e) {
        result.error = QString("login error: %1").arg(e.what());
        return result;
    }
}

QVector<GemInfo> LoginManager::fetchInventory(int slot)
{
    QMutexLocker loginLocker(&g_loginMutex); // serializado (ver login(): construcciones QJsonObject)
    QVector<GemInfo> gems;
    if (m_sessionKey.isEmpty())
        return gems;
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QString bodyJson = QString("{\"do\":\"inventory\",\"slot\":%1}").arg(slot);
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson),
                                bytesOf(m_magic), 0, 0);
    QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
    std::printf("[C++] INVENTORY RAW: %.180s\n", resp.constData()); fflush(stdout);
    {
        QFile dbg(QCoreApplication::applicationDirPath() + "/inventory_raw.txt");
        if (dbg.open(QIODevice::WriteOnly | QIODevice::Truncate))
            dbg.write(resp);
    }
    QString t = QString::fromUtf8(resp);
    QByteArray payload;
    if (t.startsWith("tBB,")) {
        // formato tBB: "tBB," + 8 hex + base64(blob). Si el blob es M2XC se
        // descifra con m2xcDecryptFull(magic); si no, es v5oh2 AES-CBC con
        // aes_key(magic) (igual que el api() de referencia en Python).
        std::printf("[C++] INVENTORY B64: %.160s\n", resp.mid(12).constData()); fflush(stdout);
        Bytes blob = b64Decode(t.mid(12));
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        } else {
            Bytes dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        }
        std::printf("[C++] INVENTORY DEC: %.200s\n", payload.constData()); fflush(stdout);
    } else {
        payload = resp;
    }
    QJsonObject obj = parseJsonObject(payload);
    QJsonArray items = obj.value("data").toObject().value("items").toArray();
    for (const auto &iv : items) {
        QJsonObject it = iv.toObject();
        GemInfo g;
        g.id = it.value("id").toInt();
        g.name = it.value("name").toString();
        g.sprite = it.value("sprite").toString();
        g.itemLevel = it.value("item_level").toInt();
        g.exp = it.value("exp").toVariant().toLongLong();
        g.cexp = it.value("cexp").toVariant().toLongLong();
        g.durability = it.value("durability").toInt();
        g.maxDurability = it.value("max_durability").toInt();
        g.price = it.value("price").toInt();
        g.sellPrice = it.value("sell_price").toInt();
        g.category = it.value("category").toInt();
        gems.push_back(g);
    }
    // la gema EQUIPADA de la cuenta (data.current): la que el server reporta
    // como activa. Se usa para el summary/sprite de la cuenta en la UI.
    m_lastCurrentItem = obj.value("data").toObject().value("current").toInt(-1);
    return gems;
}

// Tienda de gemas (do:"store"). Formato verificado contra el server real
// 2026-08-08 (captura frida full_runtime_capture_v3 + probe con apiCall):
//   REQ: {"do":"store","category":10,"evo":false}
//   RESP: {"result":"ok","message":"store","data":{"items":[{"id":1048594,
//         "name":"Gema Azul","sprite":"gem_blue1","level":1,"price":1000,
//         "exp":7200,"owned":false,"purchasable":true,
//         "data":{"attrs":[["speed",4]]}}, ...]}}
// El id del item es el del CATALOGO: la compra usa {"do":"buy","item":<id>}.
QVector<StoreItem> LoginManager::fetchStore(int category)
{
    QMutexLocker loginLocker(&g_loginMutex);
    QVector<StoreItem> items;
    if (m_sessionKey.isEmpty())
        return items;
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QString bodyJson = QString("{\"do\":\"store\",\"category\":%1,\"evo\":false}").arg(category);
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(m_magic), 0, 0);
    QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
    std::printf("[C++] STORE RAW: %.160s\n", resp.constData()); fflush(stdout);
    QString t = QString::fromUtf8(resp);
    QByteArray payload = resp;
    if (t.startsWith("tBB,")) {
        Bytes blob = b64Decode(t.mid(12));
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        } else {
            Bytes dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        }
        std::printf("[C++] STORE DEC: %.200s\n", payload.constData()); fflush(stdout);
    }
    QJsonObject obj = parseJsonObject(payload);
    QJsonArray arr = obj.value("data").toObject().value("items").toArray();
    for (const auto &iv : arr) {
        QJsonObject it = iv.toObject();
        StoreItem s;
        s.id = it.value("id").toInt();
        s.name = it.value("name").toString();
        s.sprite = it.value("sprite").toString();
        s.level = it.value("level").toInt();
        if (s.level <= 0)
            s.level = it.value("item_level").toInt();
        s.price = it.value("price").toInt();
        s.exp = it.value("exp").toVariant().toLongLong();
        s.owned = it.value("owned").toBool();
        s.purchasable = it.value("purchasable").toBool(true);
        s.category = it.value("category").toInt();
        const QJsonArray attrs = it.value("data").toObject().value("attrs").toArray();
        for (const auto &av : attrs) {
            QJsonArray pair = av.toArray();
            if (pair.size() >= 2)
                s.attrs.append(QVariantList() << pair.at(0).toString() << pair.at(1).toVariant());
        }
        items.push_back(s);
    }
    return items;
}

// API generica: envia un body arbitrario con la sesion actual
// y devuelve el JSON decodificado (mismo cifrado que fetchInventory).
QJsonObject LoginManager::apiCall(const QString &bodyJson)
{
    QMutexLocker loginLocker(&g_loginMutex);
    if (m_sessionKey.isEmpty())
        return {};
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(m_magic), 0, 0);
    QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
    QString t = QString::fromUtf8(resp);
    QByteArray payload = resp;
    if (t.startsWith("tBB,")) {
        Bytes blob = b64Decode(t.mid(12));
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        } else {
            Bytes dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        }
    }
    std::printf("[PROBE] %s -> %.4000s\n", bodyJson.toUtf8().constData(), payload.constData());
    fflush(stdout);
    // dump completo para el sondeo (probe_shop temporal)
    {
        QFile pf(QCoreApplication::applicationDirPath() + "/probe_shop_dump.txt");
        if (pf.open(QIODevice::WriteOnly | QIODevice::Append)) {
            pf.write(bodyJson.toUtf8());
            pf.write("\n>>>\n");
            pf.write(payload);
            pf.write("\n<<<\n");
            pf.close();
        }
    }
    return parseJsonObject(payload);
}

QJsonObject LoginManager::fetchUpdateExp()
{
    QMutexLocker loginLocker(&g_loginMutex); // serializado (ver login())
    if (m_sessionKey.isEmpty())
        return {};
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QString bodyJson = "{\"do\":\"updateexp\"}";
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson),
                                bytesOf(m_magic), 0, 0);
    QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
    // El server responde cifrado ("tBB," + 8 hex + base64): M2XC(magic) o
    // v5oh2 AES-CBC(aes_key(magic)), igual que el inventory/loginifneeded.
    QString t = QString::fromUtf8(resp);
    QByteArray payload = resp;
    if (t.startsWith("tBB,")) {
        Bytes blob = b64Decode(t.mid(12));
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        } else {
            Bytes dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        }
    }
    return parseJsonObject(payload);
}

QString LoginManager::fetchAccountName()
{
    QMutexLocker loginLocker(&g_loginMutex); // serializado (ver login())
    m_lastCoins = 0;
    if (m_sessionKey.isEmpty() || m_magic.isEmpty())
        return QString();
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QString bodyJson = "{\"do\":\"loginifneeded\",\"at\":\"\",\"wt\":\"\",\"usertoken\":null}";
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(m_magic), 0, 0);
    QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
    std::printf("[C++] FETCHNAME RAW: %.220s\n", resp.constData()); fflush(stdout);
    // El server responde cifrado: "tBB," + 8 hex + base64(blob).
    //  - M2XC(magic) -> m2xcDecryptFull
    //  - AES-CBC con deriveCustomAesKey(magic, 100) (loginifneeded verificado
    //    en vivo: plaintext {"result":"ok","message":"loginifneeded",...})
    //  - AES-CBC con deriveAesKey(magic) (otras respuestas v5oh2)
    QString t = QString::fromUtf8(resp);
    QByteArray payload = resp;
    if (t.startsWith("tBB,")) {
        Bytes blob = b64Decode(t.mid(12));
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
        } else {
            // intento 1: clave custom offset 100 (loginifneeded)
            Bytes dec = aesCbcCrypt(blob, deriveCustomAesKey(m_magic, 100), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
            QJsonObject firstTry = parseJsonObject(payload);
            if (firstTry.contains(QStringLiteral("result"))) {
                // Respuesta VALIDA del server pero sin data (p.ej. {"result":"error"}):
                // la clave custom era la correcta y el server respondio; NO
                // reintentar con la clave plana (descartaria el payload real y
                // reportaria un error ajeno). Sin "data" -> nombre vacio.
            } else if (!firstTry.contains(QStringLiteral("data"))) {
                // intento 2: clave plana (v5oh2)
                dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
                while (!dec.empty() && dec.back() == 0)
                    dec.pop_back();
                payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
            }
        }
        std::printf("[C++] FETCHNAME DEC: %.160s\n", payload.constData()); fflush(stdout);
    }
    QJsonObject obj = parseJsonObject(payload);
    QJsonObject data = obj.value("data").toObject();
    QJsonObject userinfo = data.value("userinfo").toObject();
    QString name = data.value("username").toString();
    if (name.isEmpty())
        name = data.value("nickname").toString();
    if (name.isEmpty())
        name = userinfo.value("username").toString();
    if (name.isEmpty())
        name = userinfo.value("nickname").toString();
    if (name.isEmpty())
        name = userinfo.value("display").toString(); // nombre real (verificado: "akar5")
    m_lastCoins = userinfo.value("coins").toVariant().toLongLong();
    return name;
}

QJsonObject LoginManager::doFullRefresh()
{
    QMutexLocker loginLocker(&g_loginMutex); // serializado (ver login())
    // Refresh completo via HTTP: FFA -> HvZ -> inventory slot=5 -> updateexp -> CTF.
    // El cambio de modo fuerza al server a actualizar la XP de la gema.
    RefreshResult result;
    if (m_sessionKey.isEmpty()) {
        result.error = QStringLiteral("Not logged in");
        QJsonObject out;
        out.insert("ok", false);
        out.insert("error", result.error);
        return out;
    }
    auto apiCall = [&](const QString &bodyJson) -> QJsonObject {
        QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
        Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(m_magic), 0, 0);
        QByteArray resp = httpPost(QUrl(url), m2xcFmt(enc).toUtf8(), &m_net);
        QString t = QString::fromUtf8(resp);
        QByteArray payload = resp;
        if (t.startsWith("tBB,")) {
            Bytes blob = b64Decode(t.mid(12));
            if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
                Bytes dec = m2xcDecryptFull(blob, bytesOf(m_magic));
                payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
            } else {
                Bytes dec = aesCbcCrypt(blob, deriveAesKey(m_magic), false);
                while (!dec.empty() && dec.back() == 0) dec.pop_back();
                payload = QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
            }
        }
        return parseJsonObject(payload);
    };
    std::printf("[REFRESH] === START doFullRefresh ===\n"); fflush(stdout);
    QElapsedTimer refreshTimer; refreshTimer.start();
    // Validacion por paso: cada apiCall devuelve JSON y los pasos clave deben
    // responder result=="ok". ANTES el refresh reportaba ok=true aunque TODOS
    // los pasos fallaran (sesion invalida, server caido -> el controller
    // mostraba XP fresca falsa). Los pasos NO criticos (i18n/gamemode/
    // updateexp) fallan sin abortar; si un paso ESENCIAL falla (connect FFA,
    // connect HvZ, inventory slot=5, restore CTF) el refresh se reporta
    // fallido con el error acumulado. El restore CTF se ejecuta SIEMPRE: no
    // se deja la cuenta en un modo intermedio.
    QStringList errors;
    bool criticalFailed = false;
    auto check = [&](const QJsonObject &resp, const char *step, bool critical) {
        if (resp.value("result").toString() != "ok") {
            const QString detail = QString::fromUtf8(QJsonDocument(resp).toJson(QJsonDocument::Compact)).left(120);
            errors << QString("%1: %2").arg(step,
                detail.isEmpty() ? QStringLiteral("sin respuesta JSON") : detail);
            if (critical)
                criticalFailed = true;
        }
    };
    try {
        // 1) i18n (no critico: solo locale)
        std::printf("[REFRESH] 1/6 i18n...\n"); fflush(stdout);
        check(apiCall(QStringLiteral("{\"do\":\"i18n\",\"update\":%1,\"locale\":\"es_CO\"}")
                          .arg(QDateTime::currentSecsSinceEpoch())),
              "1/6 i18n", false);
        std::printf("[REFRESH] 1/6 i18n OK (%lldms)\n", refreshTimer.elapsed()); fflush(stdout);
        QThread::msleep(500);
        // 2) FFA: connect gm=0 + gamemode mode=0 (critico: sin el cambio de
        // modo el server no settlea la XP de la gema)
        std::printf("[REFRESH] 2/6 FFA connect...\n"); fflush(stdout);
        QJsonObject conn = apiCall(QStringLiteral("{\"do\":\"connect\",\"invite\":false,\"defered\":true,\"i\":1,\"gm\":0,\"retrying\":false,\"locale\":\"es_CO\"}"));
        check(conn, "2/6 FFA connect", true);
        std::printf("[REFRESH] 2/6 FFA resp: %s\n", QJsonDocument(conn).toJson(QJsonDocument::Compact).left(120).constData()); fflush(stdout);
        check(apiCall(QStringLiteral("{\"do\":\"gamemode\",\"index\":1,\"mode\":0}")),
              "2/6 FFA gamemode", false);
        std::printf("[REFRESH] 2/6 FFA mode=0, waiting 4s...\n"); fflush(stdout);
        QThread::msleep(4000);
        // 3) HvZ: connect gm=7 + gamemode index=2 mode=7 (critico, idem)
        std::printf("[REFRESH] 3/6 HvZ connect...\n"); fflush(stdout);
        QJsonObject hvzConn = apiCall(QStringLiteral("{\"do\":\"connect\",\"invite\":false,\"defered\":true,\"i\":2,\"gm\":7,\"retrying\":false,\"locale\":\"es_CO\"}"));
        check(hvzConn, "3/6 HvZ connect", true);
        std::printf("[REFRESH] 3/6 HvZ resp: %s\n", QJsonDocument(hvzConn).toJson(QJsonDocument::Compact).left(120).constData()); fflush(stdout);
        check(apiCall(QStringLiteral("{\"do\":\"gamemode\",\"index\":2,\"mode\":7}")),
              "3/6 HvZ gamemode", false);
        std::printf("[REFRESH] 3/6 HvZ mode=7, waiting 3s...\n"); fflush(stdout);
        QThread::msleep(3000);
        // 4) inventory slot=5 (XP de la gema) — critico: es la lectura que
        // reporta cexp/exp; si falla no hay datos validos que devolver
        std::printf("[REFRESH] 4/6 inventory slot=5...\n"); fflush(stdout);
        QJsonObject inv = apiCall(QStringLiteral("{\"do\":\"inventory\",\"slot\":5}"));
        check(inv, "4/6 inventory", true);
        std::printf("[REFRESH] 4/6 inv resp(200): %s\n", QJsonDocument(inv).toJson(QJsonDocument::Compact).left(200).constData()); fflush(stdout);
        const QJsonArray items = inv.value("data").toObject().value("items").toArray();
        int currentId = inv.value("data").toObject().value("current").toInt();
        for (const auto &iv : items) {
            QJsonObject it = iv.toObject();
            if (it.value("id").toInt() == currentId) {
                result.cexp = it.value("cexp").toVariant().toLongLong();
                result.exp = it.value("exp").toVariant().toLongLong();
                std::printf("[REFRESH] 4/6 GEM: id=%d cexp=%lld exp=%lld\n", currentId, result.cexp, result.exp); fflush(stdout);
                break;
            }
        }
        QThread::msleep(1500);
        // 5) updateexp (no critico: solo el nivel)
        std::printf("[REFRESH] 5/6 updateexp...\n"); fflush(stdout);
        QJsonObject ue = apiCall(QStringLiteral("{\"do\":\"updateexp\"}"));
        check(ue, "5/6 updateexp", false);
        result.lvl = ue.value("data").toObject().value("lvl").toInt();
        std::printf("[REFRESH] 5/6 lvl=%d\n", result.lvl); fflush(stdout);
        QThread::msleep(500);
        // 6) back to CTF (critico: no dejar la cuenta en FFA/HvZ)
        std::printf("[REFRESH] 6/6 CTF...\n"); fflush(stdout);
        check(apiCall(QStringLiteral("{\"do\":\"connect\",\"invite\":false,\"defered\":true,\"i\":3,\"gm\":-1,\"retrying\":false,\"locale\":\"es_CO\"}")),
              "6/6 CTF connect", true);
        check(apiCall(QStringLiteral("{\"do\":\"gamemode\",\"index\":1,\"mode\":3}")),
              "6/6 CTF gamemode", true);
        // ok=true SOLO si todos los pasos esenciales pasaron; el error
        // acumulado (esenciales y no) se devuelve para el log del controller
        result.ok = !criticalFailed;
        if (!errors.isEmpty())
            result.error = errors.join("; ");
        std::printf("[REFRESH] === DONE in %lldms (ok=%d, errors=%d) ===\n",
                    refreshTimer.elapsed(), int(result.ok), int(errors.size())); fflush(stdout);
    } catch (const std::exception &e) {
        result.error = QStringLiteral("Exception: ") + e.what();
        std::printf("[REFRESH] ERROR: %s\n", result.error.toUtf8().constData()); fflush(stdout);
    } catch (...) {
        result.error = QStringLiteral("Unknown exception");
        std::printf("[REFRESH] UNKNOWN ERROR\n"); fflush(stdout);
    }
    QJsonObject out;
    out.insert("ok", result.ok);
    out.insert("cexp", result.cexp);
    out.insert("exp", result.exp);
    out.insert("lvl", result.lvl);
    out.insert("error", result.error);
    return out;
}
