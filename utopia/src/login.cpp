// login.cpp - LoginManager: KNOCK/LIM/EH + API
#include "login.h"
#include <cctype>

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
#include <QThread>
#include <QCoreApplication>
#include <QRandomGenerator>
#include <QDateTime>
#include <QElapsedTimer>

#include <windows.h>

namespace {
const QString kEngine = "https://app.mitos.is/engine_beta.php";
const QString kVersion = "10.1.8";
const QString kDesktop = "Dell Inc.;XPS 15 9530;Microsoft Windows 11 Pro;Windows;10.0.22631;x64;1920;1080";

QString urlEncode(const QString &s, bool plusForSpace)
{
    QByteArray in = s.toUtf8();
    QString out;
    for (char cc : in) {
        unsigned char ch = static_cast<unsigned char>(cc);
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            out += QChar(ch);
        else if (ch == ' ' && plusForSpace)
            out += '+';
        else
            out += QString("%%1").arg(int(ch), 2, 16, QLatin1Char('0')).toUpper();
    }
    return out;
}

QByteArray httpGet(const QUrl &url, QNetworkAccessManager *mgr)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    // debug: bytes exactos que Qt enviara (QUrl::toEncoded)
    std::printf("[httpEnc] %s\n", url.toEncoded().constData()); fflush(stdout);
    std::printf("[httpEncT] %s\n", url.toString().toUtf8().constData()); fflush(stdout);
    QNetworkReply *reply = mgr->get(req);
    // Espera activa: procesa eventos del hilo actual hasta que el reply termine.
    // (QEventLoop::exec() anidado falla cuando el hilo ya tiene un event loop
    // ocupado, p.ej. dentro del worker de una app QML.)
    QElapsedTimer timer;
    timer.start();
    while (!reply->isFinished() && timer.elapsed() < 15000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QThread::msleep(10);
    }
    QByteArray data = reply->isFinished() ? reply->readAll() : QByteArray();
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    QNetworkReply::NetworkError err = reply->error();
    std::printf("[httpGet] %.70s status=%d err=%d len=%d\n", url.toString().toUtf8().constData(), status, int(err), int(data.size()));
    {
        QFile logf(qEnvironmentVariable("APPDATA") + "/utopia_http.log");
        if (logf.open(QIODevice::Append)) {
            QTextStream ts(&logf);
            ts << QDateTime::currentDateTime().toString("HH:mm:ss.zzz")
               << " GET " << url.toString().left(80)
               << " status=" << status << " err=" << int(err)
               << " len=" << data.size() << " finished=" << reply->isFinished()
               << Qt::endl;
        }
    }
    reply->deleteLater();
    return data;
}

QByteArray httpPost(const QUrl &url, const QByteArray &body, QNetworkAccessManager *mgr)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    QNetworkReply *reply = mgr->post(req, body);
    QElapsedTimer timer;
    timer.start();
    while (!reply->isFinished() && timer.elapsed() < 15000) {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 50);
        QThread::msleep(10);
    }
    QByteArray data = reply->isFinished() ? reply->readAll() : QByteArray();
    int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    std::printf("[httpPost] %.60s status=%d len=%d\n", url.toString().toUtf8().constData(), status, int(data.size()));
    reply->deleteLater();
    return data;
}

QJsonObject parseJsonObject(const QByteArray &data)
{
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

LoginManager::LoginManager(QObject *parent) : QObject(parent) {}

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
        std::printf("[C++] LIM... token=%.30s\n", token.toUtf8().constData()); fflush(stdout);

        // ---- LIM ----
        auto parts = stringDesturple(token);
        Bytes edidBlob = m2xcEncryptFull(bytesOf(m_deviceId), bytesOf(parts.first),
                                         0xBC461A49, 0x7C2359AB);
        QString edid = m2xcFmt(edidBlob);
        qWarning("TOKEN: %.60s", token.toUtf8().constData());
        qWarning("SD1: %.40s", parts.first.toUtf8().constData());
        qWarning("EDID: %.80s", edid.toUtf8().constData());
        QVector<QPair<QString, QString>> limParams = {
            {"rus", "1"}, {"loc", "es_CO"}, {"ver", kVersion}, {"dds", "1920x1080"},
            {"do", "lim"}, {"t", token}, {"ddd", kDesktop}, {"fmt", "tbt"},
            {"chk", chk}, {"did", edid}, {"rndx", rndx()},
        };
        QJsonObject lim = parseJsonObject(httpGet(QUrl(kEngine + "?" + makeQuery(limParams)), &m_net));
        if (lim.value("result").toString() != "ok") {
            result.error = "LIM failed: " + lim.value("message").toString() + " (reset_did?)";
            return result;
        }
        QString dk = lim.value("data").toObject().value("dk").toString();
        QString dm = lim.value("data").toObject().value("dm").toString();
        std::printf("[C++] TOKEN: %s\n", token.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DK FULL: %s\n", dk.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DM FULL: %s\n", dm.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] SD1: %.40s\n", parts.first.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] EDID FULL: %s\n", edid.toUtf8().constData()); fflush(stdout);
        QString dkKey = md5Hex(token + m_deviceId);
        QString dmKey = md5Hex(m_deviceId + token);
        Bytes skBlob = m2xcDecryptFull(parseM2xcBlob(dk), bytesOf(dkKey));
        Bytes rkBlob = m2xcDecryptFull(parseM2xcBlob(dm), bytesOf(dmKey));
        if (skBlob.empty() || rkBlob.empty()) {
            result.error = "LIM: could not decrypt sk/rk";
            return result;
        }
        m_sessionKey = QString::fromUtf8(reinterpret_cast<const char *>(skBlob.data()), int(skBlob.size()));
        std::printf("[C++] SK: %s len=%d\n", m_sessionKey.toUtf8().constData(), int(m_sessionKey.size())); fflush(stdout);
        QString rsaPublicKey = QString::fromUtf8(reinterpret_cast<const char *>(rkBlob.data()), int(rkBlob.size()));

        // ---- EH ----
        m_magic = genMagic(64);
        QString dtf = buildDtf(m_sessionKey);
        // proof: con la PEM de atestacion si existe; si no, con la clave TPM
        // REAL del dispositivo (MitosDeviceKeyV2, la que el server registro).
        QByteArray chMsg = (dtf + "|" + m_deviceId + "|100").toUtf8();
        Bytes sig;
        QString mid;
        if (!m_attestPem.isEmpty()) {
            sig = rsaSignPkcs1Sha256(m_attestPem, chMsg);
            mid = buildMidPem(m_attestPem);
        } else {
            sig = tpmSignPkcs1Sha256(chMsg);
            mid = tpmBuildMid();
        }
        QString proof = urlB64EncodeNoPad(sig);
        std::printf("[C++] PROOF: %s\n", proof.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] MID FULL: %s\n", mid.toUtf8().constData()); fflush(stdout);

        QString ddJson = QString("{\"proof\":\"%1\",\"mid\":\"%2\",\"ver\":\"%3\",\"host\":\"app.mitos.is\"}")
                             .arg(proof, mid, kVersion);
        u32 R10 = u32(quint64(QDateTime::currentMSecsSinceEpoch()) ^ quint64(QRandomGenerator::global()->generate()));
        u32 ddH2 = u32(QRandomGenerator::global()->generate());
        std::printf("[C++] R10: %08x H2: %08x\n", R10, ddH2); fflush(stdout);
        Bytes ddBlob = m2xcEncryptFull(bytesOf(ddJson),
                                       bytesOf(m_magic), R10,
                                       ddH2);
        QString dd = m2xcFmt(ddBlob);
        std::printf("[C++] RK: %.80s\n", rsaPublicKey.left(80).toUtf8().constData()); fflush(stdout);
        QString ms = rsaEncryptPkcs1Base64(rsaPublicKey, m_magic);
        std::printf("[C++] MS: %.60s len=%d\n", ms.toUtf8().constData(), int(ms.size())); fflush(stdout);
        std::printf("[C++] RK FULL: %s\n", rsaPublicKey.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] MAGIC: %s\n", m_magic.toUtf8().constData()); fflush(stdout);
        std::printf("[C++] DTF FULL: %s\n", dtf.toUtf8().constData()); fflush(stdout);

        QVector<QPair<QString, QString>> ehParams = {
            {"go", "0"}, {"dd", dd}, {"de", "desktop"}, {"gi", "0"},
            {"ver", kVersion}, {"it", "1"}, {"do", "eh"}, {"im", "0"},
            {"di", kDesktop}, {"dtf", dtf}, {"ms", ms}, {"rndx", rndx()},
        };
        QString ehUrl = kEngine + "?" + makeQuery(ehParams, true);
        std::printf("[C++] EH URL: %s\n", ehUrl.toUtf8().constData()); fflush(stdout);
        QByteArray eh;
        if (qEnvironmentVariableIsSet("GEMXP_SKIP_EH")) {
            std::printf("[C++] SKIP_EH: no se envia el EH\n"); fflush(stdout);
            eh = QByteArray("{}");
        } else {
            eh = httpGet(QUrl(ehUrl), &m_net);
        }
        std::printf("[C++] EH response: %.200s\n", eh.constData()); fflush(stdout);
        if (!QString::fromUtf8(eh).contains("ok")) {
            result.error = "EH failed: " + QString::fromUtf8(eh).left(120);
            return result;
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

QJsonObject LoginManager::fetchUpdateExp()
{
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
            if (!parseJsonObject(payload).contains(QStringLiteral("data"))) {
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

// POST cifrado generico para acciones del engine (do=craft, etc).
// Replica el patron de fetchInventory: URL con _sid + body cifrado M2XC(magic).
QByteArray LoginManager::postEncrypted(const QJsonObject &body)
{
    if (m_sessionKey.isEmpty() || m_magic.isEmpty())
        return {};
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QJsonDocument doc(body);
    QString bodyJson = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
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
    // si la respuesta trae el balance actual (data.coins), actualizar m_lastCoins
    {
        QJsonParseError perr;
        QJsonDocument pdoc = QJsonDocument::fromJson(payload, &perr);
        if (perr.error == QJsonParseError::NoError && pdoc.isObject()) {
            QJsonObject d = pdoc.object().value("data").toObject();
            if (d.contains(QStringLiteral("coins")) && d.value("coins").isDouble())
                m_lastCoins = d.value("coins").toVariant().toLongLong();
        }
    }
    return payload;
}

// POST cifrado generico a un host del engine (engine.php o engine_beta.php).
QByteArray LoginManager::postEncryptedHost(const QJsonObject &body, const QString &host)
{
    if (m_sessionKey.isEmpty() || m_magic.isEmpty())
        return {};
    QString url = host + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QJsonDocument doc(body);
    QString bodyJson = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
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
    return payload;
}

// Variante del POST con cifrado v5oh2 (AES-CBC + deriveAesKey(magic)),
// formato len8+base64 igual que el LISTENER del tcp_farm.
QByteArray LoginManager::postEncryptedV5oh2(const QJsonObject &body)
{
    return postEncryptedV5oh2Key(body, deriveAesKey(m_magic));
}

// v5oh2 con clave derivada custom (offset 100 = loginifneeded).
QByteArray LoginManager::postEncryptedV5oh2Key(const QJsonObject &body, const Bytes &key)
{
    if (m_sessionKey.isEmpty() || m_magic.isEmpty())
        return {};
    QString url = kEngine + "?_sid=" + urlEncode(m_sessionKey, false) + "&rndx=" + rndx();
    QJsonDocument doc(body);
    QString bodyJson = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    Bytes padded(bytesOf(bodyJson));
    int pad = (16 - (int(padded.size()) % 16)) % 16;
    padded.insert(padded.end(), size_t(pad), 0);
    Bytes ct = aesCbcCrypt(padded, key, true);
    QString bodyV5 = QString("%1%2").arg(int(bodyJson.size()), 8, 10, QLatin1Char('0')) + b64Encode(ct);
    QByteArray resp = httpPost(QUrl(url), bodyV5.toUtf8(), &m_net);
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
    return payload;
}

