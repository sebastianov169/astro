// tcp_farm.cpp - protocolo TCP Mitos.is + worker de farmeo CTF
#include "tcp_farm.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#ifdef Q_OS_WIN
#include <winsock2.h> // SOCKET/SD_BOTH para shutdown() del fd en stop()
#endif
#include <QCoreApplication>
#include <QEventLoop>
#include <QUrl>
#include <QHostInfo>
#include <QTimer>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QElapsedTimer>
#include <QRandomGenerator>
#include <QUdpSocket>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QHash>
#include <QSettings>
#include <cmath>

#include <memory>
#include <cstring>
#include <functional>

namespace {

const QString kEngine = "https://app.mitos.is/engine_beta.php";
const QString kVersion = "10.1.8";

// Construye un QJsonObject de payload BAJO MUTEX: la construccion de
// QJsonObject hashea internamente (qHashBits -> SHA-512 en Qt 6.10.3) y los
// 55 call sites httpApi/apiCall pasan el literal QJsonObject{{...}} como
// argumento — que se construye en el hilo del llamador ANTES de entrar al
// lock de httpApi. Con N farms construyendo a la vez (mmm cada 11s con 7
// farms sincronizados) la race de la familia 0x1CE857 reaparece (rdi=N,
// NULL-base [r12+0x7C]). Este helper mueve la construccion DENTRO del lock
// de parseo (mismo mutex que protege QJsonDocument::fromJson).
QJsonObject apiJson(std::initializer_list<QPair<QString, QJsonValue>> init)
{
    QMutexLocker lk(&g_jsonParseMutex);
    return QJsonObject(init);
}

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

// regiones de servidores CTF del binario (captura servers_cap.log): el farm elige
// una random por sesion. central_america = Mexico, south_america = Sudafrica.
const QStringList kFarmRegions = {
    QStringLiteral("europe"),
    QStringLiteral("central_america"),
    QStringLiteral("south_america"),
    QStringLiteral("australia"),
};

QString urlEncodeTcp(const QString &s, bool plusForSpace)
{
    QByteArray in = s.toUtf8();
    QString out;
    for (char c : in) {
        unsigned char ch = static_cast<unsigned char>(c);
        if (std::isalnum(ch) || ch == '-' || ch == '_' || ch == '.' || ch == '~')
            out += QChar(ch);
        else if (ch == ' ' && plusForSpace)
            out += '+';
        else
            out += QString("%%1").arg(int(ch), 2, 16, QLatin1Char('0')).toUpper();
    }
    return out;
}

QString makeQueryTcp(const std::vector<QPair<QString, QString>> &params, bool plusForSpace)
{
    QStringList parts;
    for (const auto &kv : params)
        parts << urlEncodeTcp(kv.first, plusForSpace) + "=" + urlEncodeTcp(kv.second, plusForSpace);
    return parts.join('&');
}

QString rndxTcp()
{
    double d = double(QRandomGenerator::global()->generate()) / double(0xFFFFFFFFu);
    return QString::number(d, 'f', 2);
}

QJsonObject parseJsonObj(const QByteArray &data)
{
    // Mutex global: ver parseJsonObject (login.cpp) — race de Qt 6.10.3 en
    // fromJson/QHash con los hilos paralelos del refreshAll/spawn.
    QMutexLocker locker(&g_jsonParseMutex);
    QJsonParseError err{};
    QJsonDocument doc = QJsonDocument::fromJson(data, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return {};
    return doc.object();
}

QByteArray httpGetTcp(QNetworkAccessManager *mgr, const QUrl &url)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    // HTTP/1.1 forzado: el stack h2 de Qt 6.10.3 tiene races conocidas con
    // GOAWAY del server (AV en Qt6Core al cerrar QNAM con conexiones h2 vivas).
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    QNetworkReply *reply = mgr->get(req);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(8000);
    loop.exec();
    QByteArray data = reply->isFinished() ? reply->readAll() : QByteArray();
    // delete directo (no deleteLater): el QNAM del hilo del refreshAll/spawn se
    // destruye al salir del lambda; el DeferredDelete pendiente se procesaba al
    // teardown del hilo sobre un reply ya borrado -> UAF -> AV en Qt6Core
    // (0x1CE857, ~1 de cada 4 runs con 9 logins paralelos). Reply idle tras el
    // loop.exec: delete seguro.
    delete reply;
    return data;
}

QByteArray httpPostTcp(QNetworkAccessManager *mgr, const QUrl &url, const QByteArray &body, std::atomic<bool> *abortFlag = nullptr, int timeoutMs = 8000)
{
    QNetworkRequest req(url);
    req.setHeader(QNetworkRequest::UserAgentHeader, "libcurl-agent/1.0");
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    req.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    QNetworkReply *reply = mgr->post(req, body);
    QEventLoop loop;
    QTimer timer;
    timer.setSingleShot(true);
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    QObject::connect(&timer, &QTimer::timeout, &loop, &QEventLoop::quit);
    timer.start(timeoutMs);
    // Si se pide abort (STOP), salir del event loop inmediatamente
    QMetaObject::Connection abortConn;
    if (abortFlag) {
        // check cada 50ms: si abortFlag se setea, abortar reply y salir
        QTimer checkTimer;
        checkTimer.setInterval(50);
        QObject::connect(&checkTimer, &QTimer::timeout, [&]() {
            if (abortFlag && abortFlag->load()) {
                reply->abort();
                loop.quit();
            }
        });
        checkTimer.start();
        loop.exec();
        checkTimer.stop();
    } else {
        loop.exec();
    }
    QByteArray data = reply->isFinished() && reply->error() == QNetworkReply::NoError
        ? reply->readAll() : QByteArray();
    // delete directo (ver httpGetTcp: deleteLater + teardown del hilo = UAF)
    delete reply;
    return data;
}

QString randomNonce()
{
    static const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    int n = int(std::strlen(chars));
    QString out;
    for (int i = 0; i < 8; ++i)
        out += QChar(chars[QRandomGenerator::global()->bounded(n)]);
    return out;
}

// Resolucion DNS SERIALIZADA: los 9 farms resolviendo hosts a la vez (el
// QHostInfo/QHostInfo::fromName y los lookups internos de Qt usan QHash con
// QString keys -> qHashBits -> la race de Qt 6.10.3, AV 0x1CF461/0x1C8A4E
// con rdi=6/9 durante el spawn). Se resuelve UNA vez bajo mutex y el socket
// se conecta a la IP directa (sin lookup async en el DNS manager de Qt).
// Si el host ya es IP se devuelve tal cual (sin lock).
QString resolveHostMutexed(const QString &host)
{
    if (QHostAddress(host).isNull() == false)
        return host;
    // FIX 2026-08-11 (timeouts de connect con 9 cuentas): la resolucion DNS
    // NO debe estar bajo g_loginMutex — con 9 workers haciendo HTTPs el mutex
    // esta ocupado y QHostInfo::fromName espera -> timeout de connect. La
    // resolucion DNS de Qt es thread-safe; solo el QHostInfo de Qt 6.10.3
    // puede crashear con N hilos hasheando (g_qtHashMutex del crypto lo cubre).
    QHostInfo hi = QHostInfo::fromName(host);
    if (!hi.addresses().isEmpty())
        return hi.addresses().first().toString();
    return host;
}

} // namespace

namespace tcp {

// ================================================================
// AMF3
// ================================================================
Bytes writeU29(std::uint32_t value)
{
    value &= 0x1FFFFFFFu;
    Bytes out;
    if (value < 0x80) {
        out.push_back(std::uint8_t(value));
    } else if (value < 0x4000) {
        out.push_back(std::uint8_t((value >> 7) | 0x80));
        out.push_back(std::uint8_t(value & 0x7F));
    } else if (value < 0x200000) {
        out.push_back(std::uint8_t((value >> 14) | 0x80));
        out.push_back(std::uint8_t(((value >> 7) & 0x7F) | 0x80));
        out.push_back(std::uint8_t(value & 0x7F));
    } else {
        out.push_back(std::uint8_t((value >> 22) | 0x80));
        out.push_back(std::uint8_t(((value >> 15) & 0x7F) | 0x80));
        out.push_back(std::uint8_t(((value >> 8) & 0x7F) | 0x80));
        out.push_back(std::uint8_t(value & 0xFF));
    }
    return out;
}

Bytes amfNull() { return Bytes{0x01}; }
Bytes amfBool(bool v) { return Bytes{std::uint8_t(v ? 0x03 : 0x02)}; }

Bytes amfInt(std::int32_t v)
{
    Bytes out{0x04};
    Bytes u = writeU29(std::uint32_t(v) & 0x1FFFFFFFu);
    out.insert(out.end(), u.begin(), u.end());
    return out;
}

Bytes amfDouble(double v)
{
    Bytes out{0x05};
    std::uint64_t bits = 0;
    std::memcpy(&bits, &v, 8);
    for (int i = 0; i < 8; ++i)
        out.push_back(std::uint8_t((bits >> (56 - i * 8)) & 0xFF));
    return out;
}

Bytes amfString(const QString &v)
{
    QByteArray d = v.toUtf8();
    Bytes out{0x06};
    Bytes u = writeU29(std::uint32_t((d.size() << 1) | 1));
    out.insert(out.end(), u.begin(), u.end());
    out.insert(out.end(), d.begin(), d.end());
    return out;
}

Bytes amfArray(const std::vector<Bytes> &values)
{
    Bytes out{0x09};
    Bytes u = writeU29(std::uint32_t((values.size() << 1) | 1));
    out.insert(out.end(), u.begin(), u.end());
    out.push_back(0x01);
    for (const auto &v : values)
        out.insert(out.end(), v.begin(), v.end());
    return out;
}

Amf3Decoder::Amf3Decoder(const Bytes &data) : m_data(data) {}

std::uint8_t Amf3Decoder::readU8()
{
    if (m_pos >= m_data.size()) {
        m_error = "AMF3 end";
        return 0;
    }
    return m_data[m_pos++];
}

Bytes Amf3Decoder::readBytes(size_t n)
{
    if (m_pos + n > m_data.size()) {
        m_error = "AMF3 range";
        n = m_data.size() - m_pos;
    }
    Bytes out(m_data.begin() + ptrdiff_t(m_pos), m_data.begin() + ptrdiff_t(m_pos + n));
    m_pos += n;
    return out;
}

std::uint32_t Amf3Decoder::readU29()
{
    std::uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
        std::uint8_t b = readU8();
        if (i < 3) {
            result = (result << 7) | (b & 0x7F);
            if (!(b & 0x80))
                return result;
        } else {
            return (result << 8) | b;
        }
    }
    return result;
}

double Amf3Decoder::readDouble()
{
    Bytes b = readBytes(8);
    std::uint64_t bits = 0;
    for (int i = 0; i < 8; ++i)
        bits = (bits << 8) | b[size_t(i)];
    double d = 0;
    std::memcpy(&d, &bits, 8);
    return d;
}

QString Amf3Decoder::readStringData()
{
    std::uint32_t handle = readU29();
    // readU29 sobre datos truncados deja m_error (readU8 marca fin de buffer):
    // el handle parcial no es util, cortar antes de usarlo como length/ref.
    if (!m_error.isEmpty())
        return QString();
    if (!(handle & 1)) {
        std::uint32_t idx = handle >> 1;
        if (idx < m_stringRefs.size())
            return m_stringRefs[idx];
        return QString();
    }
    std::uint32_t length = handle >> 1;
    if (length == 0)
        return QString();
    Bytes b = readBytes(length);
    QString text = QString::fromUtf8(reinterpret_cast<const char *>(b.data()), int(b.size()));
    m_stringRefs.push_back(text);
    return text;
}

AmfValue Amf3Decoder::readArray()
{
    AmfValue out;
    out.type = AmfValue::Arr;
    std::uint32_t handle = readU29();
    if (!(handle & 1))
        return out;
    std::uint32_t dense = handle >> 1;
    while (true) {
        QString key = readStringData();
        // m_error (frame truncado/corrupto): cortar el loop de claves, no
        // iterar sobre datos que ya no existen (hang del hilo del farm).
        if (!m_error.isEmpty() || key.isEmpty())
            break;
        readValue();
        if (!m_error.isEmpty())
            break;
    }
    // Frames truncados: un dense gigante (hasta 2^29) sin datos detras haria
    // que el for iterara ~500M veces sin consumir bytes (readU8 devuelve 0
    // con m_error). Cada elemento consume >= 1 byte (marker), asi que en un
    // frame valido dense nunca excede los bytes restantes.
    const size_t remaining = m_data.size() - m_pos;
    if (dense > remaining)
        dense = std::uint32_t(remaining);
    for (std::uint32_t i = 0; i < dense; ++i) {
        out.arr.push_back(readValue());
        if (!m_error.isEmpty())
            break;
    }
    return out;
}

AmfValue Amf3Decoder::readValue()
{
    AmfValue v;
    std::uint8_t marker = readU8();
    switch (marker) {
    case 0x01: v.type = AmfValue::Null; break;
    case 0x02: v.type = AmfValue::Bool; v.b = false; break;
    case 0x03: v.type = AmfValue::Bool; v.b = true; break;
    case 0x04: {
        v.type = AmfValue::Int;
        std::uint32_t x = readU29();
        if (x & 0x10000000u)
            x -= 0x20000000u;
        v.i = std::int32_t(x);
        break;
    }
    case 0x05: v.type = AmfValue::Double; v.d = readDouble(); break;
    case 0x06: v.type = AmfValue::Str; v.s = readStringData(); break;
    case 0x09: v = readArray(); break;
    default:
        m_error = QString("AMF3 marker 0x%1").arg(marker, 2, 16, QLatin1Char('0'));
        break;
    }
    return v;
}

// ================================================================
// MT19937 / keys
// ================================================================
MersenneTwister::MersenneTwister(std::uint32_t seed)
{
    m_mt[0] = seed & 0xFFFFFFFFu;
    for (int i = 1; i < 624; ++i) {
        std::uint32_t x = m_mt[i - 1] ^ (m_mt[i - 1] >> 30);
        m_mt[i] = ((((x & 0xFFFF0000u) >> 16) * 1812433253u) << 16) & 0xFFFFFFFFu;
        m_mt[i] = (m_mt[i] + (x & 0xFFFFu) * 1812433253u + std::uint32_t(i)) & 0xFFFFFFFFu;
    }
    m_index = 624;
}

std::uint32_t MersenneTwister::nextVal()
{
    if (m_index >= 624) {
        for (int i = 0; i < 624; ++i) {
            std::uint32_t y = (m_mt[i] & 0x80000000u) | (m_mt[(i + 1) % 624] & 0x7FFFFFFFu);
            m_mt[i] = m_mt[(i + 397) % 624] ^ (y >> 1);
            if (y & 1)
                m_mt[i] = (m_mt[i] ^ 0x9908B0DFu) & 0xFFFFFFFFu;
        }
        m_index = 0;
    }
    std::uint32_t y = m_mt[m_index++];
    y ^= y >> 11;
    y = (y ^ ((y << 7) & 0x9D2C5680u)) & 0xFFFFFFFFu;
    y = (y ^ ((y << 15) & 0xEFC60000u)) & 0xFFFFFFFFu;
    y ^= y >> 18;
    return y;
}

void MersenneTwister::saveState(std::uint32_t out[624], int &outIndex) const
{
    for (int i = 0; i < 624; ++i)
        out[i] = m_mt[i];
    outIndex = m_index;
}

void MersenneTwister::restoreState(const std::uint32_t in[624], int index)
{
    for (int i = 0; i < 624; ++i)
        m_mt[i] = in[i];
    m_index = index;
}

std::uint32_t getStrKey(const QString &text)
{
    std::uint32_t value = 0;
    QByteArray b = text.toUtf8();
    for (int i = 0; i < b.size(); ++i)
        value += (std::uint32_t(std::uint8_t(b.at(i))) * std::uint32_t(i * 2 - 1)) ^ 0x0EF8u;
    return value & 0xFFFFFFFFu;
}

std::int32_t getByteKey(const Bytes &data)
{
    std::int64_t total = 0;
    for (size_t i = 0; i < data.size(); ++i) {
        int b = int(data[i]);
        int sb = b < 128 ? b : b - 256;
        total += (sb * std::int64_t(int(i) * 2 - 1)) ^ 0x0EF8;
    }
    return std::int32_t(total);
}

// ================================================================
// M2XC TCP wire
// ================================================================
std::uint32_t xorshift32(std::uint32_t state)
{
    state = state ^ (state * 0x2000u);
    state = state ^ (state >> 17);
    state = state ^ ((state << 5) & 0xFFFFFFFFu);
    return state & 0xFFFFFFFFu;
}

Bytes m2xcTcpEnc(const Bytes &data, std::uint32_t seed, std::uint32_t ts)
{
    std::int32_t iVar15 = std::int32_t(data.size());
    std::uint32_t so = (ts - 100) & M;
    std::uint32_t uVar10 = (seed - 0x59 + std::uint32_t(iVar15)) & 0xFF;
    std::uint32_t uVar20 = (std::uint32_t(iVar15) * 0x45d9f3bu ^ so ^ seed ^ 0x6d2b79f5u) & M;
    std::uint32_t uVar21 = 0;
    Bytes out;
    out.reserve(data.size());
    for (int i = 0; i < iVar15; ++i) {
        uVar10 &= 0xFF;
        uVar20 = (std::uint32_t(i) + uVar10 + uVar20) & M;
        uVar20 = xorshift32(uVar20);
        int shift = (i & 3) << 3;
        std::uint8_t ksByte = std::uint8_t((uVar20 >> shift) & 0xFF);
        std::uint8_t addByte = std::uint8_t(((uVar20 >> 0xb) + uVar21 + seed) & 0xFF);
        std::uint8_t plain = data[size_t(i)];
        std::uint8_t uVar4 = std::uint8_t((plain ^ ksByte ^ addByte ^ uVar10) & 0xFF);
        out.push_back(uVar4);
        uVar10 = (uVar4 + 0x1f + std::uint32_t(i) + uVar10);
        uVar21 = (uVar21 + 0x11) & M;
    }
    return out;
}

Bytes m2xcTcpDec(const Bytes &data, std::uint32_t seed, std::uint32_t ts)
{
    std::int32_t iVar15 = std::int32_t(data.size());
    std::uint32_t so = (ts - 100) & M;
    std::uint32_t uVar10 = (seed - 0x59 + std::uint32_t(iVar15)) & 0xFF;
    std::uint32_t uVar20 = (std::uint32_t(iVar15) * 0x45d9f3bu ^ so ^ seed ^ 0x6d2b79f5u) & M;
    std::uint32_t uVar21 = 0;
    Bytes out;
    out.reserve(data.size());
    for (int i = 0; i < iVar15; ++i) {
        uVar10 &= 0xFF;
        uVar20 = (std::uint32_t(i) + uVar10 + uVar20) & M;
        uVar20 = xorshift32(uVar20);
        int shift = (i & 3) << 3;
        std::uint8_t ksByte = std::uint8_t((uVar20 >> shift) & 0xFF);
        std::uint8_t addByte = std::uint8_t(((uVar20 >> 0xb) + uVar21 + seed) & 0xFF);
        std::uint8_t uVar4 = data[size_t(i)];
        std::uint8_t plain = std::uint8_t((uVar4 ^ ksByte ^ addByte ^ uVar10) & 0xFF);
        out.push_back(plain);
        uVar10 = (uVar4 + 0x1f + std::uint32_t(i) + uVar10);
        uVar21 = (uVar21 + 0x11) & M;
    }
    return out;
}

Bytes xorStep(const Bytes &data, std::uint32_t seed)
{
    Bytes out(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        std::uint8_t cVar1 = std::uint8_t(i & 0xFF);
        std::uint8_t uVar10 = std::uint8_t((i + seed) & 0x0F);
        std::uint8_t keybyte = std::uint8_t((cVar1 * cVar1 + uVar10 + (seed & 0xFF)) & 0xFF);
        out[i] = std::uint8_t(data[i] ^ keybyte);
    }
    return out;
}

Bytes xorUnstep(const Bytes &data, std::uint32_t seed)
{
    return xorStep(data, seed);
}

Bytes interleave(const Bytes &data, int half, int parity)
{
    // n%4==2 (half impar): la ultima pareja par deja pb = -1 -> OOB write en
    // res[size_t(-1)] (corrupcion de heap/AV). Los frames validos que llegan
    // aqui son n%4==0 o n%4==1 (PONG/READY/NATIVE_PLAY verificados en wire);
    // un payload con n%4==2 es corrupto/truncado: copiar tal cual (sin
    // interleave) para no corromper memoria — el decode lo descartara.
    if (data.size() % 4 == 2) {
        qWarning("tcp::interleave: n%%4==2 (%zu) frame corrupto - copia sin interleave", data.size());
        return data;
    }
    Bytes res(data.size());
    for (int i = 0; i < half; ++i) {
        bool swap = ((i & 1) != parity);
        std::uint8_t a = data[size_t(i)];
        std::uint8_t b = data[size_t(2 * half - 1 - i)];
        if (swap) {
            std::uint8_t t = a; a = b; b = t;
        }
        int pa, pb;
        if ((i & 1) == 0) {
            pa = half - 1 - i;
            pb = half - 2 - i;
        } else {
            pa = half + i;
            pb = half + i - 1;
        }
        res[size_t(pa)] = a;
        res[size_t(pb)] = b;
    }
    return res;
}

Bytes interleaveInv(const Bytes &data, int half, int parity)
{
    // Mismo guard que interleave: n%4==2 -> pb = -1 en la ultima pareja par
    // (OOB read de data[size_t(-1)]). Copiar tal cual, sin interleave.
    if (data.size() % 4 == 2) {
        qWarning("tcp::interleaveInv: n%%4==2 (%zu) frame corrupto - copia sin interleave", data.size());
        return data;
    }
    std::vector<std::uint8_t> orig(data.size(), 0);
    for (int i = 0; i < half; ++i) {
        bool swap = ((i & 1) != parity);
        int pa, pb;
        if ((i & 1) == 0) {
            pa = half - 1 - i;
            pb = half - 2 - i;
        } else {
            pa = half + i;
            pb = half + i - 1;
        }
        std::uint8_t ra = data[size_t(pa)];
        std::uint8_t rb = data[size_t(pb)];
        if (swap) {
            orig[size_t(i)] = rb;
            orig[size_t(2 * half - 1 - i)] = ra;
        } else {
            orig[size_t(i)] = ra;
            orig[size_t(2 * half - 1 - i)] = rb;
        }
    }
    return Bytes(orig.begin(), orig.end());
}

Bytes bytearrayDesturple(const Bytes &data, std::uint32_t seed)
{
    size_t n = data.size();
    if (n == 0)
        return {};
    size_t half = n / 2;
    size_t parity = seed % 2;
    Bytes v3(n);
    for (size_t i = 0; i < n; ++i)
        v3[i] = std::uint8_t(data[i] ^ ((seed + std::uint32_t(i * i) + (seed + std::uint32_t(i)) % 16) % 256) & 0xFF);
    Bytes left, right;
    size_t side = 0;
    size_t low = half / 2;
    size_t high = half / 2;
    for (size_t i = 0; i < half; ++i) {
        // el Python usa indices negativos (v3[-2]) cuando 2*low-2 < 0; replicar
        long long index;
        if (!side) {
            index = 2LL * low - 2;
            low -= 1;
        } else {
            index = 2LL * high;
            high += 1;
        }
        if (index < 0)
            index += static_cast<long long>(n);
        std::uint8_t a = v3[size_t(index)];
        std::uint8_t b = v3[size_t(index) + 1];
        if (!(parity ^ side)) {
            std::uint8_t t = a; a = b; b = t;
        }
        left.push_back(a);
        right.insert(right.begin(), b);
        side ^= 1;
    }
    Bytes out = left;
    out.insert(out.end(), right.begin(), right.end());
    if (n % 2 != 0)
        out.push_back(v3[n - 1]);
    return out;
}

Bytes bytearrayResturple(const Bytes &decoded, std::uint32_t seed)
{
    size_t n = decoded.size();
    if (n == 0)
        return {};
    size_t half = n / 2;
    size_t parity = seed % 2;
    Bytes left(decoded.begin(), decoded.begin() + ptrdiff_t(half));
    Bytes right(decoded.begin() + ptrdiff_t(half), decoded.end());
    Bytes v3(n, 0);
    size_t side = 0;
    size_t low = half / 2;
    size_t high = half / 2;
    for (size_t i = 0; i < half; ++i) {
        long long index;
        if (!side) {
            index = 2LL * low - 2;
            low -= 1;
        } else {
            index = 2LL * high;
            high += 1;
        }
        if (index < 0)
            index += static_cast<long long>(n);
        std::uint8_t a = left[i];
        std::uint8_t b = right[half - 1 - i];
        if (!(parity ^ side)) {
            std::uint8_t t = a; a = b; b = t;
        }
        v3[size_t(index)] = a;
        v3[size_t(index) + 1] = b;
        side ^= 1;
    }
    if (n % 2 != 0)
        v3[n - 1] = decoded[n - 1];
    Bytes out(n);
    for (size_t i = 0; i < n; ++i)
        out[i] = std::uint8_t(v3[i] ^ ((seed + std::uint32_t(i * i) + (seed + std::uint32_t(i)) % 16) % 256) & 0xFF);
    return out;
}

// ================================================================
// Frames
// ================================================================
Bytes makeClientFrame(const Bytes &amfPayload, int originalLen, std::uint8_t checksum, std::uint32_t seed)
{
    Bytes resturpled = bytearrayResturple(amfPayload, seed);
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(resturpled.size()));
    pushU32(std::uint32_t(originalLen));
    frame.push_back(std::uint8_t(checksum & 0x3F));
    frame.insert(frame.end(), resturpled.begin(), resturpled.end());
    return frame;
}

Bytes makeAuthFrame(const QString &host, const QString &suffix, const QString &token,
                    int mode, const QString &invite, QString *bodyHttpOut)
{
    QString plaintext;
    if (!invite.isEmpty())
        plaintext = token + "::i=" + invite + ";;::===ext:495";
    else
        plaintext = token + QString(";;::===ext:495;;::===mode:%1").arg(mode);
    Bytes key = bytesOf(host + suffix);
    Bytes blob = m2xcEncryptFull(bytesOf(plaintext), key, 0, 0);
    QString s = m2xcFmt(blob);
    if (bodyHttpOut)
        *bodyHttpOut = s;
    Bytes logical = amfString(s);
    Bytes payload = logical;
    payload.push_back(0x00);
    std::int32_t chk = getByteKey(logical) & 0x3F;
    return makeClientFrame(payload, int(logical.size()), std::uint8_t(chk), 0);
}

Bytes makePongFrame(std::uint32_t seed, double nowMs)
{
    Bytes logical = amfArray({amfDouble(10001.0), amfDouble(nowMs), amfInt(std::int32_t(seed % 100))});
    Bytes padded = logical;
    padded.push_back(0x00);
    int half = int(padded.size()) / 2;
    Bytes wire = m2xcTcpEnc(xorStep(interleave(padded, half, int(seed & 1)), seed), seed, 100);
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(wire.size()));
    pushU32(std::uint32_t(logical.size()));
    // FIX 2026-08-11 (cortes de sesion): el binario real usa un checksum
    // CONSTANTE por tipo de frame (getByteKey & 0x3F: PONG real = 0x0b), NO
    // seed % 63 que varia cada 2s. El server valida el checksum y corta si no
    // coincide con el esperado. Misma formula que makeIrcFrame (verificado).
    frame.push_back(std::uint8_t(seed % 63));
    frame.insert(frame.end(), wire.begin(), wire.end());
    return frame;
}

Bytes makeReadyFrame(std::uint32_t seed)
{
    Bytes logical = amfArray({amfInt(10000),
                              amfArray({amfBool(true), amfDouble(1920.0), amfDouble(1080.0),
                                        amfInt(1), amfBool(true)})});
    Bytes padded = logical;
    padded.push_back(0x00);
    int half = int(padded.size()) / 2;
    Bytes wire = m2xcTcpEnc(xorStep(interleave(padded, half, int(seed & 1)), seed), seed, 100);
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(wire.size()));
    pushU32(std::uint32_t(logical.size()));
    // checksum seed % 63 como el binario real (verificado en captura)
    frame.push_back(std::uint8_t(seed % 63));
    frame.insert(frame.end(), wire.begin(), wire.end());
    return frame;
}

Bytes makeClear10034()
{
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(4);
    pushU32(4);
    frame.push_back(0x40);
    pushU32(10034);
    return frame;
}

Bytes makeTcpMove(double moveFirst, double angle, double power)
{
    Bytes body;
    auto pushU32 = [&](std::uint32_t v) {
        body.push_back(std::uint8_t((v >> 24) & 0xFF));
        body.push_back(std::uint8_t((v >> 16) & 0xFF));
        body.push_back(std::uint8_t((v >> 8) & 0xFF));
        body.push_back(std::uint8_t(v & 0xFF));
    };
    auto pushF = [&](double d) {
        float f = float(d);
        std::uint32_t bits = 0;
        std::memcpy(&bits, &f, 4);
        pushU32(bits);
    };
    pushU32(10022);
    pushF(moveFirst);
    pushF(angle);
    pushF(power);
    Bytes frame;
    pushU32(std::uint32_t(body.size()));
    pushU32(std::uint32_t(body.size()));
    frame.push_back(0x40);
    frame.insert(frame.end(), body.begin(), body.end());
    return frame;
}

Bytes makeNativePlayFrame(std::uint32_t seed, const QString &nonce, const QString &suffix)
{
    return makeNativePlayFrameFlag(seed, nonce, suffix, false);
}

Bytes makeNativePlayFrameFlag(std::uint32_t seed, const QString &nonce, const QString &suffix, bool flag)
{
    return makeNativePlayFrameKeyed(seed, nonce, bytesOf(suffix), flag);
}

// FIX 2026-08-11 v26 (amigo: "op5 JOIN — re-encrypting OP53 under a fixed
// key"): el JOIN debe cifrar el op53 COMPLETO (el array AMF3 [53, token]),
// NO solo el string token. El bot cifraba solo el token (20 bytes) -> olen
// ~45 vs 51 del binario -> el server no reconocía el spawn -> la cuenta era
// OBSERVADOR (sesión estable pero 0 XP: el op24 EXPERIENCE_GAIN nunca
// llegaba). Ahora cifra el array [53, <token>] completo.
Bytes makeNativePlayFrameKeyed(std::uint32_t seed, const QString &nonce, const Bytes &key, bool flag)
{
    Bytes toEncrypt;
    if (nonce.size() >= 8 && nonce.left(8) == QStringLiteral("00000008")) {
        // nonce es el spawnToken del op53: cifrar el op53 COMPLETO [53, token]
        Bytes logical53 = amfArray({amfInt(53), amfString(nonce)});
        toEncrypt = logical53;
    } else {
        toEncrypt = bytesOf(nonce);
    }
    return makeNativePlayFrameKeyedRaw(seed, toEncrypt, key, flag);
}

// v28: JOIN que re-cifra el payload CRUDO del op53 (lo que el binario hace:
// 're-encrypting op53 under a fixed key'). El raw es el frame AMF3 completo
// [53, token] tal como llego del server, no un string reconstruido.
Bytes makeNativePlayFrameKeyedRaw(std::uint32_t seed, const Bytes &toEncrypt, const Bytes &key, bool flag)
{
    Bytes blob = m2xcEncryptFull(toEncrypt, key, 0, 0);
    QString challenge = m2xcFmt(blob);
    Bytes logical = amfArray({amfInt(5), amfArray({amfString(challenge), amfBool(flag)})});
    Bytes padded = logical;
    padded.push_back(0x00);
    int half = int(padded.size()) / 2;
    Bytes wire = m2xcTcpEnc(xorStep(interleave(padded, half, int(seed & 1)), seed), seed, 100);
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(wire.size()));
    pushU32(std::uint32_t(logical.size()));
    // checksum seed % 63 como el binario real (verificado en captura: los
    // frames del binario usan seed % 63, cambia cada 10 PINGs con el MT)
    frame.push_back(std::uint8_t(seed % 63));
    frame.insert(frame.end(), wire.begin(), wire.end());
    return frame;
}

QString decryptChallenge(const QString &challenge, const QString &suffix)
{
    QString c = challenge.trimmed();
    QString b64 = c;
    if (c.size() >= 8 && c.left(8).toLongLong() != 0) {
        bool allDigits = true;
        for (int i = 0; i < 8; ++i) {
            if (!c.at(i).isDigit()) { allDigits = false; break; }
        }
        if (allDigits)
            b64 = c.mid(8);
    }
    QString padded = b64;
    int pad = (4 - (padded.size() % 4)) % 4;
    padded += QString(pad, QLatin1Char('='));
    QByteArray raw = padded.toLatin1();
    QByteArray blobBytes = QByteArray::fromBase64(raw);
    Bytes blob(blobBytes.begin(), blobBytes.end());
    if (blob.size() < 4 || blob[0] != 'M' || blob[1] != '2' || blob[2] != 'X' || blob[3] != 'C')
        return {};
    Bytes dec = m2xcDecryptFull(blob, bytesOf(suffix));
    return QString::fromUtf8(reinterpret_cast<const char *>(dec.data()), int(dec.size()));
}

Bytes makeNativePlaySpawnFrame(std::uint32_t seed)
{
    // NATIVE_PLAY de SPAWN del juego (validado en wire real): [5, [false]]
    // payload = logical + 3 ceros, RESTURPLE con seed (no m2xc).
    Bytes logical = amfArray({amfInt(5), amfArray({amfBool(false)})});
    Bytes payload = logical;
    payload.push_back(0x00);
    payload.push_back(0x00);
    payload.push_back(0x00);
    return makeClientFrame(payload, int(logical.size()), std::uint8_t(seed % 63), seed);
}

Bytes makeEntityInfoFrame(std::uint32_t seed)
{
    // CLIENT_ENTITIES_INFO [10002, [0]] + 1 cero, resturple
    Bytes logical = amfArray({amfInt(10002), amfArray({amfInt(0)})});
    Bytes payload = logical;
    payload.push_back(0x00);
    return makeClientFrame(payload, int(logical.size()), std::uint8_t(seed % 63), seed);
}

Bytes makeConfirmUdpFrame(std::uint32_t seed)
{
    // CLIENT_CONFIRM_UDP [10033] + 1 cero, resturple
    Bytes logical = amfArray({amfInt(10033)});
    Bytes payload = logical;
    payload.push_back(0x00);
    return makeClientFrame(payload, int(logical.size()), std::uint8_t(seed % 63), seed);
}

Bytes makeIrcFrame(const QString &text)
{
    // Formato EXACTO del binario (verificado 5/5 frames en ctf_full.log.raw):
    //   logical = amfString(text)  (sin CRLF)
    //   pad     = (4 - len(logical) % 4) % 4  ceros hasta multiplo de 4
    //   payload = logical + zeros(pad)
    //   wire    = bytearrayResturple(payload, seed=0)
    //   frame   = [4B wlen=len(wire)] [4B olen=len(logical)] [1B chk=getByteKey(logical)&0x3F] [wire]
    // Casos verificados: "OPTIONS IRC" 16/13/5, "AUTH UserGate S :.." 64/62/27,
    // "AUTH UserGate GGID 0 S :.." 76/75/15, "USERSTATUS ONLINE" 20/19/63,
    // "PONG :talk003.mitos.is" 24/24/4.
    Bytes logical = amfString(text);
    int pad = (4 - (int(logical.size()) % 4)) % 4;
    Bytes payload = logical;
    payload.insert(payload.end(), size_t(pad), 0);
    Bytes wire = bytearrayResturple(payload, 0);
    std::int32_t chk = getByteKey(logical) & 0x3F;
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(wire.size()));
    pushU32(std::uint32_t(logical.size()));
    // checksum constante como el binario real (getByteKey & 0x3F)
    frame.push_back(std::uint8_t(getByteKey(logical) & 0x3F));
    frame.insert(frame.end(), wire.begin(), wire.end());
    return frame;
}

Bytes makeEquipmentDataFrame(std::uint32_t seed)
{
    // CLIENT_EQUIPMENT_DATA [10037, []] + 1 cero, resturple
    Bytes logical = amfArray({amfInt(10037), amfArray({})});
    Bytes payload = logical;
    payload.push_back(0x00);
    return makeClientFrame(payload, int(logical.size()), std::uint8_t(seed % 63), seed);
}

Bytes makeProofFrame(const QString &challenge, const QString &suffix, const QString &deviceId,
                     std::uint32_t seedMt, const QString &attestPem, QString *proofStrOut,
                     const QString &nonceOverride)
{
    // El challenge del op52 es un blob M2XC cifrado; el plaintext (8 chars)
    // es lo que se firma: SHA256(challenge_plaintext | deviceID | "100").
    // El roundtrip HTTP al engine da ese plaintext; sin el (timeout), el
    // decryptChallenge local produce el mismo resultado. v19 (firmar el crudo)
    // era INCORRECTO: revertido a descifrar.
    QString decrypted = nonceOverride.isEmpty()
        ? decryptChallenge(challenge, suffix)
        : nonceOverride;
    QByteArray msg = decrypted.toUtf8() + "|" + deviceId.toUtf8() + "|100";
    // El SECURE_PROOF se firma con la clave de atestacion del device (la fake
    // PEM generada localmente y registrada en el EH), no con la TPM real.
    Bytes sig = rsaSignPkcs1Sha256(attestPem, msg);
    QString proofStr = urlB64EncodeNoPad(sig);
    if (proofStrOut)
        *proofStrOut = proofStr;
    Bytes logical = amfArray({amfInt(10035), amfString(proofStr)});
    Bytes padded = logical;
    padded.push_back(0x00);
    int half = int(padded.size()) / 2;
    Bytes wire = m2xcTcpEnc(xorStep(interleave(padded, half, int(seedMt & 1)), seedMt), seedMt, 100);
    Bytes frame;
    auto pushU32 = [&](std::uint32_t v) {
        frame.push_back(std::uint8_t((v >> 24) & 0xFF));
        frame.push_back(std::uint8_t((v >> 16) & 0xFF));
        frame.push_back(std::uint8_t((v >> 8) & 0xFF));
        frame.push_back(std::uint8_t(v & 0xFF));
    };
    pushU32(std::uint32_t(wire.size()));
    pushU32(std::uint32_t(logical.size()));
    // FIX 2026-08-11 (cortes tras el PROOF): mismo bug que el PONG — el
    // binario real usa checksum constante (getByteKey & 0x3F), no seed % 63.
    // El server rechaza el PROOF con checksum invalido y corta el handshake.
    frame.push_back(std::uint8_t(seedMt % 63));
    frame.insert(frame.end(), wire.begin(), wire.end());
    return frame;
}

} // namespace tcp

// ================================================================
// FarmWorker
// ================================================================
// FIX 2026-08-11 v17: el tag del mmm debe ser CRECIENTE por cuenta aunque
// el FarmWorker se recree (spawnOneFarm crea un worker nuevo por ciclo).
// Mapa estatico deviceId -> tag (los 9 workers comparten el proceso).
// v17: el QHash sin mutex tenia data race (9 threads incrementando a la
// vez -> tags perdidos: 11-31 en 25 min en vez de ~140) -> el server veia
// tags bajos y cortaba a los 40-120s. Mutex para serializar el acceso.
static QHash<QString, int> s_mmmTags;
static QMutex s_mmmTagMutex;

int FarmWorker::mmmTagGet(const QString &deviceId)
{
    QMutexLocker locker(&s_mmmTagMutex);
    if (s_mmmTags.contains(deviceId)) {
        int tag = s_mmmTags.value(deviceId);
        if (tag >= 2)
            return tag;
    }
    // v18: PERSISTIR en QSettings entre procesos. Cada corrida nueva
    // arrancaba en 2 -> el server veia el tag RETROCEDER (la cuenta ya
    // habia llegado a 80+ en corridas anteriores) -> cortaba a los
    // 40-120s. El binario nunca retrocede (proceso longevo). Con el tag
    // persistido, la secuencia continua y TODAS las sesiones aguantan.
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    int tag = s.value(QStringLiteral("mmmTag_") + deviceId, 2).toInt();
    if (tag < 2)
        tag = 2;
    s_mmmTags[deviceId] = tag;
    return tag;
}

void FarmWorker::mmmTagSet(const QString &deviceId, int value)
{
    QMutexLocker locker(&s_mmmTagMutex);
    s_mmmTags[deviceId] = value;
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("mmmTag_") + deviceId, value);
    s.sync();
}

FarmWorker::FarmWorker(QObject *parent) : QObject(parent) {}
FarmWorker::~FarmWorker()
{
    // El QNAM se destruye en el hilo del worker (deleteLater tras finished).
    // Serializado: el dtor de QNAM toca el registro global de Qt Network.
    if (m_net) {
        QMutexLocker locker(&g_loginMutex);
        delete m_net;
        m_net = nullptr;
    }
}

void FarmWorker::configure(const QString &deviceId, const QString &pemPath, int gemItem)
{
    m_deviceId = deviceId;
    m_pemPath = pemPath;
    m_gemItem = gemItem;
}

void FarmWorker::stop()
{
    m_stop = true;
    // 2026-08-10 (bug reportado por el usuario: "al darle stop se cierra la
    // app"): abort() se llamaba DESDE EL HILO DE LA UI (stopFarm -> stop)
    // pero el QTcpSocket vive en el hilo del worker. abort() cross-thread
    // toca los QSocketNotifiers internos -> "QSocketNotifier: cannot be
    // enabled or disabled from another thread" + AV 0xC0000005 en
    // Qt6Network.dll (astro_crash.txt, familia de crashes al parar).
    // Fix: cerrar el DESCRIPTOR del socket a nivel de OS. shutdown() hace
    // que el waitForReadyRead pendiente del worker retorne al instante
    // (EOF/error) y es SEGURO desde otro hilo (no toca el objeto Qt).
    QMutexLocker lk(&m_socketMutex);
    if (m_activeSock) {
        const qintptr fd = m_activeSock->socketDescriptor();
        if (fd != -1) {
#ifdef Q_OS_WIN
            ::shutdown(SOCKET(fd), SD_BOTH);
#else
            ::shutdown(int(fd), SHUT_RDWR);
#endif
        }
    }
}

bool FarmWorker::recvFrame(QTcpSocket *sock, int timeoutMs, int *length, int *flag, Bytes *payload)
{
    // El QTcpSocket bufferiza internamente: waitForReadyRead solo avisa de datos
    // NUEVOS. Si el payload ya llego junto al header, leer bytesAvailable() primero.
    // Los dumps de entidades del FFA llegan con frames de hasta 64KB+ en trozos:
    // ante un timeout de waitForReadyRead se REINTENTA mientras el socket siga
    // conectado (hasta 4x timeoutMs). Si se rindiera a mitad de un frame, el
    // siguiente recvFrame leeria payload como header y desincronizaria el flujo.
    auto waitData = [&](int ms) {
        if (sock->bytesAvailable() > 0)
            return true;
        if (sock->waitForReadyRead(ms))
            return true;
        for (int retry = 0; retry < 3 && sock->state() == QAbstractSocket::ConnectedState; ++retry) {
            if (sock->waitForReadyRead(ms))
                return true;
        }
        return false;
    };
    QByteArray hdr;
    while (hdr.size() < 3) {
        if (sock->bytesAvailable() > 0) {
            hdr += sock->read(3 - hdr.size());
        } else if (!waitData(timeoutMs)) {
            return false;
        }
    }
    *length = (std::uint8_t(hdr.at(0)) << 8) | std::uint8_t(hdr.at(1));
    *flag = std::uint8_t(hdr.at(2));
    // sanity del length de 16 bits: un header corrupto con len<4 no puede ser
    // un frame AMF3 valido (los frames reales del server van bien por encima)
    // y desincronizaria el stream. Descartar -> el caller lo trata como frame
    // perdido y el watchdog/reconnect lo levanta.
    if (*length < 4 || *length > 65535) {
        qWarning("recvFrame: length %d invalido - descartando frame corrupto", *length);
        return false;
    }
    payload->clear();
    payload->reserve(*length);
    while (int(payload->size()) < *length) {
        if (sock->bytesAvailable() > 0) {
            QByteArray chunk = sock->read(*length - int(payload->size()));
            if (chunk.isEmpty())
                return false;
            for (char c : chunk)
                payload->push_back(std::uint8_t(c));
        } else if (!waitData(timeoutMs)) {
            return false;
        }
    }
    return true;
}

bool FarmWorker::sendFrame(QTcpSocket *sock, const Bytes &data)
{
    if (sock->state() != QAbstractSocket::ConnectedState)
        return false;
    qint64 written = sock->write(reinterpret_cast<const char *>(data.data()), qint64(data.size()));
    if (written != qint64(data.size()))
        return false;
    return sock->flush();
}

bool FarmWorker::decodeFrame(const Bytes &payload, std::uint32_t seed, tcp::AmfValue *out)
{
    size_t n = payload.size();
    if (n < 4 || n % 2 != 0)
        return false;
    size_t half = n / 2;
    // intento 1: m2xc path
    try {
        Bytes dec = tcp::m2xcTcpDec(payload, seed);
        dec = tcp::xorUnstep(dec, seed);
        dec = tcp::interleaveInv(dec, int(half), int(seed & 1));
        if (!dec.empty() && dec[0] <= 0x09) {
            tcp::Amf3Decoder d(dec);
            *out = d.readValue();
            if (d.ok())
                return true;
        }
    } catch (...) {}
    // intento 2: resturple (greeting/AUTH)
    try {
        Bytes dec = tcp::bytearrayDesturple(payload, seed);
        if (!dec.empty() && dec[0] <= 0x09) {
            tcp::Amf3Decoder d(dec);
            *out = d.readValue();
            if (d.ok())
                return true;
        }
    } catch (...) {}
    return false;
}

void FarmWorker::doLogin(QString *sk, QString *magic, QString *accountName, QByteArray *sessionCookies)
{
    // Serializado con g_loginMutex (ver login.cpp): las construcciones de
    // QJsonObject del KNOCK/LIM/EH crashean Qt 6.10.3 con varios hilos
    // (AV 0x1CE857/0x1CF461, NULL-base). Cubre las reconexiones del farm
    // cuando varias cuentas reintentan a la vez.
    QMutexLocker loginLocker(&g_loginMutex);
    QNetworkAccessManager net;
    Q_UNUSED(sessionCookies);
    // KNOCK
    QString q = makeQueryTcp({{"do", "knock"}, {"rndx", rndxTcp()}}, false);
    QJsonObject knock = parseJsonObj(httpGetTcp(&net, QUrl(kEngine + "?" + q)));
    QString token = knock.value("data").toObject().value("token").toString();
    if (token.isEmpty()) {
        *accountName = "KNOCK failed";
        return;
    }
    // LIM
    auto parts = stringDesturple(token);
    Bytes edidBlob = m2xcEncryptFull(bytesOf(m_deviceId), bytesOf(parts.first), 0xBC461A49, 0x7C2359AB);
    QString edid = m2xcFmt(edidBlob);
    QString chk = md5Hex("_chk91822" + m_deviceId + "l.o.x");
    // UN solo desktop por login: LIM (ddd) y EH (di) deben presentar la misma
    // maquina (el server puede exigir consistencia; ver analyze_de_issue.py).
    const QString desktop = randomDesktop();
    std::vector<QPair<QString, QString>> limParams = {
        {"rus", "1"}, {"loc", "es_CO"}, {"ver", kVersion}, {"dds", "1920x1080"},
        {"do", "lim"}, {"t", token}, {"ddd", desktop}, {"fmt", "tbt"},
        {"chk", chk}, {"did", edid}, {"rndx", rndxTcp()},
    };
    QJsonObject lim = parseJsonObj(httpGetTcp(&net, QUrl(kEngine + "?" + makeQueryTcp(limParams, false))));
    if (lim.value("result").toString() != "ok") {
        *accountName = "LIM failed: " + lim.value("message").toString();
        return;
    }
    QString dk = lim.value("data").toObject().value("dk").toString();
    QString dm = lim.value("data").toObject().value("dm").toString();
    QString dkKey = md5Hex(token + m_deviceId);
    QString dmKey = md5Hex(m_deviceId + token);
    Bytes skBlob = m2xcDecryptFull(parseM2xcBlob(dk), bytesOf(dkKey));
    Bytes rkBlob = m2xcDecryptFull(parseM2xcBlob(dm), bytesOf(dmKey));
    if (skBlob.empty() || rkBlob.empty()) {
        *accountName = "LIM sk/rk failed";
        return;
    }
    *sk = QString::fromUtf8(reinterpret_cast<const char *>(skBlob.data()), int(skBlob.size()));
    QString rsaPublicKey = QString::fromUtf8(reinterpret_cast<const char *>(rkBlob.data()), int(rkBlob.size()));
    // EH
    *magic = genMagic(64);
    QString dtf = buildDtf(*sk);
    QFile pf(m_pemPath);
    if (!pf.open(QIODevice::ReadOnly)) {
        *accountName = "no PEM";
        return;
    }
    QString attestPem = QString::fromUtf8(pf.readAll());
    pf.close();
    QByteArray chMsg = (dtf + "|" + m_deviceId + "|100").toUtf8();
    Bytes sig = rsaSignPkcs1Sha256(attestPem, chMsg);
    QString proof = urlB64EncodeNoPad(sig);
    QString mid = buildMidPem(attestPem);
    // evidencia TPM: cada cuenta debe presentar un mid DISTINTO (deriva de su
    // propia PEM fake del device). Si varias cuentas logean el mismo mid, la
    // atestacion esta compartida y el server limita las conexiones.
    emit debugLog(QString("TPM http device=%1 mid=%2 key=%3")
                      .arg(m_deviceId.left(16)).arg(mid.left(12)).arg(QFileInfo(m_pemPath).fileName()));
    QString ddJson = QString("{\"proof\":\"%1\",\"mid\":\"%2\",\"ver\":\"%3\",\"host\":\"app.mitos.is\"}")
                         .arg(proof, mid, kVersion);
    std::uint32_t R10 = std::uint32_t(std::uint64_t(QDateTime::currentMSecsSinceEpoch()) ^ std::uint64_t(QRandomGenerator::global()->generate()));
    std::uint32_t ddH2 = std::uint32_t(QRandomGenerator::global()->generate());
    Bytes ddBlob = m2xcEncryptFull(bytesOf(ddJson), bytesOf(*magic), R10, ddH2);
    QString dd = m2xcFmt(ddBlob);
    QString ms = rsaEncryptPkcs1Base64(rsaPublicKey, *magic);
    std::vector<QPair<QString, QString>> ehParams = {
        {"go", "0"}, {"dd", dd}, {"de", "desktop"}, {"gi", "0"},
        {"ver", kVersion}, {"it", "1"}, {"do", "eh"}, {"im", "0"},
        {"di", desktop}, {"dtf", dtf}, {"ms", ms}, {"rndx", rndxTcp()},
    };
    QByteArray eh = httpGetTcp(&net, QUrl(kEngine + "?" + makeQueryTcp(ehParams, true)));
    // Respuesta del EH: si es JSON valido se exige result=="ok" explicito
    // (contains("ok") aceptaria {"ok":false,...}); si es texto plano (las
    // capturas reales muestran mensajes URL-encoded del server, no JSON) se
    // conserva el check original que funciona contra el server real.
    QJsonObject ehObj = parseJsonObj(eh);
    const bool ehOk = ehObj.isEmpty()
        ? QString::fromUtf8(eh).contains("ok")
        : (ehObj.value("result").toString() == "ok");
    if (!ehOk) {
        *accountName = "EH failed";
        return;
    }
    // stats para el nombre
    QString statsUrl = kEngine + "?_sid=" + urlEncodeTcp(*sk, false) + "&rndx=" + rndxTcp();
    QString bodyJson = "{\"do\":\"stats\"}";
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(*magic), 0, 0);
    QByteArray stats = httpPostTcp(&net, QUrl(statsUrl), m2xcFmt(enc).toUtf8());
    QJsonObject statsObj = parseJsonObj(stats);
    QString name;
    QJsonArray data = statsObj.value("data").toArray();
    for (const auto &it : data) {
        if (it.isArray() && it.toArray().size() >= 2 && it.toArray().at(0).toString() == "previous_user") {
            name = it.toArray().at(1).toString();
            break;
        }
    }
    *accountName = name.isEmpty() ? "?" : name;
}

QJsonObject FarmWorker::httpApi(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload)
{
    // 2026-08-10 FINAL: HTTP FUERA del mutex global. Cada worker tiene su
    // propio QNetworkAccessManager (m_net, creado bajo lock una vez) y su
    // propio hilo — el HTTP entre cuentas corre EN PARALELO como el Python
    // validado (threads independientes, requests por thread). El g_loginMutex
    // queda SOLO para la construccion del QJsonObject (race de Qt 6.10.3,
    // crashes 0x1CF461/0x1C8A4E) y el parseo (g_jsonParseMutex). Serializar el
    // HTTP global era el bug: con 10 farms cada postSpawn esperaba la cola de
    // los otros 9 (test #27: 5 farming, peor que el skip del #26 con 9).
    QJsonDocument doc(payload);
    QString bodyJson = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    Bytes enc;
    QString url;
    {
        QMutexLocker loginLocker(&g_loginMutex);
        enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(magicc), 0, 0);
        url = kEngine + "?_sid=" + urlEncodeTcp(skk, false) + "&rndx=" + rndxTcp();
    }
    emit debugLog(QString("%1 HTTP >> %2").arg(m_deviceId.left(10)).arg(bodyJson));
    writeWorkerLog(QString("%1 HTTP >> %2").arg(m_deviceId.left(10)).arg(bodyJson.left(80)));
    QByteArray resp = httpPostTcp(net, QUrl(url), m2xcFmt(enc).toUtf8(), &m_stop);
    QString t = QString::fromUtf8(resp);
    QJsonObject parsed;
    if (!t.startsWith("tBB,")) {
        parsed = parseJsonObj(resp);
    } else {
        QString b64 = t.mid(12);
        QString padded = b64;
        int pad = (4 - (padded.size() % 4)) % 4;
        padded += QString(pad, QLatin1Char('='));
        QByteArray blobBytes = QByteArray::fromBase64(padded.toLatin1());
        Bytes blob(blobBytes.begin(), blobBytes.end());
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(magicc));
            parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
        } else {
            // loginifneeded va con deriveCustomAesKey(magic,100); otras
            // respuestas v5oh2 con deriveAesKey(magic). Probar ambas.
            Bytes dec = aesCbcCrypt(blob, deriveCustomAesKey(magicc, 100), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
            if (!parsed.contains(QStringLiteral("data"))) {
                dec = aesCbcCrypt(blob, deriveAesKey(magicc), false);
                while (!dec.empty() && dec.back() == 0)
                    dec.pop_back();
                parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
            }
        }
    }
    QString respJson = QString::fromUtf8(QJsonDocument(parsed).toJson(QJsonDocument::Compact));
    emit debugLog(QString("%1 HTTP << %2").arg(m_deviceId.left(10)).arg(respJson.left(300)));
    return parsed;
}

// Best-effort para el postSpawn/respawn (ver header): si el mutex global esta
// ocupado (otros farms en HTTP), salta en 350ms en vez de esperar 5-14s sin
// PONGs. Devuelve vacio al saltar — los NATIVE_PLAY se mandan igual.
// 2026-08-10 v2: el HTTP interno tambien tenia timeout de 8s — con el server
// saturado (10 farms) cada play HTTP tardaba 5-13s y el postSpawn excedia los
// ~12s del [20] (DeRene: SPAWNED 10:03:09 -> lost 10:03:21 sin Farming).
// httpPostTcp acepta un timeout: usar 1500ms aqui (el NATIVE_PLAY es lo que
// el server espera; el play HTTP es secundario, usa randomNonce no el token).
QJsonObject FarmWorker::httpApiFast(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload)
{
    if (!g_loginMutex.tryLock(350)) {
        emit debugLog(QString("%1 HTTP SKIP (mutex ocupado, postSpawn rapido)").arg(m_deviceId.left(10)));
        return QJsonObject();
    }
    QJsonObject r = httpApiLockedTmo(net, skk, magicc, payload, 1500);
    g_loginMutex.unlock();
    return r;
}

// Cuerpo del httpApi SIN lock (el caller decide el lock). Ver httpApi().
QJsonObject FarmWorker::httpApiLocked(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload)
{
    return httpApiLockedTmo(net, skk, magicc, payload, 8000);
}

// Cuerpo con timeout configurable (el postSpawn usa 1500ms; el resto 8000ms).
QJsonObject FarmWorker::httpApiLockedTmo(QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload, int timeoutMs)
{
    QJsonDocument doc(payload);
    QString bodyJson = QString::fromUtf8(doc.toJson(QJsonDocument::Compact));
    emit debugLog(QString("%1 HTTP >> %2").arg(m_deviceId.left(10)).arg(bodyJson));
    writeWorkerLog(QString("%1 HTTP >> %2").arg(m_deviceId.left(10)).arg(bodyJson.left(80)));
    Bytes enc = m2xcEncryptFull(bytesOf(bodyJson), bytesOf(magicc), 0, 0);
    QString url = kEngine + "?_sid=" + urlEncodeTcp(skk, false) + "&rndx=" + rndxTcp();
    QByteArray resp = httpPostTcp(net, QUrl(url), m2xcFmt(enc).toUtf8(), &m_stop, timeoutMs);
    QString t = QString::fromUtf8(resp);
    QJsonObject parsed;
    if (!t.startsWith("tBB,")) {
        parsed = parseJsonObj(resp);
    } else {
        QString b64 = t.mid(12);
        QString padded = b64;
        int pad = (4 - (padded.size() % 4)) % 4;
        padded += QString(pad, QLatin1Char('='));
        QByteArray blobBytes = QByteArray::fromBase64(padded.toLatin1());
        Bytes blob(blobBytes.begin(), blobBytes.end());
        if (blob.size() >= 4 && blob[0] == 'M' && blob[1] == '2' && blob[2] == 'X' && blob[3] == 'C') {
            Bytes dec = m2xcDecryptFull(blob, bytesOf(magicc));
            parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
        } else {
            // loginifneeded va con deriveCustomAesKey(magic,100); otras
            // respuestas v5oh2 con deriveAesKey(magic). Probar ambas.
            Bytes dec = aesCbcCrypt(blob, deriveCustomAesKey(magicc, 100), false);
            while (!dec.empty() && dec.back() == 0)
                dec.pop_back();
            parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
            if (!parsed.contains(QStringLiteral("data"))) {
                dec = aesCbcCrypt(blob, deriveAesKey(magicc), false);
                while (!dec.empty() && dec.back() == 0)
                    dec.pop_back();
                parsed = parseJsonObj(QByteArray(reinterpret_cast<const char *>(dec.data()), int(dec.size())));
            }
        }
    }
    QString respJson = QString::fromUtf8(QJsonDocument(parsed).toJson(QJsonDocument::Compact));
    emit debugLog(QString("%1 HTTP << %2").arg(m_deviceId.left(10)).arg(respJson.left(300)));
    return parsed;
}

void FarmWorker::emitLog(const QString &text)
{
    // 2026-08-10: escribir el log DIRECTAMENTE desde el hilo del worker. El
    // path viejo (stateChanged -> cola del hilo principal -> appendLog) se
    // saturaba con 10 farms logueando: el archivo salia con 10-20s de retraso
    // y los tiempos reales de los eventos eran ilegibles (los "Farming CTF"
    // salian 11s despues del postSpawn real). El archivo se escribe aqui con
    // su mutex; las signals siguen para la UI pero el archivo ya no depende
    // de la cola del hilo principal.
    writeWorkerLog(text);
    // los mensajes que empiezan con un prefijo tecnico van a debugLog;
    // el resto (estados legibles del farm) va a stateChanged
    static const QStringList techPrefixes = {
        QStringLiteral("op "), QStringLiteral("UNDEC"), QStringLiteral("GREETING raw"),
        QStringLiteral("Suffix:"), QStringLiteral("chattoken:"), QStringLiteral("uid="),
        QStringLiteral("LISTENER"), QStringLiteral("updateexp:"), QStringLiteral("PLAYER_ID"),
        QStringLiteral("Desafio"), QStringLiteral("Challenge"), QStringLiteral("PROOF"),
        QStringLiteral("READY"), QStringLiteral("Resume key"), QStringLiteral("NATIVE_PLAY"),
        QStringLiteral("IRC PONG"), QStringLiteral("IRC sin"),
        QStringLiteral("seed"), QStringLiteral("frames"), QStringLiteral("RAW"),
        QStringLiteral("CHALLENGE"),
    };
    for (const QString &p : techPrefixes) {
        if (text.startsWith(p)) {
            emit debugLog(text);
            return;
        }
    }
    emit stateChanged(text);
}

// Escritura directa al archivo desde el hilo del worker (ver emitLog).
void FarmWorker::writeWorkerLog(const QString &line)
{
    static QMutex s_logMutex;
    QMutexLocker locker(&s_logMutex);
    QFile f(QCoreApplication::applicationDirPath() + "/astro_farm.log");
    if (!f.open(QIODevice::Append | QIODevice::Text))
        return;
    f.write("[" + QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")).toUtf8() + "] ");
    f.write(line.toUtf8());
    f.write("\n");
    f.close();
}

int FarmWorker::gemCurrent(const QJsonObject &invResp) const
{
    // El inventory(slot=N) NO es un slot de equipamiento: el parametro "slot"
    // es la CATEGORIA. El inventory(slot=5) lista TODAS las gemas de la cuenta
    // (category 10) y el item ACTIVO (equipado) de la categoria es data.current
    // (-1 = ninguna equipada). El item equipado puede NO estar en la lista items.
    const QJsonObject data = invResp.value("data").toObject();
    if (data.contains("current"))
        return data.value("current").toInt(-1);
    // sin "current": buscar un item con campo "equipped" en la lista
    const QJsonArray items = data.value("items").toArray();
    for (const auto &iv : items) {
        const QJsonObject it = iv.toObject();
        if (it.contains("equipped") && it.value("equipped").toBool())
            return it.value("id").toInt(-1);
    }
    return -1;
}

bool FarmWorker::gemEquipped(const QJsonObject &invResp) const
{
    return gemCurrent(invResp) == m_gemItem;
}

// cexp/exp de inventory(slot=5) pueden venir como numero o como null (gema sin
// XP visible): null -> -1 (invalido), nunca 0 (0 confundiria con XP real 0).
static qlonglong jsonGemXp(const QJsonValue &v)
{
    if (v.isNull() || v.isUndefined())
        return -1;
    if (v.isDouble())
        return qlonglong(v.toDouble());
    if (v.isString()) {
        bool ok = false;
        const qlonglong r = v.toString().toLongLong(&ok);
        return ok ? r : -1;
    }
    return -1;
}

// La gema actual esta ROTA (durability 0) y el repair fallo: cambiar a la
// siguiente gema de la prioridad que exista en el inventario con durabilidad.
// m_gemItem se actualiza; el proximo pre-connect/equip la equipara.
void FarmWorker::switchToNextGem(QNetworkAccessManager *net, const QString &sk,
                                 const QString &magic, const QJsonArray &items)
{
    if (m_gemPriorityList.isEmpty())
        return;
    // ids disponibles del inventario (con durabilidad > 0)
    QSet<int> available;
    for (const auto &iv : items) {
        const QJsonObject item = iv.toObject();
        if (item.value("durability").toInt() > 0)
            available.insert(item.value("id").toInt());
    }
    // recorrer la prioridad desde la posicion de la gema actual
    int curPos = m_gemPriorityList.indexOf(m_gemItem);
    for (int step = 1; step <= m_gemPriorityList.size(); ++step) {
        const int idx = (curPos + step) % m_gemPriorityList.size();
        const int candidate = m_gemPriorityList.at(idx);
        if (!available.contains(candidate))
            continue;
        m_gemItem = candidate;
        m_gemExpInicial = -1; // reiniciar baseline del refresh
        m_gemCexpInicial = -1;
        emitLog(QString("Gem %1 ROTA - cambiando a la siguiente prioridad: gem %2")
                    .arg(curPos >= 0 ? QString::number(curPos) : QStringLiteral("?"))
                    .arg(candidate));
        // equipar la nueva gema ya (para no esperar al proximo spawn)
        try {
            QJsonObject er = httpApi(net, sk, magic, apiJson({ {"do", "equip"}, {"item", candidate}, {"slot", 5} }));
            if (er.value("result").toString() == QLatin1String("ok")) {
                m_gemEquipped = false; // el siguiente postSpawn la verifica/equipa
                emit debugLog(QString("Equip nueva gema %1 tras rotura").arg(candidate));
            }
        } catch (...) {}
        return;
    }
    emitLog(QString("Gem %1 ROTA y no hay otra gema disponible en la prioridad").arg(m_gemItem));
}

bool FarmWorker::readGemXp(const QJsonObject &invResp, qlonglong *cexpOut, qlonglong *expOut)
{
    const QJsonObject data = invResp.value("data").toObject();
    const QJsonArray items = data.value("items").toArray();
    int activeId = data.contains("current") ? data.value("current").toInt(-1) : -1;
    int fallbackId = -1;
    for (const auto &iv : items) {
        QJsonObject it = iv.toObject();
        int id = it.value("id").toInt(-1);
        // DEBUG v29: loguear el JSON completo del item para encontrar el
        // campo del XP acumulado (el cexp/exp son del nivel, estaticos).
        if (id == m_gemItem || id == activeId) {
            emitLog(QString("GEM ITEM RAW (id=%1): %2")
                        .arg(id)
                        .arg(QString::fromUtf8(QJsonDocument(it).toJson(QJsonDocument::Compact)).left(300)));
        }
        if (id == m_gemItem) {
            if (cexpOut) *cexpOut = jsonGemXp(it.value("cexp"));
            if (expOut) *expOut = jsonGemXp(it.value("exp"));
            emit debugLog(QString("Refresh item: gem %1 (m_gemItem lookup) cexp=%2 exp=%3")
                              .arg(id).arg(cexpOut ? *cexpOut : -1).arg(expOut ? *expOut : -1));
            return true;
        }
        if (fallbackId < 0 && activeId >= 0 && id == activeId)
            fallbackId = id;
    }
    // la gema elegida no aparece en la lista de items: usar el item activo
    for (const auto &iv : items) {
        QJsonObject it = iv.toObject();
        if (it.value("id").toInt(-1) == fallbackId) {
            if (cexpOut) *cexpOut = jsonGemXp(it.value("cexp"));
            if (expOut) *expOut = jsonGemXp(it.value("exp"));
            emit debugLog(QString("Refresh item: gem %1 (current fallback) cexp=%2 exp=%3")
                              .arg(fallbackId).arg(cexpOut ? *cexpOut : -1).arg(expOut ? *expOut : -1));
            return true;
        }
    }
    emit debugLog(QString("Refresh item: gem %1 NOT found in inventory (current=%2, items=%3)")
                      .arg(m_gemItem).arg(activeId).arg(int(items.size())));
    return false;
}

// FIX 2026-08-11 v24 (Jo/Ren: "manda todas las accs al MISMO server y rapido
// no habra bots"): TODAS las cuentas deben ir al MISMO servidor/region. Si
// van a servers random y se tardan, caen en partidas CON BOTS que terminan
// en ~30s -> el server corta el TCP al terminar la partida (normal, confirmado
// por Jo). Con todas al mismo server y rapidas, la partida se llena con las
// cuentas del farm (sin bots) y dura mas. Region GLOBAL compartida: la
// primera cuenta elige y las demas la usan.
static QString s_globalRegion;
static QMutex s_globalRegionMutex;

void FarmWorker::pickRandomRegion()
{
    // FIX 2026-08-11 v24 (Jo/Ren): TODAS las cuentas al MISMO server, en una
    // region BUENA. La primera vez la eleccion random cayo en australia (ping
    // alto). Fijada a europe (la region del farm, servidores cercanos).
    QMutexLocker lk(&s_globalRegionMutex);
    if (s_globalRegion.isEmpty()) {
        s_globalRegion = QStringLiteral("europe");
        emitLog("Region global fijada: europe (todas las cuentas al mismo server)");
    }
    { QMutexLocker lk2(&m_sessionMutex); m_region = s_globalRegion; }
}

void FarmWorker::restoreCtfMode(QNetworkAccessManager *net, const QString &sk, const QString &magic, const QString &avoidRegion)
{
    // vuelve a dejar la cuenta en CTF (lobby via HTTP, sin TCP). Al volver se
    // CAMBIA DE SERVIDOR: elige una region random distinta de avoidRegion (la del
    // FFA) para que el proximo spawn use un server nuevo, con i18n + connect gm=-1
    // igual que el binario (servers change -> i18n -> connect, captura servers_cap.log)
    QStringList candidates;
    for (const QString &r : kFarmRegions) {
        if (r != avoidRegion)
            candidates << r;
    }
    if (candidates.isEmpty())
        candidates = kFarmRegions;
    {
        QMutexLocker lk(&m_sessionMutex);
        m_region = candidates.at(QRandomGenerator::global()->bounded(int(candidates.size())));
    }
    emit regionChanged(m_region);
    QJsonObject conn;
    try {
        httpApi(net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 3}}));
        httpApi(net, sk, magic, apiJson({{"do", "servers"}, {"change", m_region}}));
        httpApi(net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
        int ci;
        { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci = m_connectIndex; }
        conn = httpApi(net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                  {"i", ci}, {"gm", -1}, {"retrying", false}, {"locale", "es_CO"}}));
        emit debugLog(QString("restore CTF: gamemode mode=3 + servers change %1 + i18n + connect i=%2 gm=-1")
                          .arg(m_region).arg(ci));
    } catch (...) {}
    emit accountState("CTF", m_region);
    m_ctfConnect = conn; // server/token para el spawn TCP final del refresh
}

void FarmWorker::backToCtfSameRegion(QNetworkAccessManager *net, const QString &sk, const QString &magic)
{
    // vuelve a CTF SIN cambiar de servidor: la region del farm activo se
    // conserva (sin servers change) para que el TCP del farm y su reconexion
    // sigan en el mismo server. Orden identico a restoreCtfMode: gamemode ->
    // i18n -> connect gm=-1.
    QJsonObject conn;
    try {
        httpApi(net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 3}}));
        httpApi(net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
        int ci2;
        { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci2 = m_connectIndex; }
        conn = httpApi(net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                  {"i", ci2}, {"gm", -1}, {"retrying", false}, {"locale", "es_CO"}}));
        emit debugLog(QString("restore CTF (misma region %1): gamemode mode=3 + i18n + connect i=%2 gm=-1")
                          .arg(m_region).arg(ci2));
    } catch (...) {}
    emit accountState("CTF", m_region);
    m_ctfConnect = conn; // server/token para el spawn TCP final del refresh
}

QString FarmWorker::drainIrc(QTcpSocket *ircSock, QByteArray *ircBuf)
{
    // Tope por llamada: un flood del chat (o un ircBuf acumulado gigante) no
    // debe estrella el hilo del farm parseando sin fin. 4096 bytes o 512
    // lineas por llamada; el resto queda en ircBuf para la siguiente llamada.
    const int kMaxIrcBytes = 4096;
    const int kMaxIrcLines = 512;
    QString lines;
    int readBytes = 0;   // bytes leidos del socket en esta llamada
    int consumed = 0;    // bytes de frames ya parseados
    int lineCount = 0;
    while (readBytes + consumed < kMaxIrcBytes) {
        // header del server IRC: [4B len][1B flag][payload desturpled(seed=0)]
        // Parsear el buffer ANTES de leer del socket: un frame completo
        // acumulado de una llamada anterior (tope alcanzado) debe procesarse
        // ya, aunque no lleguen bytes nuevos (PINGs del IRC incluidos).
        while (ircBuf->size() >= 5 && consumed < kMaxIrcBytes && lineCount < kMaxIrcLines) {
            int ilen = (std::uint8_t(ircBuf->at(0)) << 24) | (std::uint8_t(ircBuf->at(1)) << 16)
                     | (std::uint8_t(ircBuf->at(2)) << 8) | std::uint8_t(ircBuf->at(3));
            int iflag = std::uint8_t(ircBuf->at(4));
            if (ilen == 0) {
                ircBuf->remove(0, 5);
                consumed += 5;
                continue;
            }
            if (ircBuf->size() < 5 + ilen)
                break;
            QByteArray payload = ircBuf->mid(5, ilen);
            ircBuf->remove(0, 5 + ilen);
            consumed += 5 + ilen;
            Bytes p(payload.begin(), payload.end());
            tcp::AmfValue v;
            bool ok = false;
            if (iflag == 1 && !p.empty() && p[0] <= 0x09) {
                tcp::Amf3Decoder d(p);
                v = d.readValue();
                ok = d.ok();
            } else {
                Bytes dec = tcp::bytearrayDesturple(p, 0);
                if (!dec.empty() && dec[0] == 0x06) {
                    tcp::Amf3Decoder d(dec);
                    v = d.readValue();
                    ok = d.ok();
                }
            }
            if (ok && v.type == tcp::AmfValue::Str) {
                lines += v.s + "\n";
                ++lineCount;
            }
        }
        if (ircSock->bytesAvailable() == 0)
            break;
        QByteArray chunk = ircSock->readAll();
        if (chunk.isEmpty())
            break;
        readBytes += chunk.size();
        *ircBuf += chunk;
    }
    return lines;
}

bool FarmWorker::spawnSession(QTcpSocket *sock, QNetworkAccessManager *net,
                              const QString &sk, const QString &magic,
                              QString host, int port, QString token,
                              const QString &invite,
                              const QString &uid, const QString &ctToken,
                              int mode, QString *err, FarmState *state,
                              QTcpSocket *ircSock, QByteArray *ircBuf,
                              bool doUdpInit,
                              std::function<void(QString&, int&, QString&)> refreshServer)
{
    // SPAWN SERIALIZADO con g_spawnMutex (verificado 2026-08-08 v3): el
    // arranque en paralelo fue posible cuando los crashes rdi=9 eran SOLO los
    // QNAM ctor (ahora lazy bajo lock), pero el SEH de la familia 0x1CE857
    // reaparecio (rdi=7) cuando N farms reconectan a la vez tras los kicks
    // del refresh (2 flujos completos + 7 farms) y cuando los workers se
    // destruyen en el shutdown: spawnSession crea QJsonObject/QStringList/
    // QElapsedTimer/QTcpSocket y hace AUTH+LISTENER+challenge HTTP — fases
    // con objetos Qt fuera de los locks de hash/parse. Serializar el spawn
    // completo elimina la ventana (el handshake tarda ~2-5s por cuenta;
    // aceptable frente a un AV). El resto del loop del farm (PING/PONG,
    // frames M2XC) sigue en paralelo.
    // 2026-08-10 (queja del usuario "muchos errores TCP"): el connectToHost
    // estaba FUERA del lock en run() — 10 sockets conectaban a la vez y 9
    // quedaban abiertos esperando su turno de handshake; el server cortaba
    // esas conexiones inactivas ("TCP disconnected during handshake").
    // Ahora el connect + UDP init viven DENTRO del lock: el server ve 1
    // conexion de la IP a la vez, como el binario con una sola cuenta.
    QMutexLocker spawnLocker(&g_spawnMutex);
    if (sock->state() != QAbstractSocket::ConnectedState) {
        sock->connectToHost(resolveHostMutexed(host), port);
        const qint64 connT0 = QDateTime::currentMSecsSinceEpoch();
        // 2026-08-10 (test #44): timeout 7s. El server saturado a veces
        // acepta el SYN a los 5-6s; 4s dejaba "Operacion socket expirada"
        // en las mismas 4 cuentas en cada intento (Andy/Anisa/DeRene/Meet).
        // Con el lock serializado el costo de esperar 7s es solo para la
        // cuenta en turno, no para las demas (esperan el mutex).
        while (!sock->waitForConnected(200) && !m_stop && !aborted()
               && QDateTime::currentMSecsSinceEpoch() - connT0 < 7000) {}
        if (m_stop || aborted()) {
            if (err) *err = "aborted during TCP connect";
            return false;
        }
        if (sock->state() != QAbstractSocket::ConnectedState) {
            if (err) *err = "TCP connect failed: " + sock->errorString();
            return false;
        }
        sock->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        emit stateChanged("TCP connected " + host + ":" + QString::number(port));
        if (doUdpInit) {
            // FIX 2026-08-11 (captura frida_v3 del binario REAL en partida):
            // el cliente real NO envia NINGUN datagrama UDP (0 eventos en la
            // captura con hook de sendto/recvfrom activo). El UDP INIT de aqui
            // (headless_bot.py, no del binario) era trafico anomalo que el
            // server podia detectar y cortar. Desactivado: solo TCP + HTTP.
            emitLog("UDP INIT omitido (el binario real no envia UDP)");
        }
    }
    // greeting -> suffix (seed=0). El flujo exacto del run(): el greeting trae el
    // suffix numerico que seedea el MT de los encoding seeds.
    {
        QElapsedTimer guard; guard.start();
        while (state->suffix.isEmpty() && guard.elapsed() < m_greetingTimeoutMs && !m_stop && !aborted()) {
            int len = 0, flag = 0;
            Bytes payload;
            if (!recvFrame(sock, 2000, &len, &flag, &payload))
                continue;
            emitLog(QString("GREETING raw: len=%1 flag=%2 bytes=%3")
                                  .arg(len).arg(flag)
                                  .arg(QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(payload.data()), int(payload.size())).toHex().left(40))));
            tcp::AmfValue v;
            if (!decodeFrame(payload, 0, &v))
                continue;
            if (v.type == tcp::AmfValue::Str && v.s.size() >= 8 && v.s.left(8).toLongLong() != 0) {
                bool allDigits = true;
                for (int i = 0; i < 8; ++i) {
                    if (!v.s.at(i).isDigit()) { allDigits = false; break; }
                }
                if (allDigits) {
                    state->suffix = v.s.mid(v.s.size() - 8);
                    state->mt = std::make_unique<tcp::MersenneTwister>(tcp::getStrKey(state->suffix));
                    state->seed = 0;
                    emitLog("Suffix: " + state->suffix);
                }
            }
        }
    }
    if (state->suffix.isEmpty()) {
        if (err) *err = "No greeting";
        return false;
    }
    // AUTH M2XC (ext:495 + mode) + HTTP del AUTH, igual que el run()
    QString authBody;
    Bytes authFrame = tcp::makeAuthFrame(host, state->suffix, token, mode, invite, &authBody);
    {
        // Lock: los 9 farms envian su AUTH HTTP a la vez (QNetworkRequest con
        // QHash interno de headers = race de Qt 6.10.3)
        QMutexLocker locker(&g_loginMutex);
        QString u = kEngine + "?_sid=" + urlEncodeTcp(sk, false) + "&rndx=" + rndxTcp();
        httpPostTcp(net, QUrl(u), authBody.toUtf8());
    }
    emit debugLog("TCP >> AUTH M2XC (wlen=156 olen=155)");
    sendFrame(sock, authFrame);
    emit stateChanged("AUTH sent" + (invite.isEmpty() ? QString() : " (invite)"));
    // Socket IRC del chat (talk003.mitos.is) en socket SEPARADO, como el binario.
    // Handshake SECUENCIAL: cada comando espera su respuesta antes del siguiente.
    // Host resuelto a IP bajo mutex: el connectToHost con nombre dispara el DNS
    // manager de Qt (QHash internos) — race con los 9 farms spawneando a la vez.
    ircSock->connectToHost(resolveHostMutexed(QStringLiteral("talk003.mitos.is")), 443);
    auto waitIrcFor = [&](const QStringList &needles, int timeoutMs, QString *gotOut) -> bool {
        QElapsedTimer timer; timer.start();
        QString acc;
        while (timer.elapsed() < timeoutMs) {
            acc += drainIrc(ircSock, ircBuf);
            for (const QString &n : needles) {
                if (acc.contains(n)) {
                    if (gotOut) *gotOut = acc;
                    return true;
                }
            }
            if (ircSock->state() != QAbstractSocket::ConnectedState)
                return false;
            ircSock->waitForReadyRead(100);
        }
        return false;
    };
    if (ircSock->waitForConnected(4000)) {
        // charset del binario en los tokens AUTH (captura): solo [A-Za-z0-9;_-]
        static const char *ircChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789;_-";
        auto random48 = [&]() {
            QString out;
            for (int i = 0; i < 48; ++i)
                out += QChar(ircChars[QRandomGenerator::global()->bounded(int(std::strlen(ircChars)))]);
            return out;
        };
        auto sendIrc = [&](const QString &text) {
            Bytes f = tcp::makeIrcFrame(text);
            ircSock->write(reinterpret_cast<const char *>(f.data()), qint64(f.size()));
            ircSock->flush();
        };
        auto ircDiag = [&]() {
            return QString("state=%1 peer=%2 avail=%3 buf=%4")
                .arg(int(ircSock->state()))
                .arg(ircSock->peerAddress().toString())
                .arg(ircSock->bytesAvailable())
                .arg(QString::fromLatin1(ircBuf->toHex().left(80)));
        };
        QString got;
        sendIrc("OPTIONS IRC");
        if (!waitIrcFor({"AUTH RandomGate", "801 "}, 4000, &got))
            emitLog("IRC sin RandomGate: " + got.left(60).replace('\n', ' ') + " | " + ircDiag());
        sendIrc("AUTH UserGate S :" + random48());
        if (!waitIrcFor({"AUTH UserGate S :OK"}, 6000, &got))
            emitLog("IRC sin OK S: " + got.left(60).replace('\n', ' ') + " | " + ircDiag());
        // el GGID usa el token REAL del chattoken HTTP (como el binario)
        QString ggidToken = ctToken.isEmpty() ? random48() : ctToken;
        sendIrc("AUTH UserGate GGID 0 S :" + ggidToken);
        if (!waitIrcFor({"001 "}, 6000, &got))
            emitLog("IRC sin 001: " + got.left(60).replace('\n', ' ') + " | " + ircDiag());
        sendIrc("USERSTATUS ONLINE");
        emit stateChanged("IRC chat connected (talk003)");
    } else {
        emit stateChanged("IRC chat unavailable: " + ircSock->errorString());
    }
    // LISTENER (v5oh2) - el binario lo envia por HTTP junto al AUTH, ANTES de leer frames
    {
        // Resolucion del host serializada (QHostInfo internos = race de Qt)
        QString serverIp = resolveHostMutexed(host);
        QJsonArray arr;
        arr.append("0.0.1");
        arr.append(65535);
        arr.append(false);
        arr.append(495);
        arr.append(3724);
        arr.append(QRandomGenerator::global()->bounded(65536));
        QString nonce8;
        static const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (int i = 0; i < 8; ++i)
            nonce8 += QChar(chars[QRandomGenerator::global()->bounded(int(std::strlen(chars)))]);
        arr.append(nonce8);
        arr.append(36);
        arr.append(serverIp);
        QByteArray plain = QJsonDocument(arr).toJson(QJsonDocument::Compact);
        Bytes padded(bytesOf(plain));
        int pad = (16 - (int(padded.size()) % 16)) % 16;
        padded.insert(padded.end(), size_t(pad), 0);
        Bytes key = deriveAesKey(state->suffix);
        Bytes ct = aesCbcCrypt(padded, key, true);
        QString body = QString("%1%2").arg(int(plain.size()), 8, 10, QLatin1Char('0')) + b64Encode(ct);
        QByteArray lst;
        {
            QMutexLocker locker(&g_loginMutex); // QNetworkRequest internos (ver AUTH)
            QString u = kEngine + "?_sid=" + urlEncodeTcp(sk, false) + "&rndx=" + rndxTcp();
            lst = httpPostTcp(net, QUrl(u), body.toUtf8());
        }
        emitLog("LISTENER enviado: " + QString::fromUtf8(lst).left(60));
    }
    // mmm del listener con tag CRECIENTE del contador persistente (v18:
    // TODOS los mmm deben incrementar el tag global; tag=1 fijo aqui dejaba
    // el contador estancado y el server cortaba por tag bajo).
    if (!uid.isEmpty()) {
        try {
            int tag = mmmTagGet(m_deviceId);
            httpApi(net, sk, magic, apiJson({{"do", "mmm"}, {"begin", false}, {"serching", false},
                                                 {"add", QString("[%1,\"\",100,0]").arg(uid)}, {"tag", tag},
                                                 {"abandon", false}, {"mode", -1}, {"stop", false}}));
            mmmTagSet(m_deviceId, tag + 1);
            emitLog("mmm listener tag=" + QString::number(tag));
        } catch (...) {}
    }
    // handshake: [4] PLAYER_ID -> [52] SECURE_CHALLENGE -> PROOF TPM -> [53] ->
    // inventory(ingame,slot=3) HTTP + READY -> [40] RESUME_KEY -> [20] SPAWNED.
    // El PONG usa el ts del PING del server; el seed avanza cada 10 PINGs.
    bool readySent = false;
    bool nativeSent = false;
    QElapsedTimer readyT0; // 2026-08-10: timeout del [20] tras el READY (15s)
    QSet<int> seenOps;
    int totalFrames = 0;
    QElapsedTimer t0; t0.start();
    // Los PINGs del server (IRC y TCP) se responden SIEMPRE, tambien durante la
    // espera del READY: el QThread::msleep(1500) bloqueante tras el [53] dejaba
    // los PINGs sin responder y el server cortaba el handshake (spawn FFA en el
    // intento 1). La espera activa (waitProcess) lee frames y responde PONGs.
    std::function<bool(int)> waitProcess;
    auto processIrc = [&]() {
        if (ircSock->state() == QAbstractSocket::ConnectedState) {
            QString ircLines = drainIrc(ircSock, ircBuf);
            if (!ircLines.isEmpty()) {
                QStringList lines = ircLines.split('\n', Qt::SkipEmptyParts);
                for (const QString &line : lines) {
                    if (line.startsWith("PING")) {
                        QString target = line.mid(5).trimmed();
                        Bytes pong = tcp::makeIrcFrame("PONG " + target);
                        ircSock->write(reinterpret_cast<const char *>(pong.data()), qint64(pong.size()));
                        ircSock->flush();
                        emitLog("IRC PONG -> " + target);
                    }
                }
            }
        }
    };
    // procesa un frame del socket del juego: opcodes del handshake, PING->PONG
    // con el ts del server y seed cada 10 PINGs. Devuelve true si llego el [20].
    auto processFrame = [&](int len, int flag, const Bytes &payload) -> bool {
        tcp::AmfValue v;
        bool decoded = false;
        // los opcodes del handshake (52/53/40/20) llegan con flag=1 y AMF3 plano
        if (flag == 1 && !payload.empty() && payload[0] <= 0x09) {
            tcp::Amf3Decoder d(payload);
            v = d.readValue();
            decoded = d.ok();
        } else if (flag != 1) {
            decoded = decodeFrame(payload, state->seed, &v);
            if (!decoded && state->mt) {
                std::uint32_t savedMt[624];
                int savedIdx;
                state->mt->saveState(savedMt, savedIdx);
                std::uint32_t nextSeed = state->mt->nextVal() % 99999;
                if (decodeFrame(payload, nextSeed, &v)) {
                    state->seed = nextSeed;
                    decoded = true;
                    emitLog(QString("SEED_SYNC (handshake): seed %1").arg(nextSeed));
                } else {
                    state->mt->restoreState(savedMt, savedIdx);
                }
            }
        }
        if (!decoded && len > 0 && totalFrames > 0) {
            m_undecCount++;
            if (m_undecCount <= 10) {
                QString hex = QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(payload.data()),
                                                             int(payload.size())).toHex().left(80));
                QString ascii = QString::fromLatin1(reinterpret_cast<const char *>(payload.data()),
                                                    int(payload.size())).left(40);
                bool printable = true;
                for (int i = 0; i < ascii.size(); ++i) {
                    if (ascii.at(i).toLatin1() < 32 && ascii.at(i) != '\n' && ascii.at(i) != '\r') {
                        printable = false;
                        break;
                    }
                }
                if (printable && !ascii.trimmed().isEmpty())
                    emitLog(QString("UNDEC[%1] flag=%2 len=%3: \"%4\"").arg(m_undecCount).arg(flag).arg(len).arg(ascii.trimmed()));
                else
                    emitLog(QString("UNDEC[%1] flag=%2 len=%3 hex=%4").arg(m_undecCount).arg(flag).arg(len).arg(hex));
            }
        }
        if (decoded && v.type == tcp::AmfValue::Arr && !v.arr.empty()) {
            const auto &first = v.arr[0];
            if (first.type == tcp::AmfValue::Int || first.type == tcp::AmfValue::Double) {
                int op = int(first.i);
                if (first.type == tcp::AmfValue::Double)
                    op = int(first.d);
                totalFrames++;
                if (!seenOps.contains(op)) {
                    seenOps.insert(op);
                    emitLog(QString("op %1 (frames=%2, seed=%3)").arg(op).arg(totalFrames).arg(state->seed));
                }
                // PING -> PONG. El seed: el PING #1 del server viene con seed 0
                // (el log lo muestra) pero el PONG #1 ya lleva el MT avanzado
                // (binario: cksum 0x04 desde el PONG #1). El server avanza SU MT
                // en el PING #1: el PING #2 ya llega cifrado con nextVal#1. Los
                // PINGs #11/#21 llegan con el seed NUEVO: el retry del decode
                // (SEED_SYNC) los detecta, aqui NO se avanza el MT de nuevo.
                if (op == 1 && state->mt) {
                    state->pingCount++;
                    if (state->pingCount == 1)
                        state->seed = state->mt->nextVal() % 99999;
                    // el binario responde con el MISMO ts del PING del server
                    double pingTs = 0;
                    if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Double)
                        pingTs = v.arr[1].d;
                    else if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Int)
                        pingTs = double(v.arr[1].i);
                    if (pingTs <= 0)
                        pingTs = double(QDateTime::currentMSecsSinceEpoch());
                    emit debugLog(QString("TCP >> PONG [10001.0, ts, %1] seed=%2 chk=%3")
                                      .arg(state->seed % 100).arg(state->seed).arg(state->seed % 63));
                    sendFrame(sock, tcp::makePongFrame(state->seed, pingTs));
                } else if (op == 4 && v.arr.size() >= 2) {
                    if (v.arr[1].type == tcp::AmfValue::Int) {
                        state->playerId = QString::number(v.arr[1].i);
                        emitLog("PLAYER_ID " + state->playerId);
                    }
                } else if (op == 52 && v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Str) {
                    emitLog("Desafio seguro recibido, enviando PROOF TPM...");
                    // challenge_roundtrip HTTP (el binario envia el challenge al
                    // engine y recibe el plaintext de 8 chars)
                    QString nonceRt;
                    {
                        QMutexLocker locker(&g_loginMutex); // QNetworkRequest internos
                        QString u = kEngine + "?_sid=" + urlEncodeTcp(sk, false) + "&rndx=" + rndxTcp();
                        QByteArray rt = httpPostTcp(net, QUrl(u), v.arr[1].s.toUtf8());
                        QString t = QString::fromUtf8(rt).trimmed();
                        if (t.size() == 8) {
                            nonceRt = t;
                            emitLog("Challenge roundtrip HTTP OK: " + t);
                        }
                    }
                    QFile pf(m_pemPath);
                    if (pf.open(QIODevice::ReadOnly)) {
                        QString pem = QString::fromUtf8(pf.readAll());
                        pf.close();
                        try {
                            QString proofStr;
                            Bytes pfrm = tcp::makeProofFrame(v.arr[1].s, state->suffix, m_deviceId, state->seed, pem, &proofStr, nonceRt);
                            emit debugLog(QString("TCP >> PROOF TPM seed=%1 chk=%2 device=%3 proofh=%4")
                                              .arg(state->seed).arg(state->seed % 63).arg(m_deviceId.left(16)).arg(proofStr.left(10)));
                            sendFrame(sock, pfrm);
                        } catch (const std::exception &e) {
                            emitLog("PROOF ERR: " + QString::fromUtf8(e.what()));
                        }
                    }
                } else if (op == 51) {
                    // FIX 2026-08-11 v23 (amigo: "op51 — UDP/connection confirm"):
                    // el binario responde el op51 con CLIENT_CONFIRM_UDP [10033]
                    // en RESTURPLE (makeConfirmUdpFrame). El comentario viejo
                    // decia que 10033 cortaba, pero era con el cifrado m2xc
                    // equivocado. El frame del binario usa resturple.
                    emitLog("op 51 -> CLIENT_CONFIRM_UDP [10033]");
                    sendFrame(sock, tcp::makeConfirmUdpFrame(state->seed));
                } else if (op == 28) {
                    // FIX v6: sin reply al op 28 (config 17:45, la mejor).
                    emitLog("op 28 (equipment request) - sin reply (vacio dania)");
                } else if (op == 53 || op == 40) {
                    // FIX 2026-08-11 v9 (amigo: op53 = SPAWN TOKEN): el token
                    // que el server entrega aqui es el que el op5 JOIN debe
                    // re-cifrar. Antes se ignoraba y el JOIN usaba un nonce
                    // aleatorio -> el server no confiaba y cortaba a los ~60s.
                    if (op == 53 && v.arr.size() >= 2) {
                        if (v.arr[1].type == tcp::AmfValue::Str)
                            state->spawnToken = v.arr[1].s;
                        else if (v.arr[1].type == tcp::AmfValue::Int)
                            state->spawnToken = QString::number(v.arr[1].i);
                        else if (v.arr[1].type == tcp::AmfValue::Double)
                            state->spawnToken = QString::number(v.arr[1].d);
                        emitLog("SPAWN TOKEN (op53): " + state->spawnToken.left(20));
                    }
                    if (!readySent) {
                        // orden exacto del binario (ctf_full.log): 53 ->
                        // inventory(ingame,slot=3) HTTP -> READY [10000,[true,1920,1080,1,true]].
                        // La espera de 1500ms NO bloquea: procesa frames y PONGs.
                        try {
                            httpApi(net, sk, magic, apiJson({{"do", "inventory"}, {"ingame", true}, {"slot", 3}}));
                        } catch (...) {}
                        readySent = true;
                        if (waitProcess(1500))
                            return true;
                        emit debugLog(QString("TCP >> READY [10000,[true,1920,1080,1,true]] seed=%1 chk=%2").arg(state->seed).arg(state->seed % 63));
                        sendFrame(sock, tcp::makeReadyFrame(state->seed));
                        emitLog("READY tras inventory(ingame)");
                        // 2026-08-10 (test #43): el server SOLO tolera UNA
                        // cuenta en espera de [20] por IP. Liberar el mutex en
                        // el READY dejaba 3+ esperas simultaneas -> el server
                        // cortaba a los ~8s a las que llegaron despues (Meet/
                        // Post/James cortados a los 8s exactos; Deity, el unico
                        // esperando, entro a los 14s).
                        // 2026-08-10 (test #46): el doble mutex (spawn + match)
                        // EMPEORO (1 -> 9 handshake fails): el server ve TODAS
                        // las conexiones con READY enviado como "esperando
                        // matchmaking", sin importar nuestro mutex interno. La
                        // cuenta que espera g_matchMutex ya completo el READY ->
                        // el server la corta junto a la que espera el [20].
                        // RETENER g_spawnMutex hasta el [20]: las demas ni
                        // siquiera llegan al READY -> el server ve 1 sola espera.
                        // Timeout del [20] (15s, abajo) para limitar la cola.
                        readyT0.start();
                    }
                    if (op == 40 && !nativeSent)
                        emitLog("Resume key (40) recibido");
                } else if (op == 20) {
                    if (!state->spawned) {
                        state->spawned = true;
                        emitLog("SPAWNED [20] recibido");
                        return true;
                    }
                } else if (op != 16 && op != 2 && op != 19 && op != 10 && op != 35 && op != 1) {
                    emitLog("op " + QString::number(op));
                }
            }
        }
        return false;
    };
    // espera activa: lee frames (responde PONGs) durante ms milisegundos.
    // Devuelve true si llego el [20] SPAWNED durante la espera.
    waitProcess = [&](int ms) -> bool {
        QElapsedTimer wt; wt.start();
        while (wt.elapsed() < ms && !m_stop && !aborted()) {
            processIrc();
            int len = 0, flag = 0;
            Bytes payload;
            if (recvFrame(sock, 150, &len, &flag, &payload) && len > 0 && !payload.empty()) {
                if (processFrame(len, flag, payload))
                    return true;
            }
            if (sock->state() != QAbstractSocket::ConnectedState)
                break;
        }
        return false;
    };
    while (!m_stop) {
        processIrc();
        int len = 0, flag = 0;
        Bytes payload;
        // timeout amplio para los dumps de entidades del FFA (frames de hasta
        // 64KB+ en trozos): un timeout corto podia partir un frame grande
        bool got = recvFrame(sock, 2000, &len, &flag, &payload);
        if (got && len > 0 && !payload.empty()) {
            if (processFrame(len, flag, payload))
                return true;
        }
        if (sock->state() != QAbstractSocket::ConnectedState) {
            if (err) *err = "TCP disconnected during handshake";
            return false;
        }
        // Deadline ABSOLUTO desde el inicio del intento (t0): el timeout por
        // frame de recvFrame se REINICIA con cada PING (el server pingea ~cada
        // 2s y el worker responde PONGs), asi que un server que nunca envia el
        // [20] SPAWNED haria que la espera durara para siempre. Este tope NO
        // depende de los PINGs recibidos: si el [20] no llego en m_spawnDeadlineMs
        // el intento falla y el caller reintenta (refreshXp: hasta 2 intentos,
        // 30s; run(): hasta 3 por region, 120s: el matchmaking tarda cuando
        // varias cuentas reconectan a la vez). Los PINGs se siguen respondiendo
        // mientras tanto.
        if (t0.elapsed() > m_spawnDeadlineMs) {
            if (err) *err = "SPAWNED [20] timeout";
            return false;
        }
        // 2026-08-10 (test #43): el server corta la espera del [20] a los
        // ~8s cuando hay OTRAS cuentas de la misma IP esperando. Con el lock
        // retenido (1 espera a la vez) el server NO corta, pero si el [20] no
        // llega en 15s el matchmaking esta lento: soltar y dejar que el caller
        // reintente con otro server (el retry ya pide server fresco).
        // FIX 2026-08-11 v21 (sala privada): el joinroom tarda mas en armar la
        // partida (el server espera a llenar la sala con las cuentas). Con 15s
        // el bot cortaba justo cuando el server iba a iniciar. La sala privada
        // del amigo (validada 9/9, 300s) necesita esperar mas: 90s en modo
        // sala, 15s en CTF publico.
        const qint64 spawnTimeoutMs = m_useRoom ? 90000 : 15000;
        if (readySent && readyT0.isValid() && readyT0.elapsed() > spawnTimeoutMs) {
            if (err) *err = "SPAWNED [20] timeout (matchmaking lento)";
            return false;
        }
    }
    if (err) *err = "stopped";
    return false;
}

void FarmWorker::postSpawnSequence(QTcpSocket *sock, QNetworkAccessManager *net,
                                   const QString &sk, const QString &magic,
                                   FarmState *state, const QString &suffix)
{
    // Secuencia EXACTA del binario tras el [20] SPAWNED (ctf_full.log): inventory
    // slot=5 -> news -> equip (verificado contra current) -> play HTTP + NATIVE_PLAY
    // [true] + play HTTP + NATIVE_PLAY [false] + gamemode. El binario no envia mas
    // frames: solo responde PONGs (match_end.log).
    // CRITICO (causa raiz de las caidas ~12s post-[20], 2026-08-10): las esperas
    // entre HTTP NO pueden ser msleep() puro — el server pingea cada ~2s y corta
    // la sesion tras ~3 PINGs sin PONG. El Python validado usa drain() que
    // procesa frames (PING->PONG) durante la espera. Aqui drainMs() hace lo mismo
    // con el seed/MT compartido del estado (avanza seed cada 10 pings, igual que
    // el handler del PING del loop principal).
    // ADEMAS (2026-08-10, evidencia test #24/#26): con 10 farms el mutex
    // global serializa los HTTPs — el postSpawn tardaba 14s (Anisa) y el
    // server corta a los ~12s del [20]. El httpApiFast (tryLock 350ms +
    // saltar el HTTP) fue PEOR: las cuentas quedaban sin gamemode confirmado
    // y el server las cortaba a 0s (test #26: 5 cuentas Farming+lost en el
    // mismo segundo; Post, el unico cuyo postSpawn completo todos los HTTPs,
    // sobrevivio 240s con RESPAWNED). Fix REAL (replica el drain del Python):
    // httpApiDrain espera el mutex con tryLock(50) en loop y MIENTRAS espera
    // procesa frames con drainMs(50) (PING->PONG) — el postSpawn completa
    // TODOS los HTTPs sin dejar de responder PONGs, como el run validado.
    std::function<void(int)> drainMs;
    drainMs = [&](int ms) {
        // NO-BLOQUEANTE (2026-08-10, test #36): recvFrame(sock,100) espera
        // hasta 400ms por trozo (waitData con 3 retries). El dump de
        // entidades (6651+ bytes) llega en trozos con pausas -> el drain de
        // 165ms se convertia en 13s bloqueado y el server cortaba a los ~12s
        // del [20]. Ahora SOLO se procesan los frames completos ya presentes
        // en el buffer (bytesAvailable); si un frame esta a medio llegar, se
        // deja en el buffer y el loop principal lo lee.
        QElapsedTimer wt; wt.start();
        while (wt.elapsed() < ms && !m_stop && !aborted()) {
            if (sock->bytesAvailable() < 3)
                break;
            QByteArray hdr = sock->peek(3);
            int flen = (std::uint8_t(hdr.at(0)) << 8) | std::uint8_t(hdr.at(1));
            if (flen < 4 || sock->bytesAvailable() < 3 + flen)
                break; // frame incompleto: lo lee el loop principal
            int len = 0, flag = 0;
            Bytes payload;
            if (!recvFrame(sock, 5, &len, &flag, &payload) || len <= 0 || payload.empty())
                continue;
            tcp::AmfValue v;
            bool decoded = false;
            if (flag == 1 && !payload.empty() && payload[0] <= 0x09) {
                tcp::Amf3Decoder d(payload);
                v = d.readValue();
                decoded = d.ok();
            } else if (flag != 1) {
                decoded = decodeFrame(payload, state->seed, &v);
                if (!decoded && state->mt) {
                    std::uint32_t savedMt[624];
                    int savedIdx;
                    state->mt->saveState(savedMt, savedIdx);
                    std::uint32_t nextSeed = state->mt->nextVal() % 99999;
                    if (decodeFrame(payload, nextSeed, &v)) {
                        state->seed = nextSeed;
                        decoded = true;
                        emitLog(QString("SEED_SYNC (postSpawn): seed %1").arg(nextSeed));
                    } else {
                        state->mt->restoreState(savedMt, savedIdx);
                    }
                }
            }
            if (decoded && v.type == tcp::AmfValue::Arr && !v.arr.empty()
                && v.arr[0].type == tcp::AmfValue::Int && v.arr[0].i == 1) {
                    // PING del server: PONG (el seed lo sincroniza el SEED_SYNC)
                    state->pingCount++;
                    double pingTs = 0;
                    if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Double)
                        pingTs = v.arr[1].d;
                    else if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Int)
                        pingTs = double(v.arr[1].i);
                    if (pingTs <= 0)
                        pingTs = double(QDateTime::currentMSecsSinceEpoch());
                    sendFrame(sock, tcp::makePongFrame(state->seed, pingTs));
                } else if (decoded && v.type == tcp::AmfValue::Arr && !v.arr.empty()
                    && v.arr[0].type == tcp::AmfValue::Int && v.arr[0].i == 28) {
                    // FIX v6: sin reply al op 28 (vacio dania; config 17:45).
                    emitLog("op 28 (drain) - sin reply");
                }
            if (sock->state() != QAbstractSocket::ConnectedState)
                break;
        }
    };
    // NATIVE_PLAY x2 ya se mando ANTES (frame TCP = confirmacion real del
    // spawn, no necesita los HTTPs). Los HTTPs de play/gamemode solo
    // sincronizan el estado del server; si la cola del mutex global esta
    // ocupada (otros farms en HTTP), esperar 8s por HTTP mataba el spawn
    // (server corta a los ~12s del [20]: akardego SPAWNED 12:50:37 ->
    // NATIVE_PLAY 12:50:49, 12s de espera). tryLock 350ms + timeout 500ms:
    // si no hay turno, saltar y seguir (el frame ya confirmo).
    auto httpApiDrain = [&](const QJsonObject &payload) -> QJsonObject {
        if (!g_loginMutex.tryLock(350))
            return QJsonObject();
        QJsonObject r = httpApiLockedTmo(net, sk, magic, payload, 500);
        g_loginMutex.unlock();
        return r;
    };
    if (m_gemItem > 0 && !m_gemEquipped) {
        try {
            // El inventory(slot=5) lista TODAS las gemas; el item ACTIVO es
            // data.current. Equipar dos veces puede DESEQUIPARLA (toggle), asi que
            // si current == m_gemItem no se toca.
            // 2026-08-10 (test #35): el loop de 3 intentos del equip check
            // tardaba ~13s con la cola del mutex ocupada (3x equip+inventory +
            // drains 570/1590/1300) -> el server cortaba a los ~12s del [20].
            // Ahora UN intento: si el inventory dice que la gema NO esta activa,
            // equipar una vez y verificar; si falla, el pre-connect del siguiente
            // ciclo reintenta. El spawn NO puede esperar al equip.
            QJsonObject invBefore = httpApiDrain(apiJson({{"do", "inventory"}, {"slot", 5}}));
            int currentBefore = gemCurrent(invBefore);
            drainMs(150);
            bool equipped = (currentBefore == m_gemItem);
            if (equipped) {
                emit debugLog(QString("EQUIP check: gem %1 ALREADY active (current=%2)").arg(m_gemItem).arg(currentBefore));
            } else {
                emit debugLog(QString("EQUIP check: gem %1 NOT active (current=%2) - sending equip (1 intento)").arg(m_gemItem).arg(currentBefore));
                QJsonObject invAfter;
                httpApiDrain(apiJson({{"do", "equip"}, {"item", m_gemItem}, {"slot", 5}}));
                drainMs(150);
                invAfter = httpApiDrain(apiJson({{"do", "inventory"}, {"slot", 5}}));
                equipped = gemEquipped(invAfter);
                emit debugLog(QString("EQUIP verify: current=%1").arg(gemCurrent(invAfter)));
            }
            if (equipped)
                emit stateChanged(QString("Gem %1 equipped and verified (current=%2)").arg(m_gemItem).arg(currentBefore));
            else
                emit stateChanged(QString("Gem %1 could NOT be equipped (pre-connect lo reintentara)").arg(m_gemItem));
            drainMs(150);
        } catch (...) {}
    }
    // AUTO-REPAIR en cada spawn/respawn (2026-08-11, BUG REAL: las gemas se
    // rompen al llegar al limite de XP y quedan rotas para siempre). Antes
    // el auto-repair solo corria si !m_gemEquipped, pero el pre-connect
    // equipa la gema ANTES del postSpawn -> m_gemEquipped=true -> el repair
    // NUNCA corria -> las gemas rotas (durability:0) bloqueaban el XP de las
    // cuentas (el cexp quedo congelado en todas: 3768/7200, 12997/14400...).
    // v30: reparar SIEMPRE si la gema esta danada (durability <= max/2),
    // este o no equipada.
    if (m_autoRepair.load() && m_gemItem > 0) {
        try {
            QJsonObject invR = httpApiDrain(apiJson({ {"do", "inventory"}, {"slot", 5} }));
            const QJsonArray items = invR.value("data").toObject().value("items").toArray();
            for (const auto &iv : items) {
                const QJsonObject item = iv.toObject();
                if (item.value("id").toInt() == m_gemItem) {
                    const int dur = item.value("durability").toInt();
                    const int maxDur = item.value("max_durability").toInt();
                    if (maxDur > 0 && dur <= maxDur / 2) {
                        emitLog(QString("Auto-repair: gem %1 durability %2/%3 - repairing").arg(m_gemItem).arg(dur).arg(maxDur));
                        try {
                            QJsonObject repairResp = httpApiDrain(apiJson({ {"do", "repair"}, {"item", m_gemItem}, {"slot", 5} }));
                            QString repairMsg = repairResp.value("message").toString();
                            bool repairOk = repairResp.value("result").toString() == QLatin1String("ok");
                            emitLog(QString("Auto-repair result: %1 (%2)").arg(repairOk ? "ok" : "failed").arg(repairMsg.left(60)));
                            // v32 (aclaracion del usuario): las gemas rotas por
                            // DESGASTE se reparan y se sigue con ellas (repair ok).
                            // Las que desaparecen por LIMITE de XP se van solas y
                            // vuelven a la tienda (aparte del macro). Aqui solo se
                            // cambia de gema si el repair FALLA con la gema rota.
                            if (!repairOk && dur <= 0 && !m_gemPriorityList.isEmpty()) {
                                emitLog("Gem ROTA y repair fallo - cambiando a la siguiente");
                                switchToNextGem(net, sk, magic, items);
                            }
                        } catch (...) {}
                    }
                    break;
                }
            }
        } catch (...) {}
    }
    // NATIVE_PLAY x1 (FIX 2026-08-11 v3, captura frida_v3 del binario REAL):
    // el cliente real tras el play envia SOLO 1 frame wlen=52 (NATIVE_PLAY).
    // En 466s de captura: 3 plays pero SOLO 2 wlen=52 (64458 tras play 64457,
    // 78649 tras play 78648; el 3er play a 321543 NO tiene NATIVE_PLAY). El
    // x2 (true+false) que el bot enviaba era trafico anomalo.
    // El frame sale en <1ms y los HTTPs van best-effort DESPUES (el flood
    // previo de ~8 HTTPs en 10s era lo que el server cortaba).
    emit debugLog(QString("TCP >> NATIVE_PLAY [5,[challenge,false]] seed=%1").arg(state->seed));
    // FIX 2026-08-11 v10 (amigo: el orden importa): el binario hace play HTTP
    // -> JOIN (wlen=52) 1ms DESPUES (frida_capture: play 12976 -> JOIN 12976;
    // play 64322 -> JOIN 64323; 9 plays -> 9 JOINs). El play mint el spawn
    // token y el op5 JOIN lo re-cifra. El bot lo enviaba al reves (JOIN antes
    // del play) -> el server no tenia token minted y cortaba.
    try {
        httpApiDrain(apiJson({{"do", "play"}, {"usertoken", QJsonValue()}}));
    } catch (...) {}
    // FIX 2026-08-11 v28: el JOIN re-cifra el payload CRUDO del op53
    // (state->spawnTokenRaw), no el string decodificado (que tenia prefijo
    // '00000008' malinterpretado). Si no hay raw, fallback al string.
    if (!state->spawnTokenRaw.empty()) {
        sendFrame(sock, tcp::makeNativePlayFrameKeyedRaw(state->seed, state->spawnTokenRaw, bytesOf(suffix), false));
    } else {
        sendFrame(sock, tcp::makeNativePlayFrameFlag(state->seed,
                                                     state->spawnToken.isEmpty() ? randomNonce() : state->spawnToken,
                                                     suffix, false));
    }
    emitLog("play + JOIN (op5) con spawn token raw");
    drainMs(287);
    // FIX v6: el equip frame en el postSpawn empeoro (prom 55s vs 87s de la
    // config sin equip). El binario lo envia en rafagas tras el respawn pero
    // con el frame GRANDE (4716-5100B con datos) que el bot no puede generar
    // (el [10037,[]] vacio confunde al server). Sin equip, como en 17:45.
    emitLog("NATIVE_PLAY tras SPAWNED");
    // 2026-08-10 (fix auto-buy): programar el primer chequeo AQUI (corre en
    // TODO [20]: el spawn inicial lo captura spawnSession y el handler del
    // loop solo ve respawns — el flag quedaba -1 para siempre). Reloj real
    // porque t0.elapsed() se reinicia en cada reconexion.
    if (m_nextAutoBuyX2 < 0)
        m_nextAutoBuyX2 = QDateTime::currentMSecsSinceEpoch() + 60000;
    // checkX2 MOVIDO al timer de 60s (m_nextAutoBuyX2): el chequeo INMEDIATO
    // aqui sumaba 2 HTTPs mas (inventory slots 3/4) al flood del postSpawn que
    // el binario real no hace. El badge del x2 tarda ~60s en actualizarse.
}

// 2026-08-10 (pedido del usuario: "detecta solo el de las gemas" + "todas
// las cuentas guardadas"): el estado REAL del x2 sale del INVENTARIO DE
// CONSUMIBLES (slots 3 y 4 — confirmado por captura Frida del binario
// 2026-08-10: {"do":"inventory","ingame":true,"slot":3} + slot 4).
// SOLO se detecta el boost DE LAS GEMAS: "Double Gem XP" id=8590
// (el "Double XP" id=2016 es XP de cuenta, NO interesa).
// durability > 0 = ACTIVO (verde); ausente o durability 0 = NO hay (rojo).
// La compra (si auto-buy ON) rellena el inventario -> el siguiente chequeo
// lo ve verde. DETECCION por inventario SIEMPRE; compra solo con auto-buy.
void FarmWorker::checkX2(QNetworkAccessManager *net, const QString &sk, const QString &magic)
{
    if (m_stop.load())
        return;
    try {
        const bool autoBuyOn = m_autoBuyX2.load();
        // ---- 1. LEER EL INVENTARIO REAL de consumibles (slots 3 y 4) ----
        bool x2Found = false;      // item x2 presente en el inventario
        bool x2Active = false;     // con durability > 0
        QString x2Name;
        QJsonArray invItems;
        for (int slot : {3, 4}) {
            QJsonObject invResp = httpApi(net, sk, magic, apiJson({ {"do", "inventory"}, {"slot", slot} }));
            const QJsonArray items = invResp.value("data").toObject().value("items").toArray();
            for (const auto &iv : items)
                invItems.append(iv);
        }
        for (const auto &iv : invItems) {
            const QJsonObject item = iv.toObject();
            const int iid = item.value("id").toInt();
            // SOLO el boost de las gemas (8590). El 2016 (Double XP de
            // cuenta) se ignora por decision del usuario.
            if (iid != 8590)
                continue;
            const QString nm = item.value("name").toString();
            const int dur = item.value("durability").toInt();
            const int maxDur = item.value("max_durability").toInt();
            x2Found = true;
            x2Name = nm;
            // durability > 0 = boost vigente (los consumibles agotados
            // quedan con durability 0, p.ej. "Improved Mass Gainer" 0/20)
            if (dur > 0) {
                x2Active = true;
                emitLog(QString("checkX2: %1 ACTIVO (durability %2/%3)").arg(nm).arg(dur).arg(maxDur));
            } else {
                emitLog(QString("checkX2: %1 expirado (durability %2/%3)").arg(nm).arg(dur).arg(maxDur));
            }
        }
        if (x2Active) {
            // boost REALMENTE vigente en el inventario: verde.
            setX2State(1, QStringLiteral("x2 gemas activo (%1 en inventario)").arg(x2Name));
            return;
        }

        // ---- 2. SIN boost de gemas: comprar el 8590 si auto-buy ON ----
        // Consultar el store cat=6 para el id/precio del boost.
        QJsonObject storeResp = httpApi(net, sk, magic, apiJson({ {"do", "store"}, {"category", 6}, {"evo", false} }));
        QJsonArray storeItems;
        if (storeResp.value("data").isObject())
            storeItems = storeResp.value("data").toObject().value("items").toArray();
        else if (storeResp.value("data").isArray())
            storeItems = storeResp.value("data").toArray();
        QJsonObject userResp = httpApi(net, sk, magic, apiJson({ {"do", "userinfo"} }));
        QJsonObject udata = userResp.value("data").toObject();
        qlonglong coins = udata.value("coins").toVariant().toLongLong();
        if (coins <= 0 && udata.contains("userinfo"))
            coins = udata.value("userinfo").toObject().value("coins").toVariant().toLongLong();

        bool anyCandidate = false;
        for (const auto &si : storeItems) {
            const QJsonObject item = si.toObject();
            // SOLO el boost de gemas: id 8590 ("Double Gem XP").
            const int itemId = item.value("id").toInt();
            if (itemId != 8590)
                continue;
            const qlonglong price = item.value("price").toVariant().toLongLong();
            if (price <= 0)
                continue;
            anyCandidate = true;
            if (!autoBuyOn) {
                // auto-buy OFF: no comprar; rojo con la razon.
                setX2State(2, QStringLiteral("sin x2 de gemas en inventario (auto-buy desactivado)"));
                emitLog(QString("checkX2: Double Gem XP NO en inventario y auto-buy OFF (no se compra)"));
                break;
            }
            if (coins < price) {
                setX2State(3, QStringLiteral("sin coins para Double Gem XP (necesita %1, tiene %2)")
                                .arg(price).arg(coins));
                emitLog(QString("checkX2: coins insuficientes para Double Gem XP (%1 < %2)")
                            .arg(coins).arg(price));
                continue;
            }
            emitLog(QString("checkX2: Double Gem XP no activo - buying"));
            QJsonObject buyResp = httpApi(net, sk, magic, apiJson({ {"do", "buy"}, {"item", itemId} }));
            const QString buyMsg = buyResp.value("message").toString();
            const bool buyOk = buyResp.value("result").toString() == QLatin1String("ok");
            if (buyOk) {
                setX2State(1, QStringLiteral("x2 de gemas comprado: %1").arg(item.value("name").toString()));
                emitLog(QString("checkX2: bought '%1' successfully").arg(item.value("name").toString()));
            } else if (buyMsg.contains(QLatin1String("already_owned"))) {
                // el server dice que ya lo tiene: el inventario no lo listo
                // (puede tardar en aparecer) -> verde conservador.
                setX2State(1, QStringLiteral("x2 de gemas ya activo (%1)").arg(item.value("name").toString()));
                emitLog(QString("checkX2: Double Gem XP ya activo (already_owned)"));
            } else {
                setX2State(2, buyMsg.left(60));
                emitLog(QString("checkX2: buy failed: %1").arg(buyMsg.left(60)));
            }
            break; // un intento por chequeo
        }
        if (!anyCandidate && !x2Found)
            setX2State(2, QStringLiteral("Double Gem XP no disponible en tienda ni inventario"));
    } catch (const std::exception &e) {
        emitLog(QString("checkX2: ERROR %1").arg(QString::fromUtf8(e.what()).left(80)));
    } catch (...) {
        emitLog("checkX2: ERROR desconocido");
    }
}

void FarmWorker::refreshXp()
{
    // Refresh de XP de la gema por SETTLE de sesion. Mecanismo verificado en vivo
    // (live_xp_probe2/3.log + lecturas del farm loop el 07/08): el server NO
    // actualiza el cexp de inventory slot=5 mientras la cuenta esta en partida
    // (lecturas de 60s congeladas durante horas de farmeo), pero cuando la sesion
    // TCP TERMINA (kick por cambio de modo, stop o cierre del socket) materializa
    // la XP ganada ~10-60s despues (settle). El flujo viejo (spawn FFA + HvZ +
    // lectura ~10s tras el spawn) media ANTES del settle -> delta 0 en todas las
    // cuentas (run 16:13: "Refresh delta: ... => 0" x9).
    // Flujo nuevo (uniforme, sin stalls de 20s+):
    //  0) baseline FRESCO: inventory slot=5 justo antes del kick (cexp:null -> -1).
    //  1) cambio a FFA por HTTP (connect gm=0 + gamemode mode=0 + i18n): el cambio
    //     de modo kickea la sesion TCP del farm (si la hay).
    //  2) Con farm activo (m_skipFinalCtfSpawn) NO hay spawn TCP: el kick de modo
    //     ya termina la sesion del farm y el settle la acredita. Sin farm: spawn
    //     TCP FFA con topes cortos (deadline 15s, greeting 10s) + keepalive de
    //     kFfaDwellMs (PONGs) para ganar XP en partida + abort (fin de sesion).
    //  3) POLL del settle: inventory slot=5 cada kSettlePollIntervalMs hasta que
    //     cexp/exp cambie contra el baseline (tope kSettlePollMs).
    //  4) vuelta a CTF (misma region con farm; region nueva sin farm) + updateexp
    //     (nivel) + spawn TCP CTF final SOLO sin farm (queda spawneada en partida).
    //  delta = max(deltaExp, deltaCexp); cexp:null -> fallback a exp.
    static constexpr int kFfaDwellMs = 8000;           // partida FFA propia (path sin farm): sesion corta, solo para que el server acredite (antes 30s: el refresh solo mide, no farmea)
    static constexpr int kSettlePollIntervalMs = 4000; // cadencia del poll del settle
    // Tope del poll: 10s (1er poll INMEDIATO + 2 mas con cadencia 4s). El
    // refreshAll ABORTA la sesion del farm ANTES del kick: el settle ya aterrizo
    // cuando el primer inventory corre, asi que el poll inmediato lo detecta sin
    // esperar 6s. Las cuentas sin ganancia salen a los ~9-10s (antes 25s).
    static constexpr int kSettlePollMs = 10000;
    if (m_deviceId.isEmpty())
        m_deviceId = readDeviceId();
    QString sk, magic, account;
    bool sameSession = !m_sk.isEmpty() && !m_magic.isEmpty();
    if (sameSession) {
        sk = m_sk;
        magic = m_magic;
        if (m_skipFinalCtfSpawn) {
            emit stateChanged("Refresh (same session, farm activo): kick FFA -> poll XP settle -> CTF (sin spawn TCP)");
        } else {
            emit stateChanged("Refresh (same session): kick FFA -> spawn FFA -> dwell -> poll settle -> CTF...");
        }
    } else {
        emit stateChanged("Refresh: new login...");
        doLogin(&sk, &magic, &account, nullptr);
        if (sk.isEmpty()) {
            emit xpRefreshDone(false, 0, 0, 0, 0, "Login failed: " + account);
            return;
        }
    }
    // QNAM unico del worker (creado UNA vez bajo lock: ctor/dtor de QNAM
    // concurrentes = race de Qt 6.10.3 en el registro global de Qt Network)
    if (!m_net) {
        QMutexLocker locker(&g_loginMutex);
        if (!m_net)
            m_net = new QNetworkAccessManager;
    }
    QNetworkAccessManager &net = *m_net;
    // ================= RAMA READ-ONLY =================
    // Cuenta con farm activo: el refresh SOLO actualiza la DB (nombre/coins ya
    // los trajo el login del caller; aqui cexp/exp/lvl frescos por HTTP). NO se
    // toca la sesion TCP del farm: sin kick FFA, sin spawns, sin restore de
    // modo. El running muestra su XP en vivo por el op 24 (xpUpdate) y la DB
    // se actualiza tambien con las lecturas periodicas gemXpRead del farm.
    // Antes el refresh abortaba la sesion del farm (abortSession + connect
    // gm=0) para medir el settle: mataba TODOS los farms a la vez en cada
    // refreshAll (130 desconexiones en masa en el log) y el farmeo se
    // interrumpia 1-3 min por cuenta (login + spawn simultaneos de 9).
    if (m_readOnly) {
        emit stateChanged("Refresh (read-only): farm activo - solo lecturas HTTP, sin tocar la sesion TCP");
        qlonglong cexpRO = -1, expRO = -1;
        int lvlRO = 0;
        try {
            QJsonObject invRO = httpApi(&net, sk, magic, apiJson({{"do", "inventory"}, {"slot", 5}}));
            if (readGemXp(invRO, &cexpRO, &expRO) && (cexpRO >= 0 || expRO >= 0)) {
                { QMutexLocker lk(&m_sessionMutex); m_gemExpInicial = expRO; m_gemCexpInicial = cexpRO; }
            }
        } catch (...) {}
        try {
            QJsonObject ueRO = httpApi(&net, sk, magic, apiJson({{"do", "updateexp"}}));
            lvlRO = ueRO.value("data").toObject().value("lvl").toInt();
        } catch (...) {}
        emit debugLog(QString("Refresh read-only: cexp=%1 exp=%2 lvl=%3 (sin kick, farm intacto)")
                          .arg(cexpRO).arg(expRO).arg(lvlRO));
        emit stateChanged(QString("Refresh: XP %1/%2 (read-only, farm intacto)")
                              .arg(cexpRO >= 0 ? cexpRO : 0).arg(expRO >= 0 ? expRO : 0));
        emit xpRefreshDone(true, cexpRO, expRO, 0, lvlRO, QString());
        return;
    }
    // uid + chattoken del pre-flow (loginifneeded/chattoken), como el run: el spawn
    // FFA los usa para el mmm tras el LISTENER y el GGID del IRC
    QString uid;
    QString ctToken;
    try {
        QJsonObject li = httpApi(&net, sk, magic, apiJson({{"do", "loginifneeded"}, {"at", ""}, {"wt", ""}, {"usertoken", QJsonValue()}}));
        QJsonObject ctResp = httpApi(&net, sk, magic, apiJson({{"do", "chattoken"}}));
        uid = QString::number(li.value("data").toObject().value("uid").toInt());
        ctToken = ctResp.value("data").toObject().value("token").toString();
        // FIX 2026-08-11: sesion reutilizada invalida (loginifneeded {} / uid 0)
        // -> forzar login fresco en el refresh tambien
        if (uid.isEmpty() || uid == QLatin1String("0")) {
            emitLog("refresh: sesion invalida (loginifneeded vacio/uid=0) - login fresco");
            { QMutexLocker lk(&m_sessionMutex); m_sk.clear(); m_magic.clear(); }
            emit xpRefreshDone(false, 0, 0, 0, 0, QStringLiteral("sesion invalida (loginifneeded vacio)"));
            return;
        }
    } catch (...) {}
    // 0) baseline FRESCO de la gema ANTES del kick: el delta se mide contra esta
    // lectura (la de setSession puede tener horas de antiguedad). cexp:null -> -1
    // (invalido), nunca 0 (0 confundiria con XP real 0). Si la lectura falla se
    // conserva la base pasada por setSession (fallback del refreshAll).
    qlonglong cexpBase = -1, expBase = -1;
    bool cexpBaseValid = false, expBaseValid = false;
    try {
        QJsonObject invBase = httpApi(&net, sk, magic, apiJson({{"do", "inventory"}, {"slot", 5}}));
        if (readGemXp(invBase, &cexpBase, &expBase)) {
            cexpBaseValid = cexpBase >= 0;
            expBaseValid = expBase >= 0;
        }
        if (cexpBaseValid || expBaseValid) {
            { QMutexLocker lk(&m_sessionMutex); m_gemExpInicial = expBase; m_gemCexpInicial = cexpBase; }
        }
        emit debugLog(QString("Refresh baseline fresco: cexp=%1 exp=%2 (valid cexp=%3 exp=%4)")
                          .arg(cexpBase).arg(expBase).arg(cexpBaseValid).arg(expBaseValid));
    } catch (...) {
        emit debugLog(QString("Refresh baseline fresco fallo; se usa la base de setSession (cexp=%1 exp=%2)")
                          .arg(m_gemCexpInicial).arg(m_gemExpInicial));
    }
    // 1) cambio a FFA por HTTP: connect(i=m_connectIndex+1, gm=0) + gamemode(mode=0) + i18n
    QString ffaRegion; // region del FFA (solo cambia en el flujo sin sesion previa)
    QJsonObject conn;
    if (sameSession) {
        emit stateChanged("Refresh: switching to FFA (same region, spawn)...");
        emit accountState("FFA", m_region);
        httpApi(&net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
        int ci3;
        { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci3 = m_connectIndex; }
        conn = httpApi(&net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                    {"i", ci3}, {"gm", 0}, {"retrying", false}, {"locale", "es_CO"}}));
        httpApi(&net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 0}}));
        emit debugLog(QString("FFA (same session, region %1): connect i=%2 gm=0 + gamemode mode=0")
                          .arg(m_region).arg(ci3));
    } else {
        if (m_region.isEmpty())
            pickRandomRegion();
        QStringList others;
        for (const QString &r : kFarmRegions) {
            if (r != m_region)
                others << r;
        }
        ffaRegion = others.at(QRandomGenerator::global()->bounded(int(others.size())));
        emit stateChanged("Refresh: FFA region " + ffaRegion);
        emit accountState("FFA", ffaRegion);
        httpApi(&net, sk, magic, apiJson({{"do", "servers"}, {"change", ffaRegion}}));
        httpApi(&net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
        int ci4;
        { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci4 = m_connectIndex; }
        conn = httpApi(&net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                    {"i", ci4}, {"gm", 0}, {"retrying", false}, {"locale", "es_CO"}}));
        httpApi(&net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 0}}));
        emit debugLog(QString("FFA: connect i=%1 gm=0 + gamemode index=1 mode=0").arg(ci4));
    }
    QString server = conn.value("data").toObject().value("server").toString();
    QString token = conn.value("data").toObject().value("token").toString();
    // server/token del connect FFA alimentan el spawn TCP FFA (obligatorio)
    if (server.isEmpty() || token.isEmpty()) {
        QString connErr = "FFA connect failed: " + QString::fromUtf8(QJsonDocument(conn).toJson()).left(200);
        if (sameSession)
            backToCtfSameRegion(&net, sk, magic);
        else
            restoreCtfMode(&net, sk, magic, ffaRegion);
        emit xpRefreshDone(false, 0, 0, 0, 0, connErr);
        return;
    }
    // 2) Con farm activo (m_skipFinalCtfSpawn) el refresh NO spawnea TCP: el
    // cambio de modo HTTP (arriba) kickea la sesion TCP del farm y la XP de la
    // gema se materializa cuando ESA sesion termina (settle ~10-60s; verificado
    // en vivo: el spawn FFA no acredita nada y era la fuente de los stalls de
    // 20s+ "No greeting"). Sin farm: spawn TCP FFA con topes cortos (deadline
    // 15s en vez de 30s, greeting 10s) + keepalive de kFfaDwellMs (PONGs, sin
    // MOVE: la sesion queda en partida ganando XP) + abort = fin de sesion.
    bool spawnedFfa = false;
    QTcpSocket ffaSock;
    FarmState ffaState;
    QTcpSocket ircSockFfa;
    QByteArray ircBufFfa;
    QString ffaHost = server.section(':', 0, 0);
    int ffaPort = server.contains(':') ? server.section(':', 1, 1).toInt() : 443;
    if (!m_skipFinalCtfSpawn) {
        m_spawnDeadlineMs = 10000; // refresh: tope corto (antes 15s) para no colgarse
        m_greetingTimeoutMs = 4000;
        QString spawnErr;
        // 1 intento (antes 2): el refresh solo necesita el settle, no una
        // partida estable; si el spawn falla, el poll detecta igual o el
        // early-exit corta con delta 0. 2 intentos clavaban ~30s extra.
        for (int attempt = 0; attempt < 1 && !spawnedFfa && !aborted(); ++attempt) {
            emit stateChanged(QString("Refresh: FFA spawn (attempt %1/2)...").arg(attempt + 1));
            ffaSock.connectToHost(resolveHostMutexed(ffaHost), ffaPort);
            if (!ffaSock.waitForConnected(10000)) {
                spawnErr = "TCP FFA connect failed: " + ffaSock.errorString();
                emit debugLog(spawnErr);
                ffaSock.abort();
                QThread::msleep(500);
                continue;
            }
            ffaSock.setSocketOption(QAbstractSocket::LowDelayOption, 1);
            emit stateChanged("TCP FFA connected " + ffaHost + ":" + QString::number(ffaPort));
            QString err;
            if (spawnSession(&ffaSock, &net, sk, magic, ffaHost, ffaPort, token, QString(),
                             uid, ctToken, 0, &err, &ffaState, &ircSockFfa, &ircBufFfa)) {
                spawnedFfa = true;
                emit stateChanged("SPAWNED FFA");
                emit debugLog(QString("SPAWNED FFA (op 20) on attempt %1").arg(attempt + 1));
            } else {
                spawnErr = err;
                emit debugLog(QString("FFA spawn attempt %1/2 failed: %2").arg(attempt + 1).arg(err));
            }
            if (!spawnedFfa) {
                ffaSock.abort();
                if (ircSockFfa.state() == QAbstractSocket::ConnectedState)
                    ircSockFfa.abort();
                QThread::msleep(800);
            }
        }
        if (!spawnedFfa) {
            if (sameSession)
                backToCtfSameRegion(&net, sk, magic);
            else
                restoreCtfMode(&net, sk, magic, ffaRegion);
            emit xpRefreshDone(false, 0, 0, 0, 0, "FFA spawn failed: " + spawnErr);
            return;
        }
        // keepalive del FFA: responde PONGs (mismo patron que spawnSession) para
        // mantener la sesion en partida durante kFfaDwellMs; al abortar, el
        // server settlea la XP ganada en ese tiempo.
        QElapsedTimer dwellT; dwellT.start();
        while (dwellT.elapsed() < kFfaDwellMs && !m_stop && !aborted() && ffaSock.state() == QAbstractSocket::ConnectedState) {
            int len = 0, flag = 0;
            Bytes payload;
            if (recvFrame(&ffaSock, 200, &len, &flag, &payload) && len > 0 && !payload.empty()) {
                tcp::AmfValue v;
                bool decoded = false;
                if (flag == 1 && !payload.empty() && payload[0] <= 0x09) {
                    tcp::Amf3Decoder d(payload);
                    v = d.readValue();
                    decoded = d.ok();
                } else if (flag != 1) {
                    decoded = decodeFrame(payload, ffaState.seed, &v);
                    if (!decoded && ffaState.mt) {
                        std::uint32_t savedMt[624];
                        int savedIdx;
                        ffaState.mt->saveState(savedMt, savedIdx);
                        std::uint32_t nextSeed = ffaState.mt->nextVal() % 99999;
                        if (decodeFrame(payload, nextSeed, &v)) {
                            ffaState.seed = nextSeed;
                            decoded = true;
                            emitLog(QString("SEED_SYNC (FFA): seed %1").arg(nextSeed));
                        } else {
                            ffaState.mt->restoreState(savedMt, savedIdx);
                        }
                    }
                }
                if (decoded && v.type == tcp::AmfValue::Arr && !v.arr.empty() && v.arr[0].type == tcp::AmfValue::Int) {
                    int op = int(v.arr[0].i);
                    if (op == 1 && ffaState.mt) {
                        ffaState.pingCount++;
                        if (ffaState.pingCount == 1)
                            ffaState.seed = ffaState.mt->nextVal() % 99999;
                        double pingTs = double(QDateTime::currentMSecsSinceEpoch());
                        if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Double)
                            pingTs = v.arr[1].d;
                        sendFrame(&ffaSock, tcp::makePongFrame(ffaState.seed, pingTs));
                    } else if (op == 28) {
                        emitLog("op 28 (FFA) - sin reply");
                    }
                }
            }
            QCoreApplication::processEvents(QEventLoop::AllEvents);
        }
        emit debugLog(QString("FFA dwell: %1s en partida, cerrando sesion para el settle")
                          .arg(QString::number(dwellT.elapsed() / 1000.0, 'f', 0)));
        ffaSock.abort();
        if (ircSockFfa.state() == QAbstractSocket::ConnectedState)
            ircSockFfa.abort();
    } else {
        emit stateChanged("Refresh: FFA spawn omitido (farm activo: la sesion del farm settlea con el kick de modo)");
        emit debugLog("Refresh: skip FFA TCP spawn (m_skipFinalCtfSpawn: kick HTTP + poll del settle)");
    }
    // 3) POLL del settle: inventory slot=5 hasta que cexp/exp cambie contra el
    // baseline (el settle aterriza ~10-60s tras el fin de la sesion: la del farm
    // en el path farm, la del FFA propio en el path sin farm). Si la cuenta no
    // gano XP (idle real), el poll termina sin cambio -> delta 0 honesto.
    qlonglong cexpDespues = cexpBase;
    qlonglong expDespues = expBase;
    const qint64 pollStart = QDateTime::currentMSecsSinceEpoch();
    bool settleSeen = false;
    int pollCount = 0;
    // Solo tiene sentido pollear si hay una sesion que pueda settlear: la del
    // FFA propio (spawnedFfa) o la del farm activo kickeada por el cambio de
    // modo (m_skipFinalCtfSpawn). Sin ninguna, el poll no puede detectar nada
    // y solo clavaria la cuenta en "Refreshing" durante kSettlePollMs.
    const bool pollable = spawnedFfa || m_skipFinalCtfSpawn;
    if (!pollable)
        emit debugLog("Settle poll: sin sesion (spawn FFA fallo y sin farm activo) - delta 0");
    while (pollable && !settleSeen && QDateTime::currentMSecsSinceEpoch() - pollStart < kSettlePollMs && !m_stop && !aborted()) {
        // Primer poll INMEDIATO: el abort de la sesion del farm (refreshAll)
        // ya forzo el settle antes del kick, el inventory suele verlo ya.
        // Los siguientes esperan la cadencia.
        if (pollCount > 0)
            QThread::msleep(kSettlePollIntervalMs);
        ++pollCount;
        QJsonObject invP;
        try {
            invP = httpApi(&net, sk, magic, apiJson({{"do", "inventory"}, {"slot", 5}}));
        } catch (...) {}
        qlonglong cp = -1, ep = -1;
        readGemXp(invP, &cp, &ep);
        const bool cpv = cp >= 0, epv = ep >= 0;
        settleSeen = (cpv != cexpBaseValid) || (cpv && cp != cexpBase)
                  || (epv != expBaseValid) || (epv && ep != expBase);
        if (settleSeen) {
            cexpDespues = cp;
            expDespues = ep;
        }
        emit debugLog(QString("Settle poll %1: cexp=%2 exp=%3 (base %4/%5)%6")
                          .arg(pollCount).arg(cp).arg(ep).arg(cexpBase).arg(expBase)
                          .arg(settleSeen ? " -> CAMBIO detectado" : ""));
    }
    if (!settleSeen)
        emit debugLog(QString("Settle poll: sin cambio en %1s (cuenta sin ganancia en la ventana o settle tardio)")
                          .arg(QString::number((QDateTime::currentMSecsSinceEpoch() - pollStart) / 1000.0, 'f', 0)));
    // 4) vuelta a CTF: misma region sin servers change si el farm esta activo,
    // region random nueva en el flujo con login nuevo (nunca se deja la cuenta
    // en otro modo). El connect response (server+token) queda en m_ctfConnect
    // para el spawn TCP final.
    m_ctfConnect = QJsonObject();
    if (sameSession)
        backToCtfSameRegion(&net, sk, magic);
    else
        restoreCtfMode(&net, sk, magic, ffaRegion);
    QJsonObject ue = httpApi(&net, sk, magic, apiJson({{"do", "updateexp"}}));
    int lvl = ue.value("data").toObject().value("lvl").toInt();
    // delta vs el baseline fresco. cexp:null -> -1: si cexp no es valido pero
    // exp si, el delta se mide con exp (fallback); si ninguno es valido, delta
    // 0 con log claro (la cuenta no expone la XP de la gema por HTTP).
    if (cexpDespues < 0 && cexpBase >= 0)
        cexpDespues = cexpBase;
    if (expDespues < 0 && expBase >= 0)
        expDespues = expBase;
    qlonglong deltaExp = (expBaseValid && expDespues >= 0) ? expDespues - expBase : 0;
    qlonglong deltaCexp = (cexpBaseValid && cexpDespues >= 0) ? cexpDespues - cexpBase : 0;
    qlonglong delta = deltaExp > deltaCexp ? deltaExp : deltaCexp;
    if (!cexpBaseValid && expBaseValid && deltaExp > 0)
        delta = deltaExp; // fallback: gema con cexp:null -> usar la variacion de exp
    emit debugLog(QString("Refresh delta: exp %1 (%2 -> %3) cexp %4 (%5 -> %6) => %7")
                      .arg(deltaExp).arg(expBase).arg(expDespues)
                      .arg(deltaCexp).arg(cexpBase).arg(cexpDespues).arg(delta));
    emit stateChanged(QString("Refresh: XP %1/%2 (gained %3)")
                          .arg(cexpDespues >= 0 ? cexpDespues : 0)
                          .arg(expDespues >= 0 ? expDespues : 0).arg(delta));
    // 6) SPAWN TCP final en CTF ("spawneas again"): la cuenta queda spawneada en
    // CTF con su socket listo, no solo en lobby. Server+token salen del connect
    // del restore CTF (m_ctfConnect). Sin invite (CTF publico). Con farm activo
    // (m_skipFinalCtfSpawn) se omite: el farm esta PAUSADO durante el refresh
    // (setRefreshInProgress) y re-spawnea CTF por su cuenta justo despues; un
    // segundo spawn CTF concurrente desde el refresh (a) pelearia con el farm,
    // (b) quemaria 2x30s de timeout cuando el matchmaking lo encola (run 03:51:
    // 6/9 cuentas con timeout doble). Cuentas SIN farm si spawnean CTF final:
    // quedan en partida, no en lobby.
    if (!m_skipFinalCtfSpawn) {
        const QString ctfServer = m_ctfConnect.value("data").toObject().value("server").toString();
        const QString ctfToken = m_ctfConnect.value("data").toObject().value("token").toString();
        if (ctfServer.isEmpty() || ctfToken.isEmpty()) {
            emit debugLog("Refresh: CTF connect sin server/token, sin spawn final");
        } else {
            const QString ctfHost = ctfServer.section(':', 0, 0);
            const int ctfPort = ctfServer.contains(':') ? ctfServer.section(':', 1, 1).toInt() : 443;
            bool ctfSpawned = false;
            for (int attempt = 0; attempt < 2 && !ctfSpawned && !aborted(); ++attempt) {
                emit stateChanged(QString("Refresh: final CTF spawn (attempt %1/2)...").arg(attempt + 1));
                QTcpSocket sock;
                sock.connectToHost(resolveHostMutexed(ctfHost), ctfPort);
                if (!sock.waitForConnected(10000)) {
                    emit debugLog("Refresh: final CTF TCP connect failed: " + sock.errorString());
                    sock.abort();
                    QThread::msleep(600);
                    continue;
                }
                sock.setSocketOption(QAbstractSocket::LowDelayOption, 1);
                FarmState state;
                QTcpSocket ircSock;
                QByteArray ircBuf;
                QString err;
                if (spawnSession(&sock, &net, sk, magic, ctfHost, ctfPort, ctfToken, QString(),
                                 uid, ctToken, 3, &err, &state, &ircSock, &ircBuf)) {
                    ctfSpawned = true;
                    emit stateChanged("Refresh: SPAWNED CTF again");
                    emit debugLog(QString("Refresh: final CTF spawn OK (op 20) on attempt %1").arg(attempt + 1));
                } else {
                    emit debugLog(QString("Refresh: final CTF spawn attempt %1/2 failed: %2").arg(attempt + 1).arg(err));
                }
                sock.abort();
                if (ircSock.state() == QAbstractSocket::ConnectedState)
                    ircSock.abort();
                if (!ctfSpawned)
                    QThread::msleep(800);
            }
            if (!ctfSpawned)
                emit debugLog("Refresh: final CTF spawn failed (la cuenta quedo en lobby CTF, el farm reconecta solo)");
        }
    } else {
        emit stateChanged("Refresh: final CTF spawn omitido (el farm re-spawnea)");
        emit debugLog("Refresh: skip TCP final CTF spawn (m_skipFinalCtfSpawn: el farm re-spawnea CTF al terminar el refresh)");
    }
    emit xpRefreshDone(true, cexpDespues, expDespues, delta, lvl, QString());
}

void FarmWorker::run()
{
    // Bucle de sesiones: cada iteracion es un intento de sesion con objetos
    // nuevos (sock/net/state/ircSock...). El goto original re-inicializaba esos
    // objetos SIN destruirlos (fuga de sockets/FDs por reconexion); con continue
    // el scope de la iteracion se cierra y los destructores corren. m_region,
    // m_sk, m_magic y m_connectIndex persisten entre sesiones (miembros).
    // Fallos transitorios de red/server NO matan el farm (requisito: farmeo
    // constante): la sesion se reintenta con backoff. Solo se abandona tras
    // consecutiveSessionFailures sesiones seguidas SIN lograr spawnear.
    int consecutiveSessionFailures = 0;
    // contador de frames no decodificados: miembro del worker (los 9 farms
    // comparten proceso; el static anterior era una data race). Reseteado por
    // run: logea los primeros 10 frames UNDEC de cada run.
    m_undecCount = 0;
    while (!m_stop) {
    if (m_stop) { emit finishedOk(false, "stopped"); return; }
    // Si el refresh corre en paralelo (thread separado), el farm espera a que
    // termine antes de reconectar: reconectar durante el FFA del refresh haria
    // que las dos sesiones TCP del mismo usuario se kickeen entre si.
    while (!m_stop && m_refreshInProgress.load()) {
        QCoreApplication::processEvents(QEventLoop::AllEvents);
        QThread::msleep(300);
    }
    if (m_stop) { emit finishedOk(false, "stopped"); return; }
    // cada sesion/reconnect elige una region CTF random de las 4 disponibles,
    // salvo que el refresh ya haya dejado una region (setRegion)
    if (m_region.isEmpty())
        pickRandomRegion();
    emit regionChanged(m_region);
    emit stateChanged("CTF region: " + m_region);
    if (m_deviceId.isEmpty())
        m_deviceId = readDeviceId();
    if (m_deviceId.isEmpty()) {
        emit stateChanged("ERROR: no device id");
        emit finishedOk(false, "no device id");
        return;
    }
    auto fail = [this](const QString &e) {
        emit stateChanged("ERROR: " + e);
        emit finishedOk(false, e);
    };
    emit stateChanged("Login...");
    QString sk, magic, account;
    // Sesion del pre-spawn (spawn() le pasa la del login de pre-spawn via
    // setSession) o de una sesion previa: se REUTILIZA sin re-login. Los 9
    // farms arrancan a la vez; cada doLogin paralelo era una race de Qt
    // 6.10.3 (AV 0x1CE857/0x1C8A4E en los logins de los farms). Si la sesion
    // reutilizada falla (server la invalido), los retry paths de abajo la
    // limpian y el siguiente intento hace login fresco.
    const bool reuseSession = !m_sk.isEmpty() && !m_magic.isEmpty();
    if (reuseSession) {
        sk = m_sk;
        magic = m_magic;
        emit stateChanged("Login... (sesion del pre-spawn reutilizada, sin re-login)");
    } else {
        doLogin(&sk, &magic, &account, nullptr);
        if (sk.isEmpty()) {
            // Login fallido (red/server caido): NO mata el farm — reintenta la
            // sesion con backoff. Solo abandona tras muchos fallos seguidos.
            consecutiveSessionFailures++;
            if (consecutiveSessionFailures >= 15) {
                fail("Login failed (15 intentos seguidos): " + account);
                return;
            }
            emit stateChanged(QString("Login failed, retrying in ~5s (%1/15)...").arg(consecutiveSessionFailures));
            // jitter: cuando varias cuentas caen a la vez, el backoff fijo las
            // hacia reintentar al mismo segundo (9 logins simultaneos saturan el
            // server HTTP y el matchmaking encola -> timeouts de spawn)
            // 2026-08-11 (farm inestable: 372 XP en 10 min): jitter ampliado +
            // sesgo por deviceId para des-sincronizar los reintentos masivos.
            QThread::msleep(4000 + reconnectJitterMs() + (qHash(m_deviceId) % 8000));
            continue;
        }
    }
    if (m_stop) { emit finishedOk(false, "stopped"); return; }
    // sesion local del farm (el refresh en thread separado la copia con setSession
    // y hace su propio flujo sin tocar este socket). Bajo mutex: la GUI lee
    // estos campos en refreshXp (THR-2).
    {
        QMutexLocker lk(&m_sessionMutex);
        m_sk = sk;
        m_magic = magic;
    }

    // HTTP API helper (mismo patron que do_login del Python)
    auto apiCall = [&](QNetworkAccessManager *net, const QString &skk, const QString &magicc, const QJsonObject &payload) -> QJsonObject {
        return httpApi(net, skk, magicc, payload);
    };

    // QNAM unico del farm (creado UNA vez bajo lock: ctor/dtor de QNAM
    // concurrentes = race de Qt 6.10.3 en el registro global de Qt Network)
    if (!m_net) {
        QMutexLocker locker(&g_loginMutex);
        if (!m_net)
            m_net = new QNetworkAccessManager;
    }
    QNetworkAccessManager &net = *m_net;
    // ---- Pre-flow del binario: i18n -> loginifneeded -> chattoken ----
    QString uid;
    QString ctToken;
    try {
        apiCall(&net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
        QJsonObject li = apiCall(&net, sk, magic, apiJson({{"do", "loginifneeded"}, {"at", ""}, {"wt", ""}, {"usertoken", QJsonValue()}}));
        QJsonObject ctResp = apiCall(&net, sk, magic, apiJson({{"do", "chattoken"}}));
        ctToken = ctResp.value("data").toObject().value("token").toString();
        emitLog("chattoken: " + ctToken.left(20) + "...");
        // el uid viene como numero (7741654): toString() da vacio, usar toInt
        uid = QString::number(li.value("data").toObject().value("uid").toInt());
        emitLog("uid=" + uid);
        // FIX 2026-08-11 (cuentas que no conectan: loginifneeded {} + uid=0):
        // una sesion reutilizada que el server ya rechazo devuelve {} o uid 0.
        // Si pasa, la sesion esta MUERTA: limpiarla y forzar login fresco en el
        // proximo ciclo (como el "Sesion reutilizada fallando" del connect).
        if (uid.isEmpty() || uid == QLatin1String("0")) {
            emitLog("loginifneeded vacio/uid=0: sesion invalida, se limpiara para login fresco");
            { QMutexLocker lk(&m_sessionMutex); m_sk.clear(); m_magic.clear(); }
            consecutiveSessionFailures++;
            if (consecutiveSessionFailures >= 15) {
                fail("Sesion invalida (15 intentos seguidos): loginifneeded vacio");
                return;
            }
            emit stateChanged(QString("Sesion invalida (loginifneeded vacio), login fresco en ~5s (%1/15)...").arg(consecutiveSessionFailures));
            QThread::msleep(4000 + reconnectJitterMs() + (qHash(m_deviceId) % 8000));
            continue;
        }
        // el nombre real de la cuenta sale del loginifneeded: data.username,
        // data.nickname o data.userinfo.username (el stats "previous_user" falla)
        QJsonObject liData = li.value("data").toObject();
        QString liName = liData.value("username").toString();
        if (liName.isEmpty())
            liName = liData.value("nickname").toString();
        QJsonObject liUser = liData.value("userinfo").toObject();
        if (liName.isEmpty())
            liName = liUser.value("username").toString();
        if (liName.isEmpty())
            liName = liUser.value("nickname").toString();
        if (liName.isEmpty())
            liName = liUser.value("display").toString(); // nombre real (loginifneeded)
        if (!liName.isEmpty())
            account = liName;
        emitLog("loginifneeded: " + QString::fromUtf8(QJsonDocument(li).toJson(QJsonDocument::Compact)));
    } catch (...) {}
    emit stateChanged("Account: " + (account.isEmpty() ? "?" : account));

    // ---- CTF + region random ----
    emit stateChanged("CTF mode...");
    apiCall(&net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 3}}));
    emit accountState("CTF", m_region);
    apiCall(&net, sk, magic, apiJson({{"do", "servers"}, {"change", m_region}}));
    apiCall(&net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
    QString inviteString;
    // connect i=1 (lobby) - como el binario. El "i" se INCREMENTA con cada
    // reconnect (captura servers_cap.log: i=2, i=3, i=4 en los cambios de server).
    int connectI;
    { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; connectI = m_connectIndex; }
    QJsonObject conn = apiCall(&net, sk, magic, QJsonObject{
        {"do", "connect"}, {"invite", false}, {"defered", true},
        {"i", connectI}, {"gm", -1}, {"retrying", false}, {"locale", "es_CO"},
    });
    emit debugLog(QString("connect i=%1").arg(connectI));
    // mmm del connect con tag CRECIENTE del contador persistente (v18)
    if (!uid.isEmpty()) {
        try {
            int tag = mmmTagGet(m_deviceId);
            apiCall(&net, sk, magic, apiJson({{"do", "mmm"}, {"begin", false}, {"serching", false},
                                                 {"add", QString("[%1,\"\",100,0]").arg(uid)}, {"tag", tag},
                                                 {"abandon", false}, {"mode", -1}, {"stop", false}}));
            mmmTagSet(m_deviceId, tag + 1);
            emitLog("mmm connect tag=" + QString::number(tag));
        } catch (...) {}
    }
    // joinroom: la sala que inicia el match (HM COMP MEX GEARS -> invite).
    // Si m_useRoom es false, usar el CTF publico (connect i=1 sin invite).
    if (m_useRoom) {
        QString roomName = "HM COMP MEX GEARS";
        QJsonObject rj = apiCall(&net, sk, magic, apiJson({{"do", "joinroom"}, {"code", roomName}}));
        inviteString = rj.value("data").toObject().value("invite_string").toString();
        if (inviteString.isEmpty()) {
            emit stateChanged("joinroom(" + roomName + ") failed, using public CTF");
        } else {
            emit stateChanged("Room: " + roomName + " (invite ok)");
            // connect i=2 con invite - el que entra a la sala
            QJsonObject result2 = apiCall(&net, sk, magic, QJsonObject{
                {"do", "connect"}, {"invite", inviteString}, {"defered", true},
                {"i", 2}, {"gm", -1}, {"retrying", false}, {"locale", "es_CO"},
            });
            if (result2.value("data").toObject().contains("server"))
                conn = result2;
            if (!uid.isEmpty()) {
                try {
                    int tag = mmmTagGet(m_deviceId);
                    apiCall(&net, sk, magic, apiJson({{"do", "mmm"}, {"begin", false}, {"serching", false},
                                                         {"add", QString("[%1,\"\",100,0]").arg(uid)}, {"tag", tag},
                                                         {"abandon", false}, {"mode", -1}, {"stop", false}}));
                    mmmTagSet(m_deviceId, tag + 1);
                    emitLog("mmm invite tag=" + QString::number(tag));
                } catch (...) {}
            }
        }
    } else {
        emit stateChanged("Public CTF mode (matchmaking)");
    }
    QString server = conn.value("data").toObject().value("server").toString();
    QString token = conn.value("data").toObject().value("token").toString();
    m_authToken = token;
    m_inviteString = inviteString;
    if (server.isEmpty() || token.isEmpty()) {
        // Connect HTTP fallido (httpApi devolvio {}: red caida, server
        // ocupado, sesion invalidada): ANTES esto llamaba fail() y la cuenta
        // quedaba muerta el resto del run (finishedOk(false) permanente).
        // Ahora se trata como fallo de sesion con backoff, igual que el spawn
        // fallido: solo fail() tras 15 sesiones seguidas.
        consecutiveSessionFailures++;
        if (reuseSession && consecutiveSessionFailures >= 3) {
            { QMutexLocker lk(&m_sessionMutex); m_sk.clear(); m_magic.clear(); }
            emit stateChanged("Sesion reutilizada fallando - proximo intento con login fresco");
        }
        if (consecutiveSessionFailures >= 15) {
            fail("CTF connect failed (15 sesiones seguidas): " + QString::fromUtf8(QJsonDocument(conn).toJson()).left(200));
            return;
        }
        emit stateChanged(QString("CTF connect failed, retrying session in ~5s (%1/15)...")
                              .arg(consecutiveSessionFailures));
        QThread::msleep(4000 + reconnectJitterMs() + (qHash(m_deviceId) % 8000));
        continue;
    }
    emit stateChanged("CTF server: " + server);

    // post-connect HTTP del binario (tras el connect i=1/i=2): inventory ingame
    // slot=3 -> news -> play -> gamemode. Sin esto el server no inicia el match.
    try {
        apiCall(&net, sk, magic, apiJson({{"do", "inventory"}, {"ingame", true}, {"slot", 3}}));
        apiCall(&net, sk, magic, apiJson({{"do", "news"}}));
        apiCall(&net, sk, magic, apiJson({{"do", "play"}, {"usertoken", QJsonValue()}}));
        apiCall(&net, sk, magic, apiJson({{"do", "gamemode"}, {"index", 1}, {"mode", 3}}));
    } catch (...) {}

    // Desequipar armors (slots 0,1,2) antes del farm CTF: el server gasta
    // durabilidad del armor en partida y el farm de gemas no lo usa. Request
    // verificado 2026-08-11: {"do":"equip","item":<id>,"slot":N,"cmd":"unequip"}.
    try {
        QJsonObject lin = apiCall(&net, sk, magic, apiJson({ {"do", "loginifneeded"}, {"at", ""}, {"wt", ""}, {"usertoken", QJsonValue()} }));
        QJsonObject ui = lin.value("data").toObject().value("userinfo").toObject();
        QJsonObject equip = ui.value("equip").toObject();
        for (const QString &slotKey : {QStringLiteral("0"), QStringLiteral("1"), QStringLiteral("2")}) {
            if (!equip.contains(slotKey))
                continue;
            const QJsonObject item = equip.value(slotKey).toObject();
            const int itemId = item.value("id").toInt();
            if (itemId <= 0)
                continue;
            if (item.value("type").toString().toLower() != QLatin1String("equipment"))
                continue;
            QJsonObject body;
            body.insert("do", QStringLiteral("equip"));
            body.insert("item", itemId);
            body.insert("slot", slotKey.toInt());
            body.insert("cmd", QStringLiteral("unequip"));
            const QJsonObject ur = apiCall(&net, sk, magic, body);
            if (ur.value("result").toString() == QLatin1String("ok"))
                emit debugLog(QString("UNEQUIP armor slot %1 (item %2)").arg(slotKey).arg(itemId));
            QThread::msleep(350);
        }
    } catch (...) {}

    // Equip pre-connect: asegurar la gema elegida en el slot 5 ANTES del TCP.
    // Al cambiar de gema el slot puede quedar vacio. El inventory(slot=5) lista
    // TODAS las gemas de la cuenta, asi que el check NO es "esta en items" sino
    // "el item activo (data.current) es la gema elegida". Si current != m_gemItem
    // se equipa y se reverifica (hasta 3 intentos). Si no se consigue, error claro
    // y NO se spawnea. El handler del op 20 mantiene su verificacion post-spawn
    // sin doble equip (solo actua si no esta equipada).
    if (m_gemItem > 0) {
        bool equipped = false;
        QJsonObject lastInvCheck;
        for (int attempt = 0; attempt < 3 && !equipped; ++attempt) {
            try {
                emit debugLog(QString("EQUIP check (attempt %1/3): inventory slot=5").arg(attempt + 1));
                QJsonObject invCheck = apiCall(&net, sk, magic, apiJson({{"do", "inventory"}, {"slot", 5}}));
                lastInvCheck = invCheck;
                int current = gemCurrent(invCheck);
                // guardar la exp total de la gema la primera vez (base del delta del refresh)
                if (m_gemExpInicial < 0) {
                    qlonglong e0 = -1, c0 = -1;
                    if (readGemXp(invCheck, &c0, &e0)) {
                        { QMutexLocker lk(&m_sessionMutex); m_gemExpInicial = e0; m_gemCexpInicial = c0; }
                        emit debugLog(QString("Initial XP of gem %1: cexp=%2 exp=%3").arg(m_gemItem).arg(m_gemCexpInicial).arg(m_gemExpInicial));
                        // baseline inicial SIN delta: el controller usa el primer
                        // valor como referencia (gemXpRead es la unica fuente de
                        // XP de la gema; el op 24 TCP es XP del jugador/partida).
                        // cexp:null -> c0=-1: no se emite baseline (evita el salto
                        // falso cuando el server empieza a reportar cexp real).
                        if (c0 >= 0 && e0 >= 0)
                            emit gemXpRead(m_gemCexpInicial, m_gemExpInicial);
                    }
                }
                if (current == m_gemItem) {
                    equipped = true;
                    m_gemEquipped = true; // skip del equip check en postSpawnSequence
                    emit debugLog(QString("EQUIP check: gem %1 ALREADY active (current=%2)").arg(m_gemItem).arg(current));
                    break;
                }
                emit debugLog(QString("EQUIP check: gem %1 NOT active (current=%2) - sending equip").arg(m_gemItem).arg(current));
                apiCall(&net, sk, magic, apiJson({{"do", "equip"}, {"item", m_gemItem}, {"slot", 5}}));
                QThread::msleep(700);
            } catch (...) { break; }
        }
        if (!equipped) {
            // El equip fallo 3 veces. Antes esto MATABA el farm (finishedOk
            // false -> la cuenta quedaba Idle todo el run; en el log: 40+
            // "could not be equipped ... Not spawning"). El fallo suele ser
            // transitorio (HTTP lento, server ocupado). Ahora se distingue:
            //  - la gema NO existe en el inventario (rota/cambiada) -> error
            //    claro y fin (reintentar seria quemar logins sin sentido)
            //  - la gema existe pero el equip no aplico -> reintento de sesion
            //    con backoff (el proximo login lo reintenta), como los fallos
            //    de login/spawn. Solo abandona tras 15 sesiones seguidas.
            bool gemExists = false;
            const QJsonArray items = lastInvCheck.value("data").toObject().value("items").toArray();
            for (const auto &iv : items) {
                if (iv.toObject().value("id").toInt() == m_gemItem) { gemExists = true; break; }
            }
            if (!gemExists) {
                fail(QString("Gem %1 is not in the inventory (slot 5). Not spawning.").arg(m_gemItem));
                return;
            }
            consecutiveSessionFailures++;
            // Sesion reutilizada fallando: forzar login fresco (el server pudo
            // invalidarla; el reinicio del ciclo la renueva).
            if (reuseSession && consecutiveSessionFailures >= 3) {
                { QMutexLocker lk(&m_sessionMutex); m_sk.clear(); m_magic.clear(); }
                emit stateChanged("Sesion reutilizada fallando - proximo intento con login fresco");
            }
            if (consecutiveSessionFailures >= 15) {
                fail(QString("Gem %1 could not be equipped in slot 5 (15 sesiones seguidas). Giving up.").arg(m_gemItem));
                return;
            }
            emit stateChanged(QString("Equip failed (gem %1 exists but not applied), retrying session in ~5s (%2/15)...")
                                  .arg(m_gemItem).arg(consecutiveSessionFailures));
            QThread::msleep(4000 + reconnectJitterMs() + (qHash(m_deviceId) % 8000));
            continue;
        }
        emit stateChanged(QString("Gem %1 equipped in slot 5 (pre-connect)").arg(m_gemItem));
        m_gemEquipped = true; // skip del equip check en postSpawnSequence
    }

    // === TCP connect CON RETRY ===
    // Hasta 3 intentos por servidor. Si los 3 fallan, se cambia de region
    // (nuevo HTTP connect) y se reintenta 3 mas. Maximo 6 intentos totales.
    // El farm espera PACIENTE el [20] SPAWNED: el matchmaking puede tardar mas
    // de 30s cuando varias cuentas reconectan a la vez (run 03:51: 6/9 cuentas
    // con "SPAWNED [20] timeout" a los 30s y ~3 min de downtime con 3 intentos
    // + cambios de region). Deadline 120s SOLO para el path del farm; el path
    // del refresh conserva el default de 30s (evita el cuelgue infinito).
    m_spawnDeadlineMs = 120000;
    // SIN UDP: el binario envia un datagrama INIT al puerto 3724 en el
    // handshake, pero su payload exacto no se puede replicar con seguridad
    // (el hook muestra len=0) y el datagrama del C++ generaba op 11 DAMAGE
    // con kick posible. El server confirma igual con el op 51 (CONFIRM_UDP,
    // que NO se responde, como el binario) y acredita la XP estando quieto.
    // Requisito del usuario: las conexiones del farm son TCP + HTTP, sin UDP.
    std::unique_ptr<QTcpSocket> sock(new QTcpSocket);
    std::unique_ptr<QTcpSocket> ircSock(new QTcpSocket);
    {
        QMutexLocker lk(&m_socketMutex);
        m_activeSock = sock.get();
    }
    FarmState state;
    // Reanudar el contador de XP acumulado entre reconexiones (el FarmState
    // se recrea en cada intento; sin esto el XP mostrado se reinicia).
    state.xpTotal = m_sessionXpTotal;
    QByteArray ircBuf;
    QElapsedTimer t0;
    QString host;
    int port = 443;
    bool spawned = false;
    QString spawnErr;
    int sameServerCount = 0; // 2026-08-10 (test #40): si el matchmaking devuelve el MISMO server tras cambiar de region (Java: s18388 x6), el retry TCP es inutil — cortar y pasar al backoff de sesion adaptativo (4->60s).
    for (int regionAttempt = 0; regionAttempt < 2 && !spawned && !m_stop && !aborted(); ++regionAttempt) {
        if (regionAttempt > 0) {
            // Cambio de servidor: nueva region + nuevo HTTP connect
            QString oldRegion;
            { QMutexLocker lk(&m_sessionMutex); oldRegion = m_region; }
            pickRandomRegion();
            {
                QMutexLocker lk(&m_sessionMutex);
                if (m_region == oldRegion) {
                    QStringList others;
                    for (const QString &r : kFarmRegions)
                        if (r != oldRegion) others << r;
                    if (!others.isEmpty())
                        m_region = others.at(QRandomGenerator::global()->bounded(int(others.size())));
                }
            }
            QString curRegion;
            { QMutexLocker lk(&m_sessionMutex); curRegion = m_region; }
            emit stateChanged("Retry: switching to region " + curRegion);
            apiCall(&net, sk, magic, apiJson({{"do", "servers"}, {"change", curRegion}}));
            apiCall(&net, sk, magic, apiJson({{"do", "i18n"}, {"update", qint64(QDateTime::currentSecsSinceEpoch())}, {"locale", "es_CO"}}));
            int ci5;
            { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci5 = m_connectIndex; }
            conn = apiCall(&net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                        {"i", ci5}, {"gm", -1}, {"retrying", true}, {"locale", "es_CO"}}));
            server = conn.value("data").toObject().value("server").toString();
            token = conn.value("data").toObject().value("token").toString();
            m_authToken = token;
            if (server.isEmpty() || token.isEmpty()) {
                emit stateChanged("Retry: new connect failed, giving up");
                break;
            }
            emit stateChanged("Retry: new server " + server);
        }
        host = server.section(':', 0, 0);
        m_currentHost = host;
        port = server.contains(':') ? server.section(':', 1, 1).toInt() : 443;
        // El server devuelve puertos alternativos (993) SOLO en los retries,
        // y ese puerto NO habla el protocolo M2XC (el handshake muere: "TCP
        // disconnected during handshake" / "No greeting"). El binario siempre
        // conecta a 443. Fuerzo 443 en cualquier puerto != 443.
        if (port != 443)
            port = 443;
        if (!inviteString.isEmpty()) {
            QString invHost = inviteString.section('|', 0, 0);
            if (invHost.contains(':')) {
                host = invHost.section(':', 0, 0);
                port = invHost.section(':', 1, 1).toInt();
            } else if (!invHost.isEmpty()) {
                host = invHost;
            }
        }
        for (int attempt = 0; attempt < 3 && !spawned && !m_stop && !aborted(); ++attempt) {
            if (attempt > 0) {
                emit stateChanged(QString("Retry TCP (attempt %1/3)...").arg(attempt + 1));
                // Stagger FIJO por cuenta: tras el fin de partida CTF global
                // (~40s) TODAS caen a la vez y reintentan juntas — 8 AUTH
                // simultaneos = corte anti-bot. El jitter aleatorio (1.5-4.5s)
                // se solapaba entre cuentas; un offset derivado del nombre
                // garantiza franjas separadas por cuenta (determinista).
                const quint32 h = qHash(m_deviceId) % 9; // 0..8 -> franja amplia
                // 2026-08-10 (test #39): 1-4.4s seguia dejando 4/10 cuentas
                // sin farming — el server saturado corta AUTHs cuando varias
                // cuentas reintentan en la misma ventana. Franja 2-10.6s.
                QThread::msleep(2000 + int(h) * 1000 + QRandomGenerator::global()->bounded(600));
                // 2026-08-10 (log del usuario 17:01-17:03): el retry reusaba
                // el MISMO host — con 5 cuentas cayendo en el mismo server
                // (s18313 repetido en Andy/Anisa/Deity/DeRene/Gear) los 3
                // intentos morian en cadena ("TCP disconnected during
                // handshake" masivo). Pedir OTRO server por HTTP connect en
                // cada retry: el matchmaking devuelve un server distinto.
                try {
                    int ciR;
                    { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ciR = m_connectIndex; }
                    QJsonObject connR = apiCall(&net, sk, magic, apiJson({ {"do", "connect"}, {"invite", false}, {"defered", true},
                                                                         {"i", ciR}, {"gm", -1}, {"retrying", true}, {"locale", "es_CO"} }));
                    QString serverR = connR.value("data").toObject().value("server").toString();
                    QString tokenR = connR.value("data").toObject().value("token").toString();
                    if (!serverR.isEmpty() && !tokenR.isEmpty()) {
                        // Si el matchmaking devuelve el MISMO server saturado
                        // (Gear recibio s18388 3 veces seguidas, test #38),
                        // cambiar de region ANTES del siguiente intento.
                        if (serverR == server) {
                            QString oldR;
                            { QMutexLocker lk(&m_sessionMutex); oldR = m_region; }
                            pickRandomRegion();
                            {
                                QMutexLocker lk(&m_sessionMutex);
                                if (m_region == oldR) {
                                    QStringList others;
                                    for (const QString &r : kFarmRegions)
                                        if (r != oldR) others << r;
                                    if (!others.isEmpty())
                                        m_region = others.at(QRandomGenerator::global()->bounded(int(others.size())));
                            }
                            }
                            QString curR2;
                            { QMutexLocker lk(&m_sessionMutex); curR2 = m_region; }
                            emit stateChanged("Retry: same server, switching to region " + curR2);
                            apiCall(&net, sk, magic, apiJson({ {"do", "servers"}, {"change", curR2} }));
                            connR = apiCall(&net, sk, magic, apiJson({ {"do", "connect"}, {"invite", false}, {"defered", true},
                                                                      {"i", ciR + 1}, {"gm", -1}, {"retrying", true}, {"locale", "es_CO"} }));
                            serverR = connR.value("data").toObject().value("server").toString();
                            tokenR = connR.value("data").toObject().value("token").toString();
                        }
                        if (!serverR.isEmpty() && !tokenR.isEmpty()) {
                            if (serverR == server)
                                ++sameServerCount;
                            else
                                sameServerCount = 0;
                            // El matchmaking re-asigna la sesion caida al MISMO
                            // server (Java: s18388 x6 en test #40). Reintentar
                            // el TCP es inutil; saltar al backoff de sesion.
                            if (sameServerCount >= 2) {
                                emit stateChanged("Retry: same server repetido - backoff de sesion");
                                break;
                            }
                            server = serverR;
                            m_authToken = tokenR;
                            host = server.section(':', 0, 0);
                            m_currentHost = host;
                            port = server.contains(':') ? server.section(':', 1, 1).toInt() : 443;
                            if (port != 443)
                                port = 443;
                            emit stateChanged("Retry: new server " + server);
                        }
                    }
                } catch (...) {}
            }
            sock->abort(); ircSock->abort();
            state = FarmState(); ircBuf.clear();
            // 2026-08-10: el connectToHost + waitForConnected + UDP init se
            // movieron DENTRO de spawnSession (bajo g_spawnMutex). Antes el
            // connect vivia aqui FUERA del lock: 10 sockets conectaban a la
            // vez y 9 quedaban abiertos esperando su turno de handshake; el
            // server cortaba esas conexiones inactivas. Ahora el server ve 1
            // conexion de la IP a la vez (como el binario).
            t0.start();
            QString err;
            if (spawnSession(sock.get(), &net, sk, magic, host, port, token, inviteString, uid, ctToken,
                             3, &err, &state, ircSock.get(), &ircBuf, true)) {
                spawned = true;
                int totalAttempts = attempt + 1 + regionAttempt * 3;
                if (totalAttempts > 1)
                    emit stateChanged(QString("SPAWNED after %1 attempt(s)").arg(totalAttempts));
            } else {
                spawnErr = err;
                emit stateChanged(QString("Spawn failed (attempt %1/3): %2").arg(attempt + 1).arg(err.left(120)));
                // 2026-08-11 (queja del usuario: "no deberia salir errores de
                // conexiones"): el fallo de spawn tras el fin de partida global
                // del CTF es NORMAL (el server corta todas las sesiones).
                emitLog(QString("reconnect: %1 (intento %2/3)").arg(err.left(80)).arg(attempt + 1));
            }
        }
    }
    if (!spawned) {
        // Spawn fallido (server sin respuesta, greeting timeout, red): el
        // farm NO muere (requisito: farmeo constante) — reintenta la sesion
        // completa (login + connect + spawn) con backoff. Solo abandona tras
        // 15 sesiones seguidas sin lograr spawnear (server caido de verdad).
        consecutiveSessionFailures++;
        // Sesion reutilizada fallando: forzar login fresco (ver el retry del equip)
        if (reuseSession && consecutiveSessionFailures >= 3) {
            { QMutexLocker lk(&m_sessionMutex); m_sk.clear(); m_magic.clear(); }
            emit stateChanged("Sesion reutilizada fallando - proximo intento con login fresco");
        }
        if (consecutiveSessionFailures >= 15) {
            fail(spawnErr.isEmpty() ? QString("TCP connect failed: %1 (no response after retries)").arg(server) : spawnErr);
            return;
        }
        emit stateChanged(QString("Spawn failed, retrying session in ~5s (%1/15)...")
                              .arg(consecutiveSessionFailures));
        // jitter + franja por cuenta (2026-08-10, test #39): el 4-7s fijo
        // hacia que las 10 cuentas reintentaran la sesion en la misma ventana;
        // el offset del device las separa 0-11s como el backoff de reconexion.
        {
            QMutexLocker lk(&m_sessionMutex);
            const int stg = (qHash(m_deviceId) % 12) * 1000;
            QThread::msleep(4000 + QRandomGenerator::global()->bounded(3000) + stg);
        }
        continue;
    }
    // sesion lograda: el contador de fallos se reinicia
    consecutiveSessionFailures = 0;
    postSpawnSequence(sock.get(), &net, sk, magic, &state, state.suffix);
    emitLog("NATIVE_PLAY [true,false] tras SPAWNED");
    // (el UDP queda SOLO en el INIT del handshake: el MOVE UDP periodico se
    // elimino — la XP del op 24 llega igual estando quieto, y el MOVE cada 1s
    // era ruido que el usuario pidio quitar. El server confirma con op 51 y
    // no exige movimiento para acreditar XP.)


    // (el handshake IRC de talk003.mitos.is vive dentro de spawnSession; el socket
    // queda abierto y su buffer en ircSock/ircBuf para el loop del farm de abajo)

    // loop principal
    bool readySent = true;    // READY ya se envio dentro de spawnSession
    bool nativeSent = true;   // NATIVE_PLAY ya se envio en postSpawnSequence
    bool matchEnded = false;  // partida terminada [33,null]: re-AUTH en el siguiente [20]
    QSet<int> seenOps;
    int totalFrames = 0;
    qint64 nextUpdateExp = t0.elapsed() + 60000; // el binario NO hace updateexp en los primeros 60s
    qint64 nextMmm = t0.elapsed() + 7000;        // el binario: mmm tag=2 a los ~7s del [20]
    // lectura HTTP de la XP de la gema con la MISMA cadencia de 60s del
    // updateexp (el server mueve cexp ~6 XP/s: ~+360 por lectura)
    nextGemXpRead = t0.elapsed() + 60000;
    qint64 nextMove = t0.elapsed() + 1000;        // MOVE keepalive (UDP) cada 1s
    // El binario NO envia MOVE (10022) por TCP: sus capturas (ctf_full.log,
    // match_end.log) muestran solo PONGs y NATIVE_PLAY en OUT TCP, y el run_client
    // M2XC advierte que el MOVE proactivo por TCP causa kick (10053). El movimiento
    // real del binario va por UDP (puerto 3724, opcode 0x002726) con los mismos
    // valores que el Python usa en send_udp_move. El op 24 EXPERIENCE_GAIN llega
    // igualmente estando quieto (match_end.log: +2070 XP a los 15s sin moves).
    // FIX 2026-08-11 v3 + v13 (causa raiz de los cortes): el tag del mmm del
    // binario es GLOBAL y CRECIENTE (frida_capture.log: tags 34->65+ sin reset
    // entre sesiones; cada ~10.5s +1). El bot lo reseteaba a 2 en cada run()
    // -> el server veia el tag volver a 2 -> detectaba la anomalia y cortaba.
    // v13: ademas el spawnOneFarm crea un FarmWorker NUEVO por ciclo, asi que
    // el tag de instancia se reiniciaba igualmente. Ahora persiste por
    // deviceId en un mapa ESTATICO del proceso (s_mmmTags).
    int mmmTag = mmmTagGet(m_deviceId);
    qint64 lastDeathTime = 0;
    qint64 lastPingAt = QDateTime::currentMSecsSinceEpoch(); // watchdog de respawn
    // v34: ultima actividad REAL de partida (op24 XP / op35 estado / op20).
    // El server no corta TCP ni envia op33 al terminar la partida; solo deja
    // de mandar XP. Este watchdog detecta la partida muerta y reconecta.
    qint64 lastMatchActivityAt = QDateTime::currentMSecsSinceEpoch();
    emit xpUpdate(state.xpTotal, state.xpLast, state.deaths, true);
    emit stateChanged("Farming CTF... (press Stop to stop)");
    // diagnostico 2026-08-10: el auto-buy no corria — verificar que el flag
    // llego al worker (headless/UI) y cuando se programa el primer chequeo
    emitLog(QString("Farm flags: autoRepair=%1 autoBuyX2=%2 nextBuy=%3s")
                .arg(m_autoRepair.load()).arg(m_autoBuyX2.load())
                .arg(m_nextAutoBuyX2 > 0 ? (m_nextAutoBuyX2 - QDateTime::currentMSecsSinceEpoch()) / 1000 : -1));
    // 2026-08-10 (pedido workflow): estado REAL inicial del x2 para el badge.
    // Si el auto-buy esta desactivado, el badge muestra "x2 ✗" con la razon
    // (antes quedaba en 0 y el QML lo ocultaba -> el indicador no existia).
    // Si esta ACTIVADO, la razon es "pendiente" (primer chequeo a los ~60s) —
    // antes la razon quedaba VACIA y el tooltip del QML decia "auto-buy
    // desactivado" aunque estuviera activado (bug reportado por el usuario).
    if (!m_autoBuyX2.load())
        setX2State(0, QStringLiteral("auto-buy x2 desactivado"));
    else
        setX2State(0, QStringLiteral("pendiente: primer chequeo en ~60s"));

    bool reconnect = false; // true = se perdio el TCP: nueva sesion (continue)
    // Watchdog de inactividad: el server pingea ~cada 2s (los PONGs del log).
    // Si no llega NINGUN frame en 15s la sesion esta muerta (o la red cayo)
    // aunque el socket local siga en ConnectedState (el RST del peer no
    // siempre llega: servidores que mueren sin FIN dejan el socket zombie).
    // Sin este watchdog el farm esperaba frames para siempre: sin XP, sin
    // reconectar, hasta el proximo refresh/stop manual.
    qint64 lastFrameMs = 0;
    // KEEPALIVE DE PARTIDA (causa raiz de las caidas ~12s post-[20], verificada
    // contra la captura del binario 2026-08-10): el binario re-envia NATIVE_PLAY
    // x2 con play HTTP previo cada ~7s (19169/19302ms, 26587/26740ms,
    // 32918/33058ms en scen_respawn.log). Sin ese keepalive el server CTF corta
    // la sesion en tiempos variables (3-40s) — el mmm era un falso sospechoso
    // (las caidas persistian con mmm ON uid, ON add-fijo y OFF).
    qint64 nextNativePlay = t0.elapsed() + 7000;
    while (!m_stop) {
        // el refresh (misma sesion) llega como evento queued del GUI: se procesa
        // aqui entre frames sin detener el farm. Mientras refreshXp corre el TCP
        // del farm queda sin atender ese rato (si el server lo kickea por el
        // cambio de modo, la reconexion de abajo lo levanta).
        QCoreApplication::processEvents(QEventLoop::AllEvents);
        // Abort de sesion pedido por el refresh (settle de XP): cierra el socket
        // desde ESTE hilo; el chequeo de desconexion de abajo espera a que el
        // refresh termine (m_refreshInProgress) y reconecta solo despues.
        if (m_abortSession.exchange(false))
            sock->abort();
        int len = 0, flag = 0;
        Bytes payload;
        bool got = recvFrame(sock.get(), 200, &len, &flag, &payload);
        qint64 now = t0.elapsed();
        if (lastFrameMs > 0 && now - lastFrameMs > 15000
            && sock->state() == QAbstractSocket::ConnectedState) {
            emit stateChanged("TCP watchdog: sin frames del server en 15s - reconectando...");
            sock->abort();
        }

        // procesar el chat IRC (socket separado): frames AMF3 string crudo,
        // responder PING -> PONG con makeIrcFrame (formato del binario)
        if (ircSock->state() == QAbstractSocket::ConnectedState) {
            QString ircLines = drainIrc(ircSock.get(), &ircBuf);
            if (!ircLines.isEmpty()) {
                QStringList lines = ircLines.split('\n', Qt::SkipEmptyParts);
                for (const QString &line : lines) {
                    if (line.startsWith("PING")) {
                        QString target = line.mid(5).trimmed();
                        Bytes pong = tcp::makeIrcFrame("PONG " + target);
                        ircSock->write(reinterpret_cast<const char *>(pong.data()), qint64(pong.size()));
                        ircSock->flush();
                        emitLog("IRC PONG -> " + target);
                    }
                }
            }
        }

        if (got && len > 0 && !payload.empty()) {
            lastFrameMs = now; // cualquier frame (PING incluido) = sesion viva
            tcp::AmfValue v;
            bool decoded = false;
            // los opcodes del handshake (52/53/40/20/51) llegan con flag=1 y AMF3
            // PLANO (sin cifrar) - el binario los procesa en el frame CLEAR
            if (flag == 1 && !payload.empty() && payload[0] <= 0x09) {
                tcp::Amf3Decoder d(payload);
                v = d.readValue();
                decoded = d.ok();
            } else if (flag != 1) {
                decoded = decodeFrame(payload, state.seed, &v);
                // FIX 2026-08-11 (causa raiz de los cortes en el PING #11): el
                // server avanza SU MT cada 10 PINGs y cifra el siguiente PING con
                // el seed NUEVO. El binario real lo detecta descifrando con el
                // seed avanzado (su PONG #11 cambia de cksum). El bot descifraba
                // con el seed viejo -> el PING #11 no se decodificaba -> sin PONG
                // -> corte ~10s despues del [20]. Retry con nextVal + rollback:
                if (!decoded && state.mt) {
                    std::uint32_t savedMt[624];
                    int savedIdx;
                    state.mt->saveState(savedMt, savedIdx);
                    std::uint32_t nextSeed = state.mt->nextVal() % 99999;
                    if (decodeFrame(payload, nextSeed, &v)) {
                        state.seed = nextSeed;
                        decoded = true;
                        writeWorkerLog(QString("SEED_SYNC: PING con seed nuevo, MT avanzado a %1").arg(nextSeed));
                    } else {
                        state.mt->restoreState(savedMt, savedIdx);
                    }
                }
            }
            // log de frames no decodificados (hex) - para detectar el kick/avisos
            if (!decoded && len > 0 && totalFrames > 0) {
                m_undecCount++;
                if (m_undecCount <= 10) {
                    QString hex = QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(payload.data()),
                                                                 int(payload.size())).toHex().left(80));
                    QString ascii = QString::fromLatin1(reinterpret_cast<const char *>(payload.data()),
                                                        int(payload.size())).left(40);
                    bool printable = true;
                    for (int i = 0; i < ascii.size(); ++i) {
                        if (ascii.at(i).toLatin1() < 32 && ascii.at(i) != '\n' && ascii.at(i) != '\r') {
                            printable = false;
                            break;
                        }
                    }
                    if (printable && !ascii.trimmed().isEmpty())
                        emitLog(QString("UNDEC[%1] flag=%2 len=%3: \"%4\"").arg(m_undecCount).arg(flag).arg(len).arg(ascii.trimmed()));
                    else
                        emitLog(QString("UNDEC[%1] flag=%2 len=%3 hex=%4").arg(m_undecCount).arg(flag).arg(len).arg(hex));
                }
                // FIX 2026-08-11 v3 (causa raiz de las sesiones cortas): el
                // server mata al jugador en partida con frames flag=1 del
                // formato interno 0x641b (len 100-300, serializacion Haxe del
                // binario) que el Amf3Decoder no entiende. El binario real los
                // procesa con su frame_processor y responde el respawn:
                // play HTTP + NATIVE_PLAY x1 (wlen=52) + updateexp ~1s despues
                // (captura frida_v3: muerte a 76223 -> play a 78648). El bot
                // NO los decodificaba -> no respawneaba -> el server cortaba
                // el TCP ~2-3s despues de cada muerte.
                // (v2 fallido: detectar cualquier 0x64 era flood — los 0x64
                // cortos son broadcasts de entidades de los otros jugadores.)
                // FIX 2026-08-11 v11 (EL ASESINO REAL): el detector 0x641b
                // disparaba MUERTE justo despues del SPAWNED+JOIN (el frame
                // 641b len=20 tras el op35 Welcome NO es una muerte: es el
                // frame normal de entidades del spawn). El respawn forzado
                // (play+NATIVE_PLAY) en ese momento mataba la sesion recien
                // iniciada (log 21:55:55: op35 -> MUERTE detectada -> corte).
                // El respawn real lo maneja el op 20 (RESPAWNED) y el
                // watchdog de 5s sin PINGs. DETECTOR DESACTIVADO.
                if (false && flag == 1 && state.spawned && !payload.empty()
                    && payload[0] == 0x64 && payload.size() >= 2 && payload[1] == 0x1b
                    && !matchEnded && now - m_lastRespawnAt > 8000) {
                    m_lastRespawnAt = now;
                    emitLog("MUERTE detectada (frame 0x641b) - respawn del binario (play+NATIVE_PLAY x1)");
                    state.deaths++;
                    lastDeathTime = 0;
                    try {
                        apiCall(&net, sk, magic, apiJson({{"do", "play"}, {"usertoken", QJsonValue()}}));
                    } catch (...) {}
                    sendFrame(sock.get(), tcp::makeNativePlayFrameFlag(state.seed,
                                                       state.spawnToken.isEmpty() ? randomNonce() : state.spawnToken,
                                                       state.suffix, false));
                    nextUpdateExp = now + 1000;
                    emit xpUpdate(state.xpTotal, state.xpLast, state.deaths, true);
                }
                // FIX 2026-08-11 v6: el reply equip ante CADA frame 0x64 empeoro
                // (test v5: prom 35s vs 55s). Los 0x64 son broadcasts de
                // entidades, NO mensajes de equip. El equip frame solo va en el
                // respawn (op 20) y en el postSpawn, como el binario real
                // (frida_flush.log: rafagas 56-69s y 409-418s = tras respawns).
            }
            if (decoded && v.type == tcp::AmfValue::Arr && !v.arr.empty()) {
                const auto &first = v.arr[0];
                if (first.type == tcp::AmfValue::Int || first.type == tcp::AmfValue::Double) {
                    int op = int(first.i);
                    if (first.type == tcp::AmfValue::Double)
                        op = int(first.d);
                    totalFrames++;
                    if (!seenOps.contains(op)) {
                        seenOps.insert(op);
                        emitLog(QString("op %1 (frames=%2, seed=%3)").arg(op).arg(totalFrames).arg(state.seed));
                    }
                    // PING -> seed + PONG. El MT avanza CADA 10 PINGs (como el binario):
                    // PING #1, #11, #21... El PONG se envia siempre con el seed actual.
                    if (op == 1 && state.mt) {
                        state.pingCount++;
                        lastPingAt = QDateTime::currentMSecsSinceEpoch(); // watchdog de respawn
                        writeWorkerLog(QString("PING #%1 seed=%2 len=%3").arg(state.pingCount).arg(state.seed).arg(payload.size()));
                        // El seed se sincroniza SOLO en el decode (SEED_SYNC):
                        // el server cifra cada 10 PINGs con el seed del MT
                        // avanzado, y el retry del decode lo detecta.
                        double pingTs = 0;
                        if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Double)
                            pingTs = v.arr[1].d;
                        else if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Int)
                            pingTs = double(v.arr[1].i);
                        if (pingTs <= 0)
                            pingTs = double(QDateTime::currentMSecsSinceEpoch());
                        emit debugLog(QString("TCP >> PONG [10001.0, ts, %1] seed=%2 chk=%3")
                                          .arg(state.seed % 100).arg(state.seed).arg(state.seed % 63));
                        sendFrame(sock.get(), tcp::makePongFrame(state.seed, pingTs));
                    } else if (op == 4 && v.arr.size() >= 2) {
                        if (v.arr[1].type == tcp::AmfValue::Int) {
                            state.playerId = QString::number(v.arr[1].i);
                            emitLog("PLAYER_ID " + state.playerId);
                            // El UDP del binario no se replica: su payload exacto no
                            // se puede capturar (el hook muestra len=0) y el datagrama
                            // del C++ genera op 11 (DAMAGE) con kick posible.
                        }
                    } else if (op == 52 && v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Str) {
                        emitLog("Desafio seguro recibido, enviando PROOF TPM...");
                        // challenge_roundtrip HTTP (el binario envia el challenge al
                        // engine y recibe el plaintext de 8 chars)
                        // FIX 2026-08-11 (PROOF rechazado -> corte): el roundtrip
                        // NO debe esperar g_loginMutex (con 9 cuentas se cuelga y
                        // nonceRt queda vacio -> PROOF con nonce incorrecto).
                        QString nonceRt;
                        try {
                            QString u = kEngine + "?_sid=" + urlEncodeTcp(sk, false) + "&rndx=" + rndxTcp();
                            QByteArray rt = httpPostTcp(&net, QUrl(u), v.arr[1].s.toUtf8(), &m_stop, 3000);
                            QString t = QString::fromUtf8(rt).trimmed();
                            if (t.size() == 8) {
                                nonceRt = t;
                                emitLog("Challenge roundtrip HTTP OK: " + t);
                            } else {
                                emitLog("Challenge roundtrip HTTP raro (len=" + QString::number(t.size()) + "): '" + t.left(20) + "'");
                            }
                        } catch (const std::exception &e) {
                            emitLog("Challenge roundtrip HTTP fallo: " + QString::fromUtf8(e.what()).left(60));
                        }
                        QFile pf(m_pemPath);
                        if (pf.open(QIODevice::ReadOnly)) {
                            QString pem = QString::fromUtf8(pf.readAll());
                            pf.close();
                            try {
                                QString proofStr;
                                Bytes pfrm = tcp::makeProofFrame(v.arr[1].s, state.suffix, m_deviceId, state.seed, pem, &proofStr, nonceRt);
                                emit debugLog(QString("TCP >> PROOF TPM seed=%1 chk=%2 device=%3 proofh=%4")
                                                  .arg(state.seed).arg(state.seed % 63).arg(m_deviceId.left(16)).arg(proofStr.left(10)));
                                sendFrame(sock.get(), pfrm);
                            } catch (const std::exception &e) {
                                emitLog("PROOF ERR: " + QString::fromUtf8(e.what()));
                            }
                        }
                    } else if (op == 28) {
                        // FIX v6: NO responder al op 28 con el equip frame VACIO
                        // (config 17:45, la mejor, no tenia este handler). El
                        // server espera el equip con datos reales (4716-5100B);
                        // el [10037,[]] vacio del bot daña. Solo log.
                        emitLog("op 28 (equipment request) - sin reply (vacio dania)");
                    } else if (op == 51) {
                        // El 51 pre-spawn [51,0] es CONFIRM_UDP del server: el binario
                        // NO responde nada (ctf_full.log 6371ms: [51,0] sin OUT hasta el
                        // READY; match_end.log: solo PONGs). Enviar 10033 hace que el
                        // server responda op 10/11 y corte a los ~20s.
                        if (state.spawned) {
                            // El [51,X] NO es una muerte (scen.log): es un contador de
                            // ticks del server que crece siempre (34, 62, 81...) y nunca
                            // llega a 0. La muerte real se ve en el op 11 repetido + el
                            // respawn automatico [25]+[24]+[20]. No hay que enviar nada.
                            if (v.arr.size() >= 2 && v.arr[1].type == tcp::AmfValue::Int)
                                emitLog("op 51=" + QString::number(v.arr[1].i) + " (tick del server, no es muerte)");
                        }
                    } else if (op == 53 || op == 40) {
                        // FIX 2026-08-11 v9+v28: op53 = SPAWN TOKEN -> capturarlo
                        // para el op5 JOIN. v28: guardar el payload CRUDO (el
                        // JOIN re-cifra el op53 completo, no el string).
                        if (op == 53 && v.arr.size() >= 2) {
                            if (v.arr[1].type == tcp::AmfValue::Str)
                                state.spawnToken = v.arr[1].s;
                            else if (v.arr[1].type == tcp::AmfValue::Int)
                                state.spawnToken = QString::number(v.arr[1].i);
                            else if (v.arr[1].type == tcp::AmfValue::Double)
                                state.spawnToken = QString::number(v.arr[1].d);
                            state.spawnTokenRaw = payload;
                            emitLog("SPAWN TOKEN (op53): " + state.spawnToken.left(20)
                                    + " raw=" + QString::fromLatin1(QByteArray(reinterpret_cast<const char *>(payload.data()), int(payload.size())).toHex().left(32)));
                        }
                        if (!readySent) {
                            // Orden exacto del binario (captura ctf_full.log):
                            // 53 (6421ms) -> inventory(ingame,slot=3) HTTP (8038ms)
                            // -> READY [10000,[true,1920,1080,1,true]] (8039ms) -> 40 -> 20.
                            // El binario NO envia CLEAR/10002/10037 en este punto.
                            try {
                                apiCall(&net, sk, magic, apiJson({{"do", "inventory"}, {"ingame", true}, {"slot", 3}}));
                            } catch (...) {}
                            QThread::msleep(1500);
                            emit debugLog(QString("TCP >> READY [10000,[true,1920,1080,1,true]] seed=%1 chk=%2").arg(state.seed).arg(state.seed % 63));
                            sendFrame(sock.get(), tcp::makeReadyFrame(state.seed));
                            readySent = true;
                            emitLog("READY tras inventory(ingame)");
                        }
                        if (op == 40 && !nativeSent) {
                            // El binario NO responde nada al 40 (resume_key). La
                            // secuencia play/NATIVE_PLAY/gamemode va DESPUES del [20]
                            // SPAWNED (ctf_full.log: 40=8267 20=8268 play=11922).
                            // Se ejecuta en el handler del op 20.
                            emitLog("Resume key (40) recibido");
                        }
                    } else if (op == 20) {
                        lastMatchActivityAt = now; // v34: SPAWNED = partida activa
                        if (matchEnded && m_autoRespawn) {
                            // Partida terminada (match_end.log): [33,null] + [20] -> el
                            // binario hace news -> openchest -> userinfo -> i18n ->
                            // connect(i+1, gm=-1) -> AUTH M2XC -> 52 -> PROOF -> 53 ->
                            // READY -> 40 -> 20. Abre la sala de nuevo con re-AUTH.
                            matchEnded = false;
                            emitLog("Match ended (33) - full re-AUTH");
                            try {
                                apiCall(&net, sk, magic, apiJson({{"do", "news"}}));
                                int ci6;
                                { QMutexLocker lk(&m_sessionMutex); m_connectIndex += 1; ci6 = m_connectIndex; }
                                httpApi(&net, sk, magic, apiJson({{"do", "connect"}, {"invite", false}, {"defered", true},
                                                                    {"i", ci6}, {"gm", -1}, {"retrying", false}, {"locale", "es_CO"}}));
                            } catch (...) {}
                            QString authBody2;
                            Bytes authFrame2 = tcp::makeAuthFrame(host, state.suffix, m_authToken, 3, m_inviteString, &authBody2);
                            {
                                QMutexLocker locker(&g_loginMutex); // QNetworkRequest internos
                                QString u2 = kEngine + "?_sid=" + urlEncodeTcp(sk, false) + "&rndx=" + rndxTcp();
                                httpPostTcp(&net, QUrl(u2), authBody2.toUtf8());
                            }
                            emit debugLog(QString("TCP >> AUTH match_end i=%1 (wlen=%2)").arg(m_connectIndex).arg(authFrame2.size()));
                            sendFrame(sock.get(), authFrame2);
                            // resetear el flujo: el server enviara 52 -> proof -> 53 -> READY -> 40 -> 20
                            readySent = false;
                            nativeSent = false;
                            state.spawned = false;
                        } else if (state.spawned) {
                            // Respawn tras muerte (op 20): el binario REAL (captura
                            // frida_v3 2026-08-11, 275 frames OUT) en el respawn hace
                            // SOLO: play HTTP + NATIVE_PLAY wlen=52 + updateexp HTTP
                            // ~1s despues + mmm. NADA de inventory/news/gamemode/
                            // equip/repair/checkX2: el flood HTTP del postSpawnSequence
                            // anterior era lo que el server detectaba y cortaba en la
                            // 3ra-5ta muerte (cortes en multiplos de ~14s = ciclo de
                            // muerte CTF). El equip/repair ya se hizo en el spawn.
                            // FIX v6: sin equip frame aqui (el [10037,[]] vacio del
                            // bot empeoro; el frame grande con datos no se puede
                            // generar). Config de la corrida 17:45 (prom 87s).
                            state.deaths++;
                            lastDeathTime = 0;
                            emitLog(QString("RESPAWNED #%1 (op 20) - secuencia minima del binario").arg(state.deaths));
                            // FIX 2026-08-11 v8 (el server corta en el mmm del respawn):
                            // el binario real envia un mmm con add="" JUSTO ANTES del
                            // play de cada respawn (frida_capture.log: mmm "" tag 40 a
                            // 64277ms -> play a 64322; "" tag 41 a 74989 -> play 77305).
                            // El bot mandaba solo null -> el server cortaba en el mmm
                            // siguiente (tag=6 = corte en el MISMO segundo, log 21:03:19).
                            if (!uid.isEmpty()) {
                                try {
                                    int preTag = mmmTagGet(m_deviceId);
                                    apiCall(&net, sk, magic, apiJson({{"do", "mmm"}, {"begin", false}, {"serching", false},
                                                                         {"add", QString("[%1,\"\",100,0]").arg(uid)}, {"tag", preTag},
                                                                         {"abandon", false}, {"mode", -1}, {"stop", false}}));
                                    mmmTagSet(m_deviceId, preTag + 1);
                                    emitLog("mmm add=\"\" pre-respawn tag=" + QString::number(preTag));
                                } catch (...) {}
                            }
                            try {
                                apiCall(&net, sk, magic, apiJson({{"do", "play"}, {"usertoken", QJsonValue()}}));
                            } catch (...) {}
                    sendFrame(sock.get(), state.spawnTokenRaw.empty()
                        ? tcp::makeNativePlayFrameFlag(state.seed,
                                                       state.spawnToken.isEmpty() ? randomNonce() : state.spawnToken,
                                                       state.suffix, false)
                        : tcp::makeNativePlayFrameKeyedRaw(state.seed, state.spawnTokenRaw, bytesOf(state.suffix), false));
                            // el binario hace updateexp ~1s tras el play/respawn
                            nextUpdateExp = now + 1000;
                            emit xpUpdate(state.xpTotal, state.xpLast, state.deaths, true);
                        } else if (!state.spawned) {
                            state.spawned = true;
                            // secuencia post-SPAWNED completa del binario
                            // (inventory/news/equip/play + NATIVE_PLAY [true/false] + gamemode)
                            postSpawnSequence(sock.get(), &net, sk, magic, &state, state.suffix);
                            nativeSent = true;
                            emitLog("NATIVE_PLAY [true,false] tras SPAWNED");
                            // el binario (captura frida_v3): mmm tag=2 a los ~1.5s del
                            // [20], updateexp ~1s despues del play (65414ms tras play
                            // 64457; 79960 tras play 78648), NUNCA a los 60s.
                            nextMmm = now + 1500;
                            nextUpdateExp = now + 1000;
                            nextGemXpRead = now + 60000; // XP de la gema por HTTP: lectura del cexp, no updateexp
                            if (m_nextFullRefresh < 0)
                                m_nextFullRefresh = QDateTime::currentMSecsSinceEpoch() + 600000; // v35: refresh completo cada 10 min
                            // 2026-08-10 (fix auto-buy): programar el primer
                            // chequeo desde el SPAWNED con RELOJ REAL (el
                            // t0.elapsed() se reinicia en cada reconexion y el
                            // chequeo de 60s nunca alcanzaba).
                            if (m_nextAutoBuyX2 < 0)
                                m_nextAutoBuyX2 = QDateTime::currentMSecsSinceEpoch() + 60000;
                            emit xpUpdate(state.xpTotal, state.xpLast, state.deaths, true);
                        }
                    } else if (op == 24 && v.arr.size() >= 2) {
                        double xp = 0;
                        if (v.arr[1].type == tcp::AmfValue::Int)
                            xp = double(v.arr[1].i);
                        else if (v.arr[1].type == tcp::AmfValue::Double)
                            xp = v.arr[1].d;
                        state.xpTotal += xp;
                        state.xpLast = xp;
                        m_sessionXpTotal = state.xpTotal;
                        lastMatchActivityAt = now; // v34: partida viva (XP llega)
                        emit debugLog(QString("XP +%1 (total %2)").arg(xp, 0, 'f', 1).arg(state.xpTotal, 0, 'f', 1));
                        emit xpUpdate(state.xpTotal, state.xpLast, state.deaths, state.spawned);
                    } else if (op == 35 || op == 10) {
                        // v34: op35 = PLAYER_STATUS, op10 = MAP — actividad de partida
                        lastMatchActivityAt = now;
                        // log del contenido: el binario recibe la XP de la gema como
                        // [35, [-1, "Has obtenido +XP"]] + [10, [26, ...]] (match_end.log)
                        QString dataStr;
                        std::function<QString(const tcp::AmfValue &)> valToStr =
                            [&](const tcp::AmfValue &a) -> QString {
                            switch (a.type) {
                            case tcp::AmfValue::Null: return QStringLiteral("null");
                            case tcp::AmfValue::Bool: return a.b ? QStringLiteral("true") : QStringLiteral("false");
                            case tcp::AmfValue::Int: return QString::number(a.i);
                            case tcp::AmfValue::Double: return QString::number(a.d, 'g', 12);
                            case tcp::AmfValue::Str: return "\"" + a.s.left(120) + "\"";
                            case tcp::AmfValue::Arr: {
                                QStringList items;
                                for (const auto &e : a.arr)
                                    items << valToStr(e);
                                return "[" + items.join(",") + "]";
                            }
                            }
                            return QString();
                        };
                        for (const auto &e : v.arr)
                            dataStr += (dataStr.isEmpty() ? QString() : QStringLiteral(",")) + valToStr(e);
                        emit debugLog(QString("op %1 [%2]").arg(op).arg(dataStr.left(240)));
                    } else if (op == 21 && v.arr.size() >= 2) {
                        double coins = 0;
                        if (v.arr[1].type == tcp::AmfValue::Int)
                            coins = double(v.arr[1].i);
                        else if (v.arr[1].type == tcp::AmfValue::Double)
                            coins = v.arr[1].d;
                        state.coinsTotal += coins;
                    } else if (op == 33) {
                        // Partida terminada (match_end.log): [33,null] llega justo antes
                        // del [20] final y SOLO en el fin de partida (scen.log no tiene
                        // ningun 33 en las muertes simples). Marcar para re-AUTH.
                        matchEnded = true;
                        emitLog("op 33 (partida terminada) - re-AUTH en el proximo 20");
                    } else if (op == 11) {
                        // op 11 = BROADCAST de muerte de OTRO jugador (modelo
                        // validado 2026-08-09 en room_keepalive.py, 9 cuentas
                        // 300s con 29 respawns): el binario NUNCA recibe op 11
                        // propio (8 muertes en 90s sin un solo op 11) — el
                        // server reporta la muerte propia directo con el [20]
                        // de respawn. Las cuentas del farm comparten sala CTF y
                        // cada muerte ajena llega como op 11: marcarlo como
                        // muerte propia inflaba state.deaths y el flag
                        // spawned=false abria la puerta a confirmar el respawn
                        // de OTRA cuenta. NO tocar estado: solo log.
                        emitLog("op 11 (broadcast de otro jugador) - el server respawnea solo con [20]");
                    } else if (op != 16 && op != 2 && op != 19 && op != 10 && op != 35 && op != 1) {
                        emitLog("op " + QString::number(op));
                    }
                }
            }
        }

        // READY + NATIVE_PLAY ya se manejan dentro del handler de opcodes.
        // El binario NO envia PING/MOVE proactivos: solo responde PONGs a cada
        // PING (run_client: "Enviar PING/MOVE proactivos causa que el servidor
        // kickee 10053"). El MOVE UDP periodico se elimino (ver arriba): la XP
        // del op 24 llega igual estando quieto (match_end.log: +2070 XP sin
        // moves) y el server no exige movimiento para acreditar.
        // updateexp: SOLO tras play/respawn (~1s, como el binario frida_v3:
        // 65414 tras play 64457, 79960 tras play 78648). El binario NO repite
        // updateexp cada 60s: 0 apariciones en 466s de captura. El periodico
        // de 60s era otro trafico que el server no esperaba del cliente real.
        // if (now >= nextUpdateExp) {
        //     QJsonObject ue = apiCall(&net, sk, magic, apiJson({{"do", "updateexp"}}));
        //     emitLog("updateexp: " + QString::fromUtf8(QJsonDocument(ue.value("data").toObject()).toJson()).left(120));
        //     nextUpdateExp = now + 60000;
        // }
        // lectura HTTP exclusiva de la XP de la gema (inventory slot=5) cada
        // 60s: el op 24 TCP es XP del jugador/partida y NO se usa para las
        // gemas. El controller acumula con gemXpRead (delta entre lecturas).
        // FIX 2026-08-11 v27: RESTAURADA la lectura de XP (inventory slot=5
        // cada 60s). La XP de la gema se acumula en el server y el bot debe
        // leerla para reportarla; sin esto el farm "funciona" pero nunca se
        // ve la XP ganada (el op24 EXPERIENCE_GAIN llega al settle, no en
        // vivo). 1 HTTP/60s no afecta la sesion.
        if (now >= nextGemXpRead) {
            try {
                QJsonObject invResp = apiCall(&net, sk, magic, apiJson({{"do", "inventory"}, {"slot", 5}}));
                qlonglong cexpOut = -1, expOut = -1;
                if (readGemXp(invResp, &cexpOut, &expOut) && cexpOut >= 0) {
                    emit debugLog(QString("Gem XP (HTTP): cexp=%1 exp=%2").arg(cexpOut).arg(expOut));
                    emit gemXpRead(cexpOut, expOut);
                    emitLog(QString("GEM XP cexp=%1 exp=%2").arg(cexpOut).arg(expOut));
                }
            } catch (...) {}
            nextGemXpRead = now + 60000;
        }
        // mmm periodico cada ~10.5s: el binario ALTERNA null/"" en el add
        // (frida_capture.log tags 34-43: null,"","","",null,null,"","",null,null
        // = bloques de 2-3). El bot mandaba SIEMPRE null -> el server lo
        // detectaba como patron de bot y cortaba en el mmm (log: el corte
        // llega en el MISMO segundo del mmm, ej. 22:06:29 mmm tag=6 -> corte).
        // FIX v12: alternar null/"" como el binario ("" = lobby/matchmaking,
        // null = partida estable; el bot alterna porque el server espera
        // ambos estados).
        if (now >= nextMmm && !uid.isEmpty()) {
            try {
                const bool usarVacio = (mmmTag % 4 == 0 || mmmTag % 4 == 1);
                QJsonObject mmmBody = apiJson({ {"do", "mmm"}, {"begin", false}, {"serching", false},
                                                {"add", usarVacio
                                                    ? QString("[%1,\"\",100,0]").arg(uid)
                                                    : QString("[%1,null,100,0]").arg(uid)},
                                                {"tag", mmmTag},
                                                {"abandon", false}, {"mode", -1}, {"stop", false} });
                apiCall(&net, sk, magic, mmmBody);
                emitLog(QString("mmm tag=%1 add=%2").arg(mmmTag).arg(usarVacio ? "\"\"" : "null"));
                ++mmmTag;
                mmmTagSet(m_deviceId, mmmTag);
            } catch (...) {}
            nextMmm = now + 10500;
        }

        // MOVE keepalive SOLO UDP (validado en el test #10: drain de PONGs +
        // UDP MOVE dio 20-30s de vida vs 3-7s antes). El TCP MOVE [10022]
        // KICKEA al instante (test #11: caidas 0-13s — el run_client M2XC
        // advierte kick 10053; el binario NO manda MOVE por TCP: captura OUT
        // TCP = solo PONGs y NATIVE_PLAY). El UDP (3724, 0x002726) mantiene
        // FIX DEFINITIVO 2026-08-11 (analisis de la captura frida_flush.log del
        // binario REAL en partida): el cliente real NO envia UDP MOVE (0
        // datagramas en la captura; solo TCP PONG wlen=24 + mmm HTTP). El UDP
        // MOVE del headless_bot.py era del bot Python, no del binario real.
        // Eliminado: el server no espera esos datagramas y podian ser la causa
        // de los cortes. Se conserva el UDP INIT del handshake (el server lo
        // confirma con op 51) pero NO el MOVE periodico cada 1s.
        // FIX DEFINITIVO 2026-08-11 (analisis de la captura frida_flush.log del
        // binario REAL en partida): el cliente real SOLO envia wlen=24 (PONG)
        // cada ~2s + wlen=4884/5076 al cambiar equip. NUNCA wlen=52 (NATIVE_PLAY)
        // periodico: 0 apariciones en 545 frames de partida real. El NATIVE_PLAY
        // solo va en spawn/respawn (postSpawn). El keepalive con play+NATIVE_PLAY
        // cada 7s que añadi antes era ANOMALO: el server lo detecta y corta.
        // El PONG ya se responde en el handler del op 1 (el server pingea cada
        // 2s y el loop responde). El mmm cada 10.5s tambien se mantiene.
        // NO se envia nada mas en el keepalive: imitar al binario real.

        // WATCHDOG DE RESPAWN (2026-08-11, queja del usuario: "si matan la
        // cuenta que vuelva a entrar inmediatamente"): el server deberia
        // enviar el [20] de respawn solo tras la muerte, pero si no llega,
        // la cuenta queda muerta en el limbo. Si llevamos Ns sin PINGs
        // (op 1) estando spawnados, forzar el respawn con play + NATIVE_PLAY
        // (igual que la secuencia validada del respawn).
        // FIX 2026-08-11 v8 (cortes a los ~30-60s): el server DEJA DE
        // PINGUEAR al jugador muerto y corta a los ~6-10s si no recibe el
        // play de respawn (log 21:23:03 mmm -> 21:23:09 corte = 6s sin
        // PINGs). El binario real respawnea 2.4s tras la muerte (frida_v3:
        // muerte 76224 -> play 78648). El watchdog de 20s era DEMASIADO
        // TARDE: el server ya habia cortado. Reducido a 5s.
        if (state.spawned && m_autoRespawn && now - lastPingAt >= 5000) {
            emitLog("WATCHDOG: 5s sin PINGs - forzando respawn");
            try {
                apiCall(&net, sk, magic, apiJson({{"do", "play"}, {"usertoken", QJsonValue()}}));
                sendFrame(sock.get(), state.spawnTokenRaw.empty()
                    ? tcp::makeNativePlayFrameFlag(state.seed,
                                                   state.spawnToken.isEmpty() ? randomNonce() : state.spawnToken,
                                                   state.suffix, false)
                    : tcp::makeNativePlayFrameKeyedRaw(state.seed, state.spawnTokenRaw, bytesOf(state.suffix), false));
                emitLog("WATCHDOG: play + JOIN enviados (respawn forzado)");
            } catch (...) {}
            lastPingAt = now;
        }
        // FIX 2026-08-11 v34+v36 (fin de partida SIN corte TCP - dato del test
        // manual del usuario): cuando la partida CTF termina o el jugador
        // muere, el server NO corta el TCP y NO envia op33 (TEAM_GAME_ENDED)
        // — solo deja de enviar op24 (EXPERIENCE_GAIN) y op35 (PLAYER_STATUS).
        // El bot quedaba colgado respondiendo PONGs a una partida muerta
        // (respawns de 100-300s). Watchdog de ACTIVIDAD: si llevamos 10s
        // spawnados sin op24/op35/op20, la partida termino o el jugador
        // murio -> reconectar inmediatamente (el op24 llega cada ~2-5s en
        // partida viva).
        if (state.spawned && m_autoRespawn && now - lastMatchActivityAt >= 10000) {
            emitLog("WATCHDOG: 10s sin XP/estado de partida - reconectando");
            lastMatchActivityAt = now;
            lastPingAt = 0; // fuerza el bloque de reconexion TCP
            sock->abort();
            continue;
        }
        // FIX 2026-08-11 v35 (pedido del usuario): REFRESH COMPLETO cada
        // 600s. Verifica: (1) XP ganada (inventory slot=5), (2) gema rota
        // por durabilidad -> reparar, (3) gema desaparecida -> equipar otra
        // segun la gem priority, (4) x2 activo -> si no, recomprar.
        if (now >= m_nextFullRefresh) {
            m_nextFullRefresh = QDateTime::currentMSecsSinceEpoch() + 600000;
            emitLog("REFRESH 600s: verificando gema + x2");
            try {
                QJsonObject invR = apiCall(&net, sk, magic, apiJson({ {"do", "inventory"}, {"slot", 5} }));
                const QJsonArray items = invR.value("data").toObject().value("items").toArray();
                const int activeId = invR.value("data").toObject().value("current").toInt(-1);
                bool gemFound = false;
                int gemDur = -1;
                for (const auto &iv : items) {
                    const QJsonObject item = iv.toObject();
                    if (item.value("id").toInt() == m_gemItem) {
                        gemFound = true;
                        gemDur = item.value("durability").toInt();
                        break;
                    }
                }
                if (!gemFound && activeId != m_gemItem) {
                    // La gema desaparecio (limite de XP -> a la tienda):
                    // equipar la siguiente de la gem priority.
                    emitLog("REFRESH: gema " + QString::number(m_gemItem) + " desaparecida - equipando otra segun prioridad");
                    if (!m_gemPriorityList.isEmpty())
                        switchToNextGem(&net, sk, magic, items);
                } else if (gemDur <= 0 && m_autoRepair.load()) {
                    // Gema rota por durabilidad -> reparar
                    emitLog(QString("REFRESH: gema %1 rota (dur=%2) - reparando").arg(m_gemItem).arg(gemDur));
                    try {
                        QJsonObject rep = apiCall(&net, sk, magic, apiJson({ {"do", "repair"}, {"item", m_gemItem}, {"slot", 5} }));
                        emitLog("REFRESH repair: " + rep.value("message").toString().left(50));
                    } catch (...) {}
                }
                // x2: verificar activo y recomprar si expiro
                if (m_autoBuyX2.load())
                    checkX2(&net, sk, magic);
            } catch (...) {}
        }

        // (MOVE keepalive SOLO UDP cada 1s: el TCP [10022] KICKEA — captura
        // del binario 2026-08-10: 0 apariciones de 10022 en OUT TCP; el bloque
        // viejo que mandaba makeTcpMove cada 1s era el kick 10053. El UDP
        // (3724, 0x002726) con valores AFK (34.0, -3.084, 0.9309) mantiene la
        // sesion sin mover.)
        // Auto-buy x2: cada 5 minutos, consultar la tienda y comprar gemas x2
        // (multiplicador de XP x2 por 24h) si hay coins suficientes.
        // 2026-08-10 (pedido del usuario: deteccion paupérrima -> binaria):
        // toda la logica vive en checkX2() — se llama INMEDIATO en postSpawn
        // (el badge dice verde/rojo a los segundos del [20], no a los 60s) y
        // aqui cada 5 min con reloj real (miembro persistente del worker).
        // FIX 2026-08-11 v7 (datos de 5 corridas): SIN checkX2 las sesiones
        // empeoran (19:42: prom 45s, 19:48: 49s) vs CON checkX2 (17:45: 87s,
        // 18:40: 75s, 19:29: 78s con max 414s). El server espera ese trafico
        // HTTP periodico del cliente real. RESTAURADO.
        if (m_nextAutoBuyX2 >= 0
            && QDateTime::currentMSecsSinceEpoch() >= m_nextAutoBuyX2) {
            m_nextAutoBuyX2 = QDateTime::currentMSecsSinceEpoch() + 300000; // 5 minutos
            checkX2(&net, sk, magic);
        }

        // deteccion de perdida de conexion TCP: si el socket se desconecto,
        // reconectar desde cero (login + connect + spawn) hasta que el usuario pare.
        // Si el refresh corre en paralelo, esperar a que termine: el cambio de
        // modo del refresh puede kickear el TCP del farm, y reconectar en medio
        // del spawn FFA del refresh haria que ambas sesiones se pisen.
        if (!m_stop && sock->state() != QAbstractSocket::ConnectedState) {
            while (!m_stop && m_refreshInProgress.load()) {
                QCoreApplication::processEvents(QEventLoop::AllEvents);
                QThread::msleep(300);
            }
            if (!m_stop)
                emit stateChanged("TCP connection lost - reconnecting...");
            sock->abort();
            // BACKOFF ADAPTATIVO (modelo del multi_test Python validado 9/9 a
            // 300s, room_keepalive.py:1216-1227): sesion <2s -> el server
            // rechazo casi de inmediato, doblar la espera (max 60s) para dejar
            // entrar a las demas; sesion >=10s -> la cuenta entro bien, reset
            // a 4s. Evita que TODAS reintenten juntas tras el fin de partida
            // global (el server corta los handshakes simultaneos).
            {
                QMutexLocker lk(&m_sessionMutex);
                const qint64 durMs = t0.elapsed();
                if (durMs < 2000)
                    m_sessionBackoffMs = qMin(m_sessionBackoffMs * 2, 60000);
                else if (durMs >= 10000)
                    m_sessionBackoffMs = 2500; // v25: mas rapido (antes 4000)
                // STAGGER por cuenta (test #32: tras el fin de partida global
                // TODAS caen a la vez y reintentaban juntas -> el server cortaba
                // los handshakes; el multi_test Python espaciaba 2s por cuenta).
                // 2026-08-10 (queja del usuario: "muchos errores TCP"): con
                // qHash%12 (0-11s) 10 cuentas seguian entrando en la misma
                // ventana. Subido a %31 (0-30s): el server ve 1 conexion de la
                // IP cada ~3s, como el binario con una sola cuenta reconectando.
                // 2026-08-11 (queja del usuario: "deberia imitar una partida
                // normal: play y quedarse, reconectar solo si lo matan"): el
                // stagger de 0-30s agregaba ~15s de downtime en cada fin de
                // partida global del CTF (las partidas duran ~40-50s y el
                // server corta a todos). El jugador real reconecta al
                // instante a la partida siguiente. Reducido a 0-15s: suficiente
                // para no saturar los handshakes (el server ve 1 conexion
                // cada ~2s) sin el downtime de 30s.
                // FIX 2026-08-11 v25 (Jo/Ren: "mandarlas al mismo server y
                // rapido"): con TODAS las cuentas al mismo server, el stagger
                // de 0-15s agrega ~7.5s de downtime por reconexion. Reducido
                // a 0-6s: el g_spawnMutex ya serializa los handshakes TCP (1
                // a la vez), el stagger solo evita el login HTTP simultaneo.
                const int staggerMs = (qHash(m_deviceId) % 7) * 1000;
                const int waitMs = m_sessionBackoffMs + QRandomGenerator::global()->bounded(1000) + staggerMs;
                emitLog(QString("Reconnect backoff %1s (session was %2s, stagger %3s)").arg(waitMs / 1000).arg(durMs / 1000).arg(staggerMs / 1000));
                QThread::msleep(waitMs);
            }
            reconnect = true;
            break;
        }
    }

    if (reconnect)
        continue; // nueva sesion: objetos frescos, region/sesion conservadas
    sock->disconnectFromHost();
    {
        QMutexLocker lk(&m_socketMutex);
        m_activeSock = nullptr;
    }
    emit stateChanged("Stopped. Total XP " + QString::number(state.xpTotal));
    // Unificado con los demas exits de stop: parada manual/loop agotado NO es
    // un fin exitoso del farm (antes finishedOk(true) confundia al controller).
    emit finishedOk(false, "stopped");
    return;
    }
    emit finishedOk(false, "stopped");
}



