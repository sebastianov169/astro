// farm_controller.cpp - puente QML <-> FarmWorker (spawn/stop/refresh/gemas/logs)
#include "farm_controller.h"

#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QDateTime>
#include <QTimer>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QStandardPaths>
#include <QSettings>
#include <QUrl>
#include <QSharedPointer>
#include <QGuiApplication>
#include <QClipboard>

#include <algorithm>

#include <atomic>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {
// Device id de la cuenta del farm (fallback si no hay qw.sol de la instalacion)
const char *kDefaultDevice = "2FlhMEfW^RHppjs-C321CXGu.CGC8JEAq34RYE1YCGRyIlXrln2VKpK7-HtGms;3";

// Maximo de cuentas seleccionables para farmear a la vez (S2: antes
// hardcodeado en 3 sitios).
constexpr int kMaxFarmSelection = 10;

// Resultado de UN login de pre-spawn (spawn paralelo). Cada hilo de login escribe
// su propio slot; cuando TODOS terminan, la GUI spawnea los N farms a la vez.
struct SpawnPrep {
    QString deviceId;
    QVector<int> priority;   // snapshot por cuenta tomado antes del login
    QString realName;
    qlonglong coins = 0;
    int equippedId = -1;   // data.current del server (inventory)
    int localId = -1;      // equippedGemId guardado en accounts.json (eleccion del usuario)
    QVector<GemInfo> gems;
    QString lastError;     // error del ULTIMO intento de login (para el log de skip)
    QString sk;            // sesion del login de pre-spawn: el farm la reutiliza
    QString magic;         // (sin re-login: los 9 doLogin simultaneos de los farms
    bool ok = false;       //  crasheaban Qt 6.10.3 - race qHashBits, AV 0x1CE857)
    int tpmGroup = -1;     // TEORIA 2026-08-10: 3 TPMs compartidos (4+4+2) en vez
                           // de 10 unicos — el server podria limitar dispositivos
                           // (mids) por IP, no cuentas. -1 = PEM unica del device.
    bool boughtByPriority = false; // 2026-08-10: la gema se COMPRO del shop por
                           // prioridad (inventario vacio) — badge PRIORIDAD en
                           // la tarjeta del dashboard.
};

// Parser Haxe serializer minimo para qw.sol:
//   o -> objeto, y<len>:<string>, t -> true, z -> null, i<int>, g -> fin.
// Busca el key literal y devuelve el valor string que le sigue (formato y<len>:<bytes>).
QString extractHaxeStringAfter(const QByteArray &data, const char *key)
{
    const int klen = int(std::strlen(key));
    const int idx = data.indexOf(key);
    if (idx < 0)
        return QString();
    const int p = idx + klen;
    if (p >= data.size() || data.at(p) != 'y')
        return QString();
    int q = p + 1;
    while (q < data.size() && data.at(q) >= '0' && data.at(q) <= '9')
        ++q;
    if (q >= data.size() || data.at(q) != ':')
        return QString();
    bool ok = false;
    const int len = QString::fromLatin1(data.mid(p + 1, q - p - 1)).toInt(&ok);
    if (!ok || len <= 0 || q + 1 + len > data.size())
        return QString();
    // El qw.sol guarda deviceIds URL-encoded (%2C, %3B...): decodificar siempre
    QString val = QString::fromUtf8(data.mid(q + 1, len));
    if (val.contains(QStringLiteral("%")))
        val = QUrl::fromPercentEncoding(data.mid(q + 1, len));
    return val;
}

// Todos los device id de un qw.sol (deviceId, deviceIdSecondary, deviceId4..N,
// deviceIdthird/fourth...). Cada key Haxe va con prefijo y<len>: y su valor con
// y<len>:<bytes>. El prefijo exacto evita falsos matches de subcadenas
// (p.ej. "deviceId" dentro de "deviceIdSecondary").
QStringList extractAllDeviceIds(const QByteArray &data)
{
    QStringList out;
    int pos = 0;
    while ((pos = data.indexOf("deviceId", pos)) >= 0) {
        if (pos > 0 && data.at(pos - 1) == ':') {
            int pre = pos - 2;
            while (pre >= 0 && data.at(pre) >= '0' && data.at(pre) <= '9')
                --pre;
            if (pre >= 0 && data.at(pre) == 'y') {
                bool ok = false;
                const int keyLen = data.mid(pre + 1, pos - pre - 2).toInt(&ok);
                if (ok && keyLen >= 8) {
                    const int v = pos + keyLen;
                    if (v < data.size() && data.at(v) == 'y') {
                        int q = v + 1;
                        while (q < data.size() && data.at(q) >= '0' && data.at(q) <= '9')
                            ++q;
                        if (q < data.size() && data.at(q) == ':') {
                            const int len = data.mid(v + 1, q - v - 1).toInt(&ok);
                            if (ok && len > 0 && q + 1 + len <= data.size()) {
                                const QByteArray rawDev = data.mid(q + 1, len);
                                QString dev = QString::fromUtf8(rawDev);
                                if (dev.contains(QStringLiteral("%")))
                                    dev = QUrl::fromPercentEncoding(rawDev);
                                if (!dev.isEmpty() && !out.contains(dev))
                                    out.append(dev);
                                pos = q + 1 + len;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        pos += 8;
    }
    return out;
}

// archivo -> tal cual; carpeta -> todos los *.sol/*.qws dentro (recursivo).
// El usuario suelta carpetas (cada cuenta es una carpeta con su qw.sol).
QStringList expandQwsPaths(const QVariantList &paths)
{
    QStringList out;
    for (const auto &pv : paths) {
        QString path = pv.toString();
        if (path.startsWith(QStringLiteral("file://")))
            path = QUrl(path).toLocalFile();
        const QFileInfo fi(path);
        if (fi.isDir()) {
            QDirIterator it(path, QStringList() << QStringLiteral("*.sol") << QStringLiteral("*.qws"),
                            QDir::Files, QDirIterator::Subdirectories);
            while (it.hasNext())
                out.append(it.next());
        } else if (fi.isFile()) {
            out.append(path);
        }
    }
    return out;
}

// Traduce nombre de gema del server (ES) a ingles para UI
QString translateGemName(const QString &esName)
{
    static const QHash<QString,QString> map = {
        {QStringLiteral("Gema Rosa"), QStringLiteral("Pink Gem")},
        {QStringLiteral("Gema Roja"), QStringLiteral("Red Gem")},
        {QStringLiteral("Gema Rojo"), QStringLiteral("Red Gem")},
        {QStringLiteral("Gema Azul"), QStringLiteral("Blue Gem")},
        {QStringLiteral("Gema Verde"), QStringLiteral("Green Gem")},
        {QStringLiteral("Gema Naranja"), QStringLiteral("Orange Gem")},
        {QStringLiteral("Gema Amarilla"), QStringLiteral("Yellow Gem")},
        {QStringLiteral("Gema Amarillo"), QStringLiteral("Yellow Gem")},
        {QStringLiteral("Gema Morada"), QStringLiteral("Purple Gem")},
        {QStringLiteral("Gema Morado"), QStringLiteral("Purple Gem")},
        {QStringLiteral("Gema P\u00farpura"), QStringLiteral("Purple Gem")},
        {QStringLiteral("Gema Dorada"), QStringLiteral("Gold Gem")},
        {QStringLiteral("Gema Dorado"), QStringLiteral("Gold Gem")},
        {QStringLiteral("Gema Plateada"), QStringLiteral("Silver Gem")},
        {QStringLiteral("Gema Plata"), QStringLiteral("Silver Gem")},
        {QStringLiteral("Gema Negra"), QStringLiteral("Black Gem")},
        {QStringLiteral("Gema Negro"), QStringLiteral("Black Gem")},
        {QStringLiteral("Gema Blanca"), QStringLiteral("White Gem")},
        {QStringLiteral("Gema Blanco"), QStringLiteral("White Gem")},
        {QStringLiteral("Gema Gris"), QStringLiteral("Gray Gem")},
        {QStringLiteral("Gema Turquesa"), QStringLiteral("Teal Gem")},
        {QStringLiteral("Gema Cian"), QStringLiteral("Cyan Gem")},
        {QStringLiteral("Gema Magenta"), QStringLiteral("Magenta Gem")},
        {QStringLiteral("Gema Granate"), QStringLiteral("Maroon Gem")},
        {QStringLiteral("Gema Bosque"), QStringLiteral("Forest Gem")},
        {QStringLiteral("Gema Arcoiris"), QStringLiteral("Rainbow Gem")},
        {QStringLiteral("Gema \u00cdndigo"), QStringLiteral("Indigo Gem")},
        // English passthrough
        {QStringLiteral("Pink Gem"), QStringLiteral("Pink Gem")},
        {QStringLiteral("Red Gem"), QStringLiteral("Red Gem")},
        {QStringLiteral("Blue Gem"), QStringLiteral("Blue Gem")},
        {QStringLiteral("Green Gem"), QStringLiteral("Green Gem")},
        {QStringLiteral("Orange Gem"), QStringLiteral("Orange Gem")},
        {QStringLiteral("Yellow Gem"), QStringLiteral("Yellow Gem")},
        {QStringLiteral("Purple Gem"), QStringLiteral("Purple Gem")},
        {QStringLiteral("Gold Gem"), QStringLiteral("Gold Gem")},
        {QStringLiteral("Silver Gem"), QStringLiteral("Silver Gem")},
        {QStringLiteral("Black Gem"), QStringLiteral("Black Gem")},
        {QStringLiteral("White Gem"), QStringLiteral("White Gem")},
        {QStringLiteral("Gray Gem"), QStringLiteral("Gray Gem")},
        {QStringLiteral("Teal Gem"), QStringLiteral("Teal Gem")},
        {QStringLiteral("Cyan Gem"), QStringLiteral("Cyan Gem")},
        {QStringLiteral("Magenta Gem"), QStringLiteral("Magenta Gem")},
        {QStringLiteral("Maroon Gem"), QStringLiteral("Maroon Gem")},
        {QStringLiteral("Forest Gem"), QStringLiteral("Forest Gem")},
        {QStringLiteral("Rainbow Gem"), QStringLiteral("Rainbow Gem")},
        {QStringLiteral("Indigo Gem"), QStringLiteral("Indigo Gem")},
    };
    if (map.contains(esName))
        return map.value(esName);
    // Fallback: busca "Gema X" -> traduce X
    if (esName.startsWith("Gema ")) {
        QString after = esName.mid(5);
        QString lower = after.toLower();
        if (lower == "rosa") return QStringLiteral("Pink Gem");
        if (lower == "roja" || lower == "rojo") return QStringLiteral("Red Gem");
        if (lower == "azul") return QStringLiteral("Blue Gem");
        if (lower == "verde") return QStringLiteral("Green Gem");
        if (lower == "naranja") return QStringLiteral("Orange Gem");
        if (lower == "amarilla" || lower == "amarillo") return QStringLiteral("Yellow Gem");
        if (lower == "morada" || lower == "morado") return QStringLiteral("Purple Gem");
        if (lower == "dorada" || lower == "dorado") return QStringLiteral("Gold Gem");
        if (lower == "plateada" || lower == "plata") return QStringLiteral("Silver Gem");
        if (lower == "negra" || lower == "negro") return QStringLiteral("Black Gem");
        if (lower == "blanca" || lower == "blanco") return QStringLiteral("White Gem");
        if (lower == "gris") return QStringLiteral("Gray Gem");
        if (lower == "turquesa") return QStringLiteral("Teal Gem");
        if (lower == "arcoiris" || lower == "arco\u00edris") return QStringLiteral("Rainbow Gem");
        // No match -> capitalize anyway
        return after.left(1).toUpper() + after.mid(1) + " Gem";
    }
    return esName;
}

// ruta qrc del sprite de una gema por nombre+nivel (misma logica que gemMap)
// Indice de color 0-19 de una gema por NOMBRE (misma logica que gemSpritePath).
// 2026-08-10: extraido para el pick por PRIORIDAD de color del spawn (que el
// farm equipe automaticamente la gema del color con mas prioridad del usuario).
int gemColorIndexByName(const QString &name)
{
    QString n = name.toLower();
    static const QHash<QString,QString> esToEn = {
        {QStringLiteral("rosa"), QStringLiteral("pink")},
        {QStringLiteral("roja"), QStringLiteral("red")}, {QStringLiteral("rojo"), QStringLiteral("red")},
        {QStringLiteral("azul"), QStringLiteral("blue")},
        {QStringLiteral("verde"), QStringLiteral("green")},
        {QStringLiteral("naranja"), QStringLiteral("orange")},
        {QStringLiteral("amarilla"), QStringLiteral("yellow")}, {QStringLiteral("amarillo"), QStringLiteral("yellow")},
        {QStringLiteral("morada"), QStringLiteral("purple")}, {QStringLiteral("morado"), QStringLiteral("purple")},
        {QStringLiteral("p\u00farpura"), QStringLiteral("purple")},
        {QStringLiteral("dorada"), QStringLiteral("gold")}, {QStringLiteral("dorado"), QStringLiteral("gold")},
        {QStringLiteral("plateada"), QStringLiteral("silver")}, {QStringLiteral("plata"), QStringLiteral("silver")},
        {QStringLiteral("negra"), QStringLiteral("black")}, {QStringLiteral("negro"), QStringLiteral("black")},
        {QStringLiteral("blanca"), QStringLiteral("white")}, {QStringLiteral("blanco"), QStringLiteral("white")},
        {QStringLiteral("gris"), QStringLiteral("gray")},
        {QStringLiteral("turquesa"), QStringLiteral("teal")}, {QStringLiteral("cian"), QStringLiteral("cyan")},
        {QStringLiteral("magenta"), QStringLiteral("magenta")},
        {QStringLiteral("granate"), QStringLiteral("maroon")}, {QStringLiteral("bord\u00f3"), QStringLiteral("maroon")},
        {QStringLiteral("marr\u00f3n"), QStringLiteral("brown")}, {QStringLiteral("marron"), QStringLiteral("brown")},
        {QStringLiteral("bosque"), QStringLiteral("forest")},
        {QStringLiteral("arcoiris"), QStringLiteral("rainbow")}, {QStringLiteral("arco\u00edris"), QStringLiteral("rainbow")},
        {QStringLiteral("\u00edndigo"), QStringLiteral("indigo")},
    };
    for (auto it = esToEn.constBegin(); it != esToEn.constEnd(); ++it)
        if (n.contains(it.key())) { n = it.value(); break; }
    if (n.contains("red")) return 8;
    if (n.contains("pink")) return 6;
    if (n.contains("forest")) return 11;
    if (n.contains("orange")) return 5;
    if (n.contains("silver") || n.contains("plata")) return 18;
    if (n.contains("blue")) return 1;
    if (n.contains("indigo")) return 14;
    if (n.contains("purple")) return 7;
    if (n.contains("gold")) return 12;
    if (n.contains("yellow")) return 10;
    if (n.contains("white")) return 9;
    if (n.contains("black")) return 0;
    if (n.contains("cyan")) return 3;
    if (n.contains("magenta")) return 15;
    if (n.contains("maroon")) return 16;
    if (n.contains("rainbow")) return 17;
    if (n.contains("gray") || n.contains("gris")) return 13;
    if (n.contains("teal")) return 19;
    if (n.contains("brown")) return 2;
    if (n.contains("green")) return 4;
    return -1;
}

QString gemSpritePath(const QString &name, int itemLevel)
{
    // assets/gems/{NN}-{color}-{LL}.png donde NN es el color (01-20) y LL la
    // banda de nivel (01=lvl1-5, 02=6-10, 03=11-15, 04=16-20, 05=21-25).
    // Mismo orden que el sprite-sheet del binario.
    QStringList colorNames = {
        QStringLiteral("black"), QStringLiteral("blue"), QStringLiteral("brown"),
        QStringLiteral("cyan"), QStringLiteral("green"), QStringLiteral("orange"),
        QStringLiteral("pink"), QStringLiteral("purple"), QStringLiteral("red"),
        QStringLiteral("white"), QStringLiteral("yellow"), QStringLiteral("forest"),
        QStringLiteral("gold"), QStringLiteral("gray"), QStringLiteral("indigo"),
        QStringLiteral("magenta"), QStringLiteral("maroon"), QStringLiteral("rainbow"),
        QStringLiteral("silver"), QStringLiteral("teal")
    };
    QString n = name.toLower();
    // Traducciones ES->EN para nombres de gemas del server
    static const QHash<QString,QString> esToEn = {
        {QStringLiteral("rosa"), QStringLiteral("pink")},
        {QStringLiteral("roja"), QStringLiteral("red")}, {QStringLiteral("rojo"), QStringLiteral("red")},
        {QStringLiteral("azul"), QStringLiteral("blue")},
        {QStringLiteral("verde"), QStringLiteral("green")},
        {QStringLiteral("naranja"), QStringLiteral("orange")},
        {QStringLiteral("amarilla"), QStringLiteral("yellow")}, {QStringLiteral("amarillo"), QStringLiteral("yellow")},
        {QStringLiteral("morada"), QStringLiteral("purple")}, {QStringLiteral("morado"), QStringLiteral("purple")},
        {QStringLiteral("p\u00farpura"), QStringLiteral("purple")},
        {QStringLiteral("dorada"), QStringLiteral("gold")}, {QStringLiteral("dorado"), QStringLiteral("gold")},
        {QStringLiteral("plateada"), QStringLiteral("silver")}, {QStringLiteral("plata"), QStringLiteral("silver")},
        {QStringLiteral("negra"), QStringLiteral("black")}, {QStringLiteral("negro"), QStringLiteral("black")},
        {QStringLiteral("blanca"), QStringLiteral("white")}, {QStringLiteral("blanco"), QStringLiteral("white")},
        {QStringLiteral("gris"), QStringLiteral("gray")},
        {QStringLiteral("turquesa"), QStringLiteral("teal")}, {QStringLiteral("cian"), QStringLiteral("cyan")},
        {QStringLiteral("magenta"), QStringLiteral("magenta")},
        {QStringLiteral("granate"), QStringLiteral("maroon")}, {QStringLiteral("bord\u00f3"), QStringLiteral("maroon")},
        {QStringLiteral("marr\u00f3n"), QStringLiteral("brown")}, {QStringLiteral("marron"), QStringLiteral("brown")},
        {QStringLiteral("bosque"), QStringLiteral("forest")},
        {QStringLiteral("arcoiris"), QStringLiteral("rainbow")}, {QStringLiteral("arco\u00edris"), QStringLiteral("rainbow")},
        {QStringLiteral("\u00edndigo"), QStringLiteral("indigo")},
    };
    // Traduce si encuentra match parcial en el hash
    for (auto it = esToEn.constBegin(); it != esToEn.constEnd(); ++it)
        if (n.contains(it.key())) { n = it.value(); break; }
    int colorIdx = 0;
    if (n.contains("red")) colorIdx = 8;
    else if (n.contains("pink")) colorIdx = 6;
    else if (n.contains("forest") || n.contains("bosque")) colorIdx = 11;
    else if (n.contains("orange")) colorIdx = 5;
    else if (n.contains("silver") || n.contains("plata") || n.contains("plateada")) colorIdx = 18;
    else if (n.contains("blue")) colorIdx = 1;
    else if (n.contains("indigo")) colorIdx = 14;
    else if (n.contains("purple")) colorIdx = 7;
    else if (n.contains("gold")) colorIdx = 12;
    else if (n.contains("yellow")) colorIdx = 10;
    else if (n.contains("white")) colorIdx = 9;
    else if (n.contains("black")) colorIdx = 0;
    else if (n.contains("cyan")) colorIdx = 3;
    else if (n.contains("magenta")) colorIdx = 15;
    else if (n.contains("maroon")) colorIdx = 16;
    else if (n.contains("rainbow")) colorIdx = 17;
    else if (n.contains("gray") || n.contains("gris")) colorIdx = 13;
    else if (n.contains("teal")) colorIdx = 19;
    else if (n.contains("brown")) colorIdx = 2;
    else if (n.contains("green")) colorIdx = 4;
    int band = (itemLevel - 1) / 5 + 1;
    if (band < 1) band = 1;
    if (band > 5) band = 5;
    QString colorName = colorNames.value(colorIdx, QStringLiteral("purple"));
    return QStringLiteral("qrc:/Astro/assets/gems/%1-%2-%3.png")
        .arg(colorIdx + 1, 2, 10, QLatin1Char('0'))
        .arg(colorName)
        .arg(band, 2, 10, QLatin1Char('0'));
}

// Caché de TODAS las gemas de una cuenta para accounts.json:
// [{id, name, level, exp, cexp}, ...] — se muestra al instante al hacer click
QVariantList gemsCacheFrom(const QVector<GemInfo> &gems)
{
    QVariantList out;
    for (const auto &g : gems) {
        QVariantMap m;
        m.insert(QStringLiteral("id"), int(g.id));
        m.insert(QStringLiteral("name"), translateGemName(g.name));
        m.insert(QStringLiteral("level"), int(g.itemLevel));
        m.insert(QStringLiteral("exp"), qlonglong(g.exp));
        m.insert(QStringLiteral("cexp"), qlonglong(g.cexp));
        m.insert(QStringLiteral("sprite"), gemSpritePath(g.name, g.itemLevel));
        out.append(m);
    }
    return out;
}

// Catalogo del shop (StoreItem) serializado para guardar en la cuenta
// (fetchAllGems lo precarga al iniciar Astro: la gems shop abre al instante
// sin re-login - pedido 2026-08-09).
QVariantList storeItemsCacheFrom(const QVector<StoreItem> &items)
{
    QVariantList out;
    for (const auto &s : items) {
        QVariantMap m;
        m.insert(QStringLiteral("id"), s.id);
        m.insert(QStringLiteral("name"), translateGemName(s.name));
        // sprite con el NIVEL REAL de la gema (banda 01-05 segun nivel:
        // 01=lvl1-5 ... 05=lvl21-25). El shop muestra el nivel verdadero,
        // a diferencia de la priority que usa siempre la banda 05.
        m.insert(QStringLiteral("sprite"), gemSpritePath(s.name, s.level));
        m.insert(QStringLiteral("level"), s.level);
        m.insert(QStringLiteral("price"), s.price);
        m.insert(QStringLiteral("exp"), qlonglong(s.exp));
        m.insert(QStringLiteral("owned"), s.owned);
        m.insert(QStringLiteral("purchasable"), s.purchasable);
        m.insert(QStringLiteral("category"), s.category);
        m.insert(QStringLiteral("attrs"), s.attrs);
        QStringList attrsText;
        for (const auto &av : s.attrs) {
            const QVariantList pair = av.toList();
            if (pair.size() >= 2)
                attrsText.append(pair[0].toString() + " +" + pair[1].toString());
        }
        m.insert(QStringLiteral("attrsText"), attrsText);
        out.append(m);
    }
    return out;
}

// AppData/Astro/accounts.json (independiente del organizationName de la app)
// FIX 2026-08-11: Qt MinGW aplica organizationName ("Astro Labs") a
// GenericDataLocation -> la ruta real terminaba en %APPDATA%\Astro Labs\Astro
// y no coincidia con la que usa el resto del ecosistema. Usar APPDATA fijo.
QString astroDataBase()
{
    QString base;
    const QByteArray env = qgetenv("APPDATA");
    if (!env.isEmpty())
        base = QString::fromLocal8Bit(env);
    if (base.isEmpty())
        base = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (base.isEmpty())
        base = QCoreApplication::applicationDirPath();
    return base;
}

QString accountsFilePath()
{
    QString base = astroDataBase();
    QDir d(base + QStringLiteral("/Astro"));
    if (!d.exists())
        d.mkpath(d.absolutePath());
    return d.absoluteFilePath(QStringLiteral("accounts.json"));
}

// Ruta del PEM de atestacion FAKE del device: %LOCALAPPDATA%/Astro/fake_tpm/
// <md5(device) 16 hex>.pem. Si no existe (o esta vacio/corrupto), se genera
// RSA-2048 con generateRsaPem2048 y se escribe. CADA device usa SIEMPRE su
// propia clave: el server identifica la atestacion por mid+proof y compartir
// la clave embebida entre cuentas hace que caigan las conexiones. Devuelve el
// path SOLO cuando existe una clave valida; vacio solo tras fallar TODOS los
// reintentos (el llamador debe abortar, nunca caer a la clave embebida).
// TEORIA 2026-08-10 (usuario): el server limita DISPOSITIVOS (mids) por IP,
// no cuentas. Con 10 PEMs unicas = 10 dispositivos de 1 IP -> corta AUTHs
// simultaneos. Probar 3 TPMs compartidos (grupos 4+4+2): el server ve 3
// dispositivos. El mid deriva SOLO del modulo RSA (buildMidPem), asi que
// compartir la PEM entre cuentas del mismo grupo = mismo dispositivo.
// El proof TCP firma challenge|deviceId|100 con la clave del grupo: sigue
// siendo valido (cada deviceId firma el suyo). Genera/usa fake_tpm/group<N>.pem.
QString fakeTpmPathForGroup(int groupIdx)
{
    if (groupIdx < 0)
        return QString();
    QString base = astroDataBase();
    if (base.isEmpty())
        base = QCoreApplication::applicationDirPath();
    QDir d(base + QStringLiteral("/Astro/fake_tpm"));
    if (!d.exists() && !d.mkpath(d.absolutePath()))
        return QString();
    const QString path = d.absoluteFilePath(QStringLiteral("group%1.pem").arg(groupIdx));
    if (QFileInfo::exists(path)) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            f.close();
            QFile::remove(path);
        } else {
            const QByteArray data = f.readAll();
            f.close();
            if (data.trimmed().isEmpty()
                || !data.contains("-----BEGIN RSA PRIVATE KEY-----"))
                QFile::remove(path);
        }
    }
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (QFileInfo::exists(path)) {
            QFile f(path);
            if (f.open(QIODevice::ReadOnly)) {
                const QByteArray data = f.readAll();
                f.close();
                if (!data.trimmed().isEmpty()
                    && data.contains("-----BEGIN RSA PRIVATE KEY-----"))
                    return path;
            }
            QFile::remove(path);
        }
        QString pem;
        if (generateRsaPem2048(&pem)) {
            QFile f(path);
            if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                f.write(pem.toUtf8());
                f.close();
                QFile vf(path);
                if (vf.open(QIODevice::ReadOnly)) {
                    const QByteArray written = vf.readAll();
                    vf.close();
                    if (!written.trimmed().isEmpty()
                        && written.contains("-----BEGIN RSA PRIVATE KEY-----"))
                        return path;
                }
            }
        }
        QThread::msleep(100);
    }
    return QString();
}

QString fakeTpmPathForDevice(const QString &device)
{
    if (device.isEmpty())
        return QString();
    QString base = astroDataBase();
    if (base.isEmpty())
        base = QCoreApplication::applicationDirPath();
    QDir d(base + QStringLiteral("/Astro/fake_tpm"));
    if (!d.exists() && !d.mkpath(d.absolutePath()))
        return QString();
    const QString path = d.absoluteFilePath(md5Hex(device).left(16) + QStringLiteral(".pem"));

    // archivo existente pero vacio o sin formato de clave RSA valida: borrarlo
    // para regenerarlo abajo (una clave truncada fallaria el EH + SECURE_PROOF)
    if (QFileInfo::exists(path)) {
        QFile f(path);
        if (!f.open(QIODevice::ReadOnly)) {
            f.close();
            QFile::remove(path);
        } else {
            const QByteArray data = f.readAll();
            f.close();
            if (data.trimmed().isEmpty()
                || !data.contains("-----BEGIN RSA PRIVATE KEY-----"))
                QFile::remove(path);
        }
    }

    // generacion con reintentos (hasta 3 intentos, 100ms de pausa entre ellos)
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (QFileInfo::exists(path)) {
            QFile f(path);
            if (f.open(QIODevice::ReadOnly)) {
                const QByteArray data = f.readAll();
                f.close();
                if (!data.trimmed().isEmpty()
                    && data.contains("-----BEGIN RSA PRIVATE KEY-----"))
                    return path;
            }
            QFile::remove(path);
        }
        QString pem;
        if (generateRsaPem2048(&pem)) {
            QFile f(path);
            if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
                f.write(pem.toUtf8());
                f.close();
                // verifica que quedo bien escrita antes de darla por buena
                QFile vf(path);
                if (vf.open(QIODevice::ReadOnly)) {
                    const QByteArray written = vf.readAll();
                    vf.close();
                    if (!written.trimmed().isEmpty()
                        && written.contains("-----BEGIN RSA PRIVATE KEY-----"))
                        return path;
                }
            }
        }
        QThread::msleep(100);
    }
    return QString();
}
} // namespace

FarmController::FarmController(QObject *parent) : QObject(parent)
{
    m_deviceId = readDeviceId();
    if (m_deviceId.isEmpty())
        m_deviceId = QString::fromUtf8(kDefaultDevice);

    // auto-refresh de cuentas: refresca la DB cada intervalo (default 10 min,
    // configurable desde QML con configureAutoRefresh). No dispara si ya corre
    // un refreshAll, si hay una carga QWS en curso o si no hay cuentas guardadas.
    m_autoRefreshTimer = new QTimer(this);
    m_autoRefreshTimer->setInterval(600000);
    connect(m_autoRefreshTimer, &QTimer::timeout, this, [this]() {
        // 2026-08-11 (queja del usuario: "el refresh no actualiza el XP en el
        // dashboard"): el XP en vivo ya lo reportan los workers (op 24 ->
        // onFarmXp -> lastXp) y el flushUi lo pinta. El refreshAll salta las
        // cuentas farmeando (no rompe sus sesiones), asi que aqui SOLO se
        // fuerza el flush de la UI con los datos frescos del worker.
        flushUi();
        // v39 (pedido del usuario: "el autorefresh deberia volver a hacer todo
        // desde 0 como si presionara RUN"): ciclo COMPLETO cada intervalo —
        // STOP de las sesiones + login nuevo (XP real tras materializar) +
        // respawn. refreshAllAccounts() ya hace exactamente eso (v38).
        if (!m_refreshingAll && !m_qwsLoading && !m_farmSelection.isEmpty())
            refreshSelectedFarmAccounts();
    });
    // Coalescing de la UI (ESC-1): las emisiones de alta frecuencia
    // (onFarmXp/onGemXpRead) marcan dirty y este timer agrupa los rebuilds en
    // UNA emision de accountsChanged/activeSessionsChanged. Los eventos
    // discretos (spawn, stop, refresh, estados) siguen emitiendo directo.
    m_uiFlushTimer = new QTimer(this);
    m_uiFlushTimer->setInterval(300);
    m_uiFlushTimer->setSingleShot(true);
    connect(m_uiFlushTimer, &QTimer::timeout, this, [this]() { flushUi(); });
    // Configs persistidas (QSettings): auto-respawn y auto-refresh se restauran
    // al arrancar para que la app inicie con los cambios que el usuario hizo.
    {
        const QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
        m_autoRespawn = s.value(QStringLiteral("autoRespawn"), m_autoRespawn).toBool();
        m_autoRepair = s.value(QStringLiteral("autoRepair"), false).toBool();
        m_autoBuyX2 = s.value(QStringLiteral("autoBuyX2"), false).toBool();
        const bool arEnabled = s.value(QStringLiteral("autoRefreshEnabled"), false).toBool();
        const int arInterval = s.value(QStringLiteral("autoRefreshInterval"), 600).toInt();
        m_autoRefreshWanted = arEnabled;
        m_autoRefreshTimer->setInterval(qMax(10, arInterval) * 1000);
        // v44: el timer NO arranca aqui — solo con farms activos (spawn lo
        // arranca). El switch del usuario queda en m_autoRefreshWanted.
        if (arEnabled && (farmRunning() || !m_farms.isEmpty()))
            m_autoRefreshTimer->start();
    }
    // prioridad de gemas persistida (QSettings, misma org)
    loadGemPriority();
    // Seleccion de cuentas persistida (casillas del workflow)
    loadFarmSelection();
    // 2026-08-10: auto-buy de la tienda por color (boton "Auto buy" en la
    // seccion de prioridad). La tienda rota 2x/dia a las 19:00 y 01:00 hora
    // Colombia (UTC-5 sin DST) = 00:00 y 06:00 UTC. El timer tickea cada 30s
    // y compra 1 min despues del reinicio (00:01/06:01 UTC) — en UTC para que
    // funcione desde cualquier pais/zona horaria.
    {
        const QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
        const QStringList saved = s.value(QStringLiteral("autoBuyColors")).toStringList();
        m_autoBuyColors.clear();
        for (const QString &str : saved) {
            bool okNum = false;
            const int idx = str.toInt(&okNum);
            if (okNum && idx >= 0 && idx < 20)
                m_autoBuyColors.insert(idx);
        }
        m_storeBuyTimer = new QTimer(this);
        m_storeBuyTimer->setInterval(30000);
        connect(m_storeBuyTimer, &QTimer::timeout, this, [this]() { runStoreAutoBuy(); });
        m_storeBuyTimer->start();
    }
}

void FarmController::saveFarmSelection()
{
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("farmSelection"), m_farmSelection);
}

void FarmController::loadFarmSelection()
{
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    const QVariantList saved = s.value(QStringLiteral("farmSelection")).toList();
    m_farmSelection.clear();
    // Solo restaura devices que existan en accounts.json (si una cuenta se
    // borro, su device ya no debe seguir marcado)
    for (const auto &v : saved) {
        const QString dev = v.toString();
        bool exists = false;
        for (const auto &av : m_accounts) {
            if (av.toMap().value(QStringLiteral("device")).toString() == dev) {
                exists = true;
                break;
            }
        }
        if (exists && m_farmSelection.size() < kMaxFarmSelection)
            m_farmSelection.append(dev);
    }
    if (!saved.isEmpty())
        emit farmSelectionChanged();
}

// 2026-08-10 (pedido del usuario: "detecta el x2 de las gemas para TODAS
// las cuentas guardadas"): login secuencial de CADA cuenta de accounts.json
// (aunque no farmee) + lectura del inventario de consumibles (slots 3 y 4,
// los mismos que consulta el binario al abrir el inventario de pociones —
// captura Frida 2026-08-10) + deteccion del boost DE LAS GEMAS:
// "Double Gem XP" id=8590 con durability>0 = ACTIVO. El resultado se
// persiste en accounts.json (x2State/x2Reason) para que el badge lo
// muestre aunque la cuenta no tenga sesion de farm. NO compra nada: solo
// detecta, para saber a que cuentas comprarles.
// Secuencial 1 login a la vez: el server corta el handshake cuando llegan
// varios AUTHs de la misma IP a la vez (leccion de la fase conexion).
void FarmController::scanAllX2()
{
    if (m_accounts.isEmpty())
        return;
    if (m_scanX2Thread) {
        // un scan ya en curso (arranque + refresco manual): no duplicar
        appendLog(QStringLiteral("X2 scan ya en curso, ignorando"));
        return;
    }
    appendLog(QStringLiteral("X2 scan: %1 cuentas guardadas...").arg(m_accounts.size()));
    // v42 (lag de arranque: la UI se congelaba ~10s): ANTES el loop de logins
    // HTTP de cada cuenta (hasta 9 logins secuenciales + msleep 800ms) corria
    // EN EL GUI THREAD -> la ventana no respondia. Ahora el scan corre en un
    // hilo propio; los resultados vuelven al GUI con queued invokeMethod.
    struct ScanEntry {
        QString device;
        QString pemPath;
        int index = -1;
        QString farmSk;
        QString farmMagic;
    };
    QVector<ScanEntry> entries;
    for (int i = 0; i < m_accounts.size(); ++i) {
        const QString dev = m_accounts.at(i).toMap().value(QStringLiteral("device")).toString();
        if (dev.isEmpty())
            continue;
        // 2026-08-11 (bug de interfaz: badges x2 rojos falsos): las cuentas con
        // farm ACTIVO ya tienen el x2State calculado en vivo por el checkX2 del
        // worker (con la sesion del farm). Hacer login simultaneo aqui rompe la
        // sesion del farm o devuelve inventario vacio -> "sin x2" falso. Saltar.
        bool farming = false;
        for (const auto &fh : std::as_const(m_farms)) {
            if (fh.deviceId == dev && fh.worker && fh.thread && fh.thread->isRunning()) {
                farming = true;
                break;
            }
        }
        if (farming)
            continue;
        ScanEntry e;
        e.device = dev;
        e.pemPath = fakeTpmPathForDevice(dev);
        e.index = i;
        // FIX 2026-08-11 (crash: el scan rompia la sesion del farm): si la
        // cuenta tiene farm activo, su worker ya tiene sk/magic validos. Usar
        // la sesion del worker (loginifneeded sin KNOCK/LIM/EH) en vez de
        // login completo - el login duplicado desconecta/crashea la sesion.
        for (const auto &fh : std::as_const(m_farms)) {
            if (fh.deviceId == dev && fh.worker) {
                e.farmSk = fh.worker->sessionSk();
                e.farmMagic = fh.worker->sessionMagic();
                break;
            }
        }
        entries.append(e);
    }
    appendLog(QStringLiteral("X2 scan: %1 con device valido").arg(entries.size()));
    if (entries.isEmpty())
        return;

    QThread *thread = new QThread(this);
    m_scanX2Thread = thread;
    connect(thread, &QThread::started, thread, [this, thread, entries]() {
        for (const ScanEntry &e : entries) {
            LoginManager local;
            if (!e.pemPath.isEmpty()) {
                QFile pf(e.pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
            }
            LoginResult r;
            if (!e.farmSk.isEmpty()) {
                // reutilizar sesion del worker: loginifneeded barato, no rompe nada
                r.ok = local.loginWithSession(e.farmSk, e.farmMagic);
                r.deviceId = e.device;
                if (!r.ok)
                    writeLogFile(QStringLiteral("[DBG] X2 scan %1: sesion del farm invalida, fallback login").arg(logName(e.device, QString())));
            }
            if (!r.ok) {
                for (int intento = 1; intento <= 2; ++intento) {
                    r = local.login(e.device);
                    if (r.ok)
                        break;
                    writeLogFile(QStringLiteral("[DBG] X2 scan login %1 intento=%2 fallo: %3")
                                     .arg(logName(e.device, QString())).arg(intento).arg(r.error));
                    if (intento < 2)
                        QThread::msleep(1200);
                }
            }
            if (!r.ok) {
                writeLogFile(QStringLiteral("[DBG] X2 scan %1: login fallo (%2)")
                                 .arg(logName(e.device, QString())).arg(r.error.left(80)));
                QMetaObject::invokeMethod(this, [this, e, r]() {
                    updateAccountX2(e.index, 2, QStringLiteral("scan: login fallo (%1)").arg(r.error.left(50)));
                }, Qt::QueuedConnection);
                continue;
            }
            // Leer el inventario de consumibles (slots 3 y 4) y buscar el 8590.
            bool found = false;
            bool active = false;
            QString name;
            int dur = 0, maxDur = 0;
            for (int slot : {3, 4}) {
                const QJsonObject inv = local.apiCall(QStringLiteral("{\"do\":\"inventory\",\"slot\":%1}").arg(slot));
                const QJsonArray items = inv.value(QStringLiteral("data")).toObject().value(QStringLiteral("items")).toArray();
                for (const auto &iv : items) {
                    const QJsonObject item = iv.toObject();
                    if (item.value(QStringLiteral("id")).toInt() != 8590)
                        continue;
                    found = true;
                    name = item.value(QStringLiteral("name")).toString();
                    dur = item.value(QStringLiteral("durability")).toInt();
                    maxDur = item.value(QStringLiteral("max_durability")).toInt();
                    if (dur > 0)
                        active = true;
                }
            }
            struct X2Out {
                int index = -1;
                int state = 0;
                QString reason;
                QString logLine;
            } o;
            if (active) {
                o.state = 1;
                o.reason = QStringLiteral("x2 gemas activo (%1 %2/%3)").arg(name).arg(dur).arg(maxDur);
                o.logLine = QStringLiteral("[DBG] X2 scan %1: %2 ACTIVO (%3/%4)")
                                .arg(logName(e.device, QString())).arg(name).arg(dur).arg(maxDur);
            } else if (found) {
                o.state = 2;
                o.reason = QStringLiteral("x2 gemas expirado (%1 %2/%3)").arg(name).arg(dur).arg(maxDur);
                o.logLine = QStringLiteral("[DBG] X2 scan %1: %2 expirado (%3/%4)")
                                .arg(logName(e.device, QString())).arg(name).arg(dur).arg(maxDur);
            } else {
                o.state = 2;
                o.reason = QStringLiteral("sin Double Gem XP en inventario");
                o.logLine = QStringLiteral("[DBG] X2 scan %1: sin Double Gem XP (8590) en inventario")
                                .arg(logName(e.device, QString()));
            }
            o.index = e.index;
            writeLogFile(o.logLine);
            QMetaObject::invokeMethod(this, [this, o]() {
                updateAccountX2(o.index, o.state, o.reason);
            }, Qt::QueuedConnection);
            // pausa anti-bot entre cuentas (el server corta AUTHs simultaneos)
            QThread::msleep(800);
        }
        QMetaObject::invokeMethod(this, [this, thread, count = entries.size()]() {
            m_scanX2Thread = nullptr;
            saveAccounts();
            emit accountsChanged();
            appendLog(QStringLiteral("X2 scan: completo (%1 cuentas)").arg(count));
            thread->quit();
        }, Qt::QueuedConnection);
    }, Qt::DirectConnection);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// 2026-08-10: persiste el estado del x2 (detectado por scanAllX2) en la
// cuenta de accounts.json y notifica a la UI (badge del dashboard).
void FarmController::updateAccountX2(int index, int state, const QString &reason)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    QVariantMap am = m_accounts.at(index).toMap();
    am.insert(QStringLiteral("x2State"), state);
    am.insert(QStringLiteral("x2Reason"), reason);
    m_accounts.replace(index, am);
}

bool FarmController::farmRunning() const
{
    for (int i = 0; i < m_farms.size(); ++i)
        if (m_farms.at(i).thread && m_farms.at(i).thread->isRunning()) return true;
    return false;
}

int FarmController::farmRunningCount() const
{
    int n = 0;
    for (int i = 0; i < m_farms.size(); ++i)
        if (m_farms.at(i).thread && m_farms.at(i).thread->isRunning()) ++n;
    return n;
}

FarmController::~FarmController()
{
    for (int i = 0; i < m_farms.size(); ++i) {
        if (m_farms.at(i).worker) m_farms.at(i).worker->stop();
    }
    QFile f(QCoreApplication::applicationDirPath() + QStringLiteral("/astro_crash.txt"));
    if (f.open(QIODevice::Append | QIODevice::Text)) {
        f.write(QStringLiteral("dtor: farms=%1 refreshRunning=%2\n")
                    .arg(farmRunningCount())
                    .arg(m_refreshThread ? m_refreshThread->isRunning() : false).toUtf8());
        f.close();
    }
    bool farmAlive = false;
    for (const auto &h : m_farms) {
        if (h.thread && h.thread->isRunning()) {
            h.thread->quit();
            if (!h.thread->wait(12000))
                farmAlive = true;
        }
    }
    m_abortingSpawn.store(true);
    if (m_spawnOrch && m_spawnOrch->isRunning()) {
        m_spawnOrch->quit();
        if (!m_spawnOrch->wait(12000))
            farmAlive = true;
    }
    m_spawnOrch = nullptr;
    for (QThread *t : m_spawnThreads) {
        if (t && t->isRunning()) {
            t->quit();
            if (!t->wait(12000))
                farmAlive = true;
        }
    }
    m_spawnThreads.clear();
    bool refreshAlive = false;
    bool fetchAlive = false;
    bool qwsAlive = false;
    if (m_qwsThread && m_qwsThread->isRunning()) {
        m_qwsThread->quit();
        m_qwsThread->wait(12000);
        qwsAlive = m_qwsThread->isRunning();
    }
    if (m_fetchThread && m_fetchThread->isRunning()) {
        m_fetchThread->quit();
        m_fetchThread->wait(12000);
        fetchAlive = m_fetchThread->isRunning();
    }
    if (m_refreshThread && m_refreshThread->isRunning()) {
        m_refreshThread->quit();
        m_refreshThread->wait(12000);
        refreshAlive = m_refreshThread->isRunning();
    }
    if (m_refreshAllThread && m_refreshAllThread->isRunning()) {
        m_refreshAllThread->wait(15000);
        refreshAlive = m_refreshAllThread->isRunning();
    }
    // v42: el scan x2 (hilo propio) tambien debe terminar antes de salir
    if (m_scanX2Thread && m_scanX2Thread->isRunning()) {
        m_scanX2Thread->wait(15000);
        if (m_scanX2Thread->isRunning())
            refreshAlive = true;
    }
    // si un hilo sigue vivo (worker bloqueado en waitForReadyRead), el detach de
    // DLLs al final del proceso crashearia: se fuerza la salida inmediata del OS.
    // farmAlive cubre los threads de farm y de login del spawn (antes solo se
    // revisaba refresh/fetch/qws y un farm vivo disparaba el qFatal del dtor de
    // su QThread hijo: "QThread: Destroyed while thread is still running").
    if (farmAlive || refreshAlive || fetchAlive || qwsAlive) {
#ifdef Q_OS_WIN
        TerminateProcess(GetCurrentProcess(), 0);
#else
        std::_Exit(0);
#endif
    }
}

QString FarmController::resolveDeviceId() const
{
    QString id = m_deviceId.trimmed();
    if (id.isEmpty())
        id = readDeviceId();
    if (id.isEmpty())
        id = QString::fromUtf8(kDefaultDevice);
    return id;
}

QVector<int> FarmController::gemPriorityForDevice(const QString &deviceId) const
{
    QVector<int> priority = m_gemPriorityByDevice.value(deviceId);
    // La cuenta activa ya tiene su vista cargada aunque sea una instalacion
    // antigua que aun no estuviera en el mapa persistido.
    if (priority.isEmpty() && deviceId == resolveDeviceId())
        priority = m_gemPriority;
    for (int color = 0; color < 20; ++color) {
        if (!priority.contains(color))
            priority.append(color);
    }
    return priority;
}

bool FarmController::autoRefreshEnabled() const
{
    // v44 (bug: el switch parecia congelado): ANTES devolvia isActive() del
    // timer. Con el timer limitado a "solo con farms", activar el switch sin
    // farms dejaba el timer parado -> el getter devolvia false -> el switch
    // se auto-deseleccionaba. Devolver el DESEO del usuario (m_autoRefreshWanted,
    // persistido); el timer corre o no segun haya farms (spawn/stopFarm).
    return m_autoRefreshWanted;
}

int FarmController::autoRefreshInterval() const
{
    return m_autoRefreshTimer ? m_autoRefreshTimer->interval() / 1000 : 600;
}

void FarmController::setAutoRespawn(bool on)
{
    if (m_autoRespawn == on)
        return;
    m_autoRespawn = on;
    // Persistido: al reiniciar el programa se conserva (QSettings, org Astro Labs)
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("autoRespawn"), on);
    for (int i = 0; i < m_farms.size(); ++i)
        if (m_farms.at(i).worker) m_farms.at(i).worker->setAutoRespawn(on);
    emit autoRespawnChanged();
}

void FarmController::setDebugEnabled(bool on)
{
    if (m_debugEnabled == on)
        return;
    m_debugEnabled = on;
    emit debugEnabledChanged();
}

void FarmController::setAutoRepair(bool on)
{
    if (m_autoRepair == on)
        return;
    m_autoRepair = on;
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("autoRepair"), on);
    // Solo aplica a las cuentas SELECCIONADAS en el workflow (casilla marcada).
    // Al runnear, spawnOneFarm ya propaga el valor a cada cuenta nueva.
    for (int i = 0; i < m_farms.size(); ++i) {
        bool selected = false;
        for (const auto &sel : m_farmSelection) {
            if (sel.toString() == m_farms.at(i).deviceId) { selected = true; break; }
        }
        if (m_farms.at(i).worker && selected)
            m_farms.at(i).worker->setAutoRepair(on);
    }
    emit autoRepairChanged();
}

void FarmController::setAutoBuyX2(bool on)
{
    if (m_autoBuyX2 == on)
        return;
    m_autoBuyX2 = on;
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("autoBuyX2"), on);
    // Solo aplica a las cuentas SELECCIONADAS en el workflow (casilla marcada).
    for (int i = 0; i < m_farms.size(); ++i) {
        bool selected = false;
        for (const auto &sel : m_farmSelection) {
            if (sel.toString() == m_farms.at(i).deviceId) { selected = true; break; }
        }
        if (m_farms.at(i).worker && selected)
            m_farms.at(i).worker->setAutoBuyX2(on);
    }
    emit autoBuyX2Changed();
}

void FarmController::setDeviceId(const QString &id)
{
    if (m_deviceId == id)
        return;
    m_deviceId = id;
    // v97e2: al cambiar la cuenta activa, cargar el gem priority de ESA cuenta.
    loadGemPriority();
    emit deviceIdChanged();
}

QString FarmController::colorFor(const QString &name) const
{
    QString n = name.toLower();
    if (n.contains("red")) return QStringLiteral("#ff4352");
    if (n.contains("pink")) return QStringLiteral("#efc8d3");
    if (n.contains("forest") || n.contains("bosque") || n.contains("green")) return QStringLiteral("#49b45a");
    if (n.contains("orange")) return QStringLiteral("#ff8e17");
    if (n.contains("silver") || n.contains("plat")) return QStringLiteral("#cfd5d6");
    if (n.contains("blue") || n.contains("indigo")) return QStringLiteral("#6377ff");
    if (n.contains("purple")) return QStringLiteral("#984bde");
    if (n.contains("gold")) return QStringLiteral("#e9b916");
    if (n.contains("yellow")) return QStringLiteral("#e9ef14");
    if (n.contains("white")) return QStringLiteral("#f2f4f1");
    if (n.contains("black")) return QStringLiteral("#161b1f");
    if (n.contains("cyan")) return QStringLiteral("#25d9d5");
    if (n.contains("magenta")) return QStringLiteral("#ed3fec");
    if (n.contains("maroon")) return QStringLiteral("#be4b4c");
    if (n.contains("rainbow")) return QStringLiteral("#32d8dc");
    return QStringLiteral("#a981ff");
}

QVariantMap FarmController::gemMap(const GemInfo &g) const
{
    QVariantMap m;
    m.insert(QStringLiteral("id"), int(g.id));
    m.insert(QStringLiteral("name"), translateGemName(g.name));
    m.insert(QStringLiteral("label"), QStringLiteral("%1 (Lv %2)").arg(translateGemName(g.name)).arg(g.itemLevel));
    m.insert(QStringLiteral("color"), colorFor(g.name));
    m.insert(QStringLiteral("level"), g.itemLevel);
    m.insert(QStringLiteral("exp"), qlonglong(g.exp));
    m.insert(QStringLiteral("cexp"), qlonglong(g.cexp));
    m.insert(QStringLiteral("durability"), g.durability);
    m.insert(QStringLiteral("maxDurability"), g.maxDurability);
    m.insert(QStringLiteral("price"), g.price);
    // sprite de la gema: helper libre gemSpritePath (misma logica que gemsCacheFrom)
    m.insert(QStringLiteral("sprite"), gemSpritePath(g.name, g.itemLevel));
    return m;
}

int FarmController::gemItemId() const
{
    if (m_selectedGem >= 0 && m_selectedGem < m_gems.size())
        return m_gems.at(m_selectedGem).toMap().value(QStringLiteral("id")).toInt();
    return 0;
}

void FarmController::selectGemIndex(int index)
{
    if (index < 0 || index >= m_gems.size())
        return;
    m_selectedGem = index;
    m_gemXpInitial = -1;
    const QVariantMap g = m_gems.at(index).toMap();
    m_gemXpText = QStringLiteral("XP %1/%2 | Gained (delta): -- | Level: %3")
                      .arg(g.value(QStringLiteral("cexp")).toLongLong())
                      .arg(g.value(QStringLiteral("exp")).toLongLong())
                      .arg(g.value(QStringLiteral("level")).toInt());
    emit selectedGemChanged();
    emit gemXpTextChanged();
}

void FarmController::selectGemById(int gemId)
{
    for (int i = 0; i < m_gems.size(); ++i) {
        if (m_gems.at(i).toMap().value(QStringLiteral("id")).toInt() == gemId) {
            selectGemIndex(i);
            return;
        }
    }
}

// Equipa un gem del inventario de la cuenta activa: lo marca como equipado y
// persiste su info (sprite/nombre/cexp/exp/nivel) en la entrada de la cuenta en
// accounts.json, asi el dashboard y la pestaña Accounts muestran la foto de la
// gema equipada aunque no se haya hecho refresh.
void FarmController::equipGem(int index)
{
    if (index < 0 || index >= m_gems.size())
        return;
    m_selectedGem = index;
    const QVariantMap g = m_gems.at(index).toMap();
    const int gemId = g.value(QStringLiteral("id")).toInt();
    // actualiza el gem cacheado de la cuenta activa (marca este como equipado)
    for (auto &gv : m_gems) {
        QVariantMap gm = gv.toMap();
        gm.insert(QStringLiteral("equipped"), gm.value(QStringLiteral("id")).toInt() == gemId);
        gv = gm;
    }
    // persiste en la entrada de la cuenta activa
    for (int i = 0; i < m_accounts.size(); ++i) {
        QVariantMap am = m_accounts.at(i).toMap();
        if (am.value(QStringLiteral("device")).toString() != m_deviceId)
            continue;
        am.insert(QStringLiteral("sprite"), g.value(QStringLiteral("sprite")).toString());
        am.insert(QStringLiteral("gemSummary"), QStringLiteral("%1 Lv%2")
            .arg(translateGemName(g.value(QStringLiteral("name")).toString())).arg(g.value(QStringLiteral("level")).toInt()));
        am.insert(QStringLiteral("gemLevel"), g.value(QStringLiteral("level")).toInt());
        am.insert(QStringLiteral("cexp"), g.value(QStringLiteral("cexp")).toLongLong());
        am.insert(QStringLiteral("exp"), g.value(QStringLiteral("exp")).toLongLong());
        am.insert(QStringLiteral("equippedGemId"), gemId);
        // actualiza los flags equipped del cache "gems" de la cuenta: el
        // dashboard/Accounts reflejan la eleccion al momento (sin refresh)
        QVariantList cached = am.value(QStringLiteral("gems")).toList();
        for (auto &gv : cached) {
            QVariantMap gm = gv.toMap();
            gm.insert(QStringLiteral("equipped"), gm.value(QStringLiteral("id")).toInt() == gemId);
            gv = gm;
        }
        am.insert(QStringLiteral("gems"), cached);
        m_accounts[i] = am;
        break;
    }
    saveAccounts();
    emit accountsChanged();
    emit selectedGemChanged();
    emit gemsChanged(); // re-sincroniza el ListModel del inventario (syncGems)
    // 2026-08-10 (fuente unica de verdad): equipar desde el inventario debe
    // refrescar TAMBIEN el panel "Current gem progress" (m_gemXpText sale de
    // la fila seleccionada, como applyAccountCache).
    if (m_selectedGem >= 0 && m_selectedGem < m_gems.size()) {
        const QVariantMap gs = m_gems.at(m_selectedGem).toMap();
        const qlonglong cexp = gs.value(QStringLiteral("cexp")).toLongLong();
        const qlonglong exp = gs.value(QStringLiteral("exp")).toLongLong();
        const int lvl = gs.value(QStringLiteral("level")).toInt();
        m_gemXpText = QStringLiteral("Gem XP %1/%2 | Gained (delta): -- | Level: %3")
                          .arg(cexp).arg(exp).arg(lvl);
        emit gemXpTextChanged();
    }
    const QString nm = g.value(QStringLiteral("name")).toString();
    emit toastMessage(QStringLiteral("Equipped: %1").arg(nm));
}

void FarmController::clearLogs()
{
    {
        QMutexLocker locker(&m_debugMutex);
        m_logLines.clear();
        m_debugLines.clear();
    }
    emit logLineAdded(QString());
}

void FarmController::appendLog(const QString &line)
{
    {
        QMutexLocker locker(&m_debugMutex);
        m_logLines.append(line);
        if (m_logLines.size() > 2000)
            m_logLines.removeFirst();
    }
    writeLogFile(line);
    emit logLineAdded(line);
}

void FarmController::appendDebug(const QString &line)
{
    // SOLO UI: la persistencia al archivo la hace el llamador (onFarmDebug /
    // el lambda de debugLog del worker) para no escribir dos veces la misma
    // linea cuando el switch Debug esta ON.
    // Mutex: este metodo se llama tambien desde los HILOS DE LOGIN del spawn
    // paralelo (started lambda, hasta 10 a la vez). Sin lock, el append a
    // QStringList de N hilos concurrentes es una data race que corrompe el
    // heap y crashea al pulsar RUN con el switch Debug activado.
    {
        QMutexLocker locker(&m_debugMutex);
        m_debugLines.append(line);
        if (m_debugLines.size() > 2000)
            m_debugLines.removeFirst();
    }
    emit debugLineAdded(line);
}

void FarmController::writeLogFile(const QString &line)
{
    QFile f(QCoreApplication::applicationDirPath() + "/astro_farm.log");
    if (!f.open(QIODevice::Append | QIODevice::Text))
        return;
    f.write("[" + QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")).toUtf8() + "] ");
    f.write(line.toUtf8());
    f.write("\n");
    f.close();
}

void FarmController::fetchGems()
{
    if (m_fetching)
        return;
    m_fetching = true;
    emit busyChanged();
    m_stateText = QStringLiteral("Fetching gems...");
    emit stateTextChanged();

    const QString deviceId = resolveDeviceId();
    const QString pemPath = fakeTpmPathForDevice(deviceId);
    // Sin clave fake TPM propia NO hay atestacion valida: abortar (jamas caer
    // a la clave embebida compartida — el server detecta el mid duplicado).
    if (pemPath.isEmpty()) {
        m_fetching = false;
        emit busyChanged();
        m_stateText = QStringLiteral("Fetch skipped: fake TPM key for this device could not be generated");
        emit stateTextChanged();
        appendLog(m_stateText);
        emit toastMessage(m_stateText);
        return;
    }
    QThread *thread = new QThread(this);
    m_fetchThread = thread;
    // LoginManager LOCAL dentro del lambda del started: su QNetworkAccessManager
    // nace en el hilo del worker (afinidad correcta, cero warnings cross-thread).
    // DirectConnection: el started se emite EN el hilo nuevo, asi el lambda corre
    // ahi (un receiver QThread con AutoConnection correria en el hilo creador).
    connect(thread, &QThread::started, thread, [this, thread, deviceId, pemPath]() {
        LoginManager local;
        // atestacion fake del device para el EH (registra la clave en el server)
        if (!pemPath.isEmpty()) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
        }
        LoginResult r = local.login(deviceId);
        QVector<GemInfo> gems;
        QString realName;
        qlonglong coins = 0;
        if (r.ok) {
            gems = local.fetchInventory(5);
            realName = local.fetchAccountName(); // loginifneeded: nombre + coins
            coins = local.lastCoins();
        }
        QMetaObject::invokeMethod(this, [this, thread, r, gems, realName, coins]() {
            if (r.ok) {
                m_accountText = QStringLiteral("%1")
                                    .arg(realName.isEmpty() ? QStringLiteral("Account") : realName);
                // guarda el sprite/nombre/nivel/XP de la gema equipada en la DB
                // para que el panel derecho del dashboard muestre la foto + barra
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != m_deviceId)
                        continue;
                    if (!realName.isEmpty())
                        am.insert(QStringLiteral("name"), realName);
                    if (!gems.isEmpty()) {
                        // gema equipada: la primera del inventario
                        const GemInfo &eg = gems.first();
                        am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                        am.insert(QStringLiteral("gemSummary"),
                                  QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                        am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                        am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                        am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                        am.insert(QStringLiteral("equippedGemId"), eg.id);
                        am.insert(QStringLiteral("gems"), gemsCacheFrom(gems));
                    }
                    if (coins > 0)
                        am.insert(QStringLiteral("coins"), coins);
                    am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
                    m_accounts[i] = am;
                    break;
                }
                m_gems.clear();
                for (const auto &g : gems)
                    m_gems.append(gemMap(g));
                m_selectedGem = m_gems.isEmpty() ? -1 : 0;
                emit gemsChanged();
                emit selectedGemChanged();
                m_stateText = QStringLiteral("Login OK  |  %1 gems in inventory (slot 5)")
                                  .arg(m_gems.size());
                if (m_gems.isEmpty())
                    m_stateText = QStringLiteral("Login OK  |  No gems in inventory (slot 5)");
                emit toastMessage(m_stateText);
            } else {
                m_accountText = QStringLiteral("Login error");
                m_stateText = r.error;
                emit toastMessage(QStringLiteral("Login error: %1").arg(r.error));
            }
            emit accountTextChanged();
            emit stateTextChanged();
            m_fetching = false;
            emit busyChanged();
            m_fetchThread = nullptr;
            // el thread del fetch debe salir de su event loop: sin esto el QThread
            // hijo quedaria vivo y su destruccion dispararia el qFatal de Qt
            thread->quit();
        }, Qt::QueuedConnection);
    }, Qt::DirectConnection);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// Login HTTP + inventory de TODAS las cuentas guardadas (no solo la activa ni
// las seleccionadas con casilla): actualiza en la DB el nombre real, coins,
// gema equipada y su XP. Se dispara al arrancar (main.cpp) y desde el boton
// si hiciera falta. Un solo hilo secuencial: los logins se serializan con
// g_loginMutex y este flujo no toca la sesion TCP de ningun farm.
void FarmController::fetchAllGems()
{
    if (m_fetching)
        return;
    // snapshot de TODAS las cuentas (device + nombre actual conocido, puede
    // estar vacio si nunca se hizo login): se toma en el GUI thread y el hilo
    // solo lo lee (m_accounts NO se toca desde el worker - data race).
    QVector<QPair<QString, QString>> targets; // (device, name)
    for (const auto &v : m_accounts) {
        const QVariantMap m = v.toMap();
        targets.append({m.value(QStringLiteral("device")).toString(),
                        m.value(QStringLiteral("name")).toString()});
    }
    if (targets.isEmpty()) {
        emit toastMessage(QStringLiteral("No saved accounts to fetch"));
        return;
    }
    m_fetching = true;
    emit busyChanged();
    m_stateText = QStringLiteral("Fetching gems for %1 accounts...").arg(targets.size());
    emit stateTextChanged();

    QThread *thread = new QThread(this);
    m_fetchThread = thread;
    connect(thread, &QThread::started, thread, [this, thread, targets]() {
        // resultados por cuenta: ok / nombre real / coins / gemas del slot 5
        struct FetchOut {
            bool ok = false;
            bool gemsEmptyConfirmed = false; // inventory vacio tras reintento (gemas reales agotadas)
            QString name;
            qlonglong coins = 0;
            QVector<GemInfo> gems;
            QVector<StoreItem> store; // catalogo de la gems shop (do:store category=10)
        };
        QVector<FetchOut> outs(targets.size());
        for (int k = 0; k < targets.size(); ++k) {
            const QString deviceId = targets.at(k).first;
            const QString pemPath = fakeTpmPathForDevice(deviceId);
            if (pemPath.isEmpty())
                continue;
            LoginManager local;
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
            LoginResult r = local.login(deviceId);
            if (!r.ok)
                continue;
            FetchOut &o = outs[k];
            o.ok = true;
            o.name = local.fetchAccountName(); // loginifneeded: nombre + coins
            o.coins = local.lastCoins();
            o.gems = local.fetchInventory(5);
            // inventory vacio puede ser un hiccup HTTP transitorio (igual que
            // en spawn): se reintenta UNA vez antes de dar la cuenta por sin
            // gemas. Si sigue vacio, es un inventario REALMENTE vacio (las
            // gemas se farmearon/vendieron) -> la UI debe limpiar los campos
            // viejos (pedido 2026-08-08: las gemas guardadas seguian visibles).
            if (o.gems.isEmpty()) {
                writeLogFile(QStringLiteral("[DBG] fetchAll %1 inventory slot=5 vacio, reintento en 1000ms")
                                 .arg(deviceId.left(16)));
                QThread::msleep(1000);
                o.gems = local.fetchInventory(5);
            }
            o.gemsEmptyConfirmed = o.gems.isEmpty();
            // gems shop precargada (pedido 2026-08-09): el catalogo de gemas
            // comprables se trae con el mismo login, asi el boton Shop abre
            // al instante sin otro round-trip de red.
            o.store = local.fetchStore(10);
            writeLogFile(QStringLiteral("[DBG] fetchAll %1 ok name=%2 coins=%3 gems=%4 store=%5%6")
                             .arg(deviceId.left(16), o.name, QString::number(o.coins),
                                  QString::number(o.gems.size()), QString::number(o.store.size()),
                                  o.gemsEmptyConfirmed ? QStringLiteral(" (inventory vacio confirmado)") : QString()));
        }
        // aplica los resultados en el GUI thread (m_accounts/m_gems viven ahi)
        QMetaObject::invokeMethod(this, [this, thread, targets, outs]() {
            for (int k = 0; k < targets.size(); ++k) {
                const FetchOut &o = outs.at(k);
                if (!o.ok)
                    continue;
                const QString deviceId = targets.at(k).first;
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != deviceId)
                        continue;
                    if (!o.name.isEmpty())
                        am.insert(QStringLiteral("name"), o.name);
                    if (o.coins > 0)
                        am.insert(QStringLiteral("coins"), o.coins);
                    if (!o.gems.isEmpty()) {
                        const GemInfo &eg = o.gems.first();
                        am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                        am.insert(QStringLiteral("gemSummary"),
                                  QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                        am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                        am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                        am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                        am.insert(QStringLiteral("equippedGemId"), eg.id);
                        am.insert(QStringLiteral("gems"), gemsCacheFrom(o.gems));
                    } else if (o.gemsEmptyConfirmed) {
                        // Inventory vacio CONFIRMADO (tras reintento): las gemas
                        // de esta cuenta se agotaron (farmed/vendidas). Limpiar
                        // los campos de gema para que la UI muestre vacio en vez
                        // de las gemas viejas guardadas (pedido 2026-08-08).
                        am.remove(QStringLiteral("sprite"));
                        am.remove(QStringLiteral("gemSummary"));
                        am.remove(QStringLiteral("gemLevel"));
                        am.remove(QStringLiteral("cexp"));
                        am.remove(QStringLiteral("exp"));
                        am.remove(QStringLiteral("equippedGemId"));
                        am.remove(QStringLiteral("gems"));
                    }
                    am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
                    // shop precargado: se guarda en la cuenta para que el boton
                    // Shop abra al instante con el catalogo del ultimo arranque
                    if (!o.store.isEmpty())
                        am.insert(QStringLiteral("shopCache"), storeItemsCacheFrom(o.store));
                    else
                        am.remove(QStringLiteral("shopCache"));
                    m_accounts[i] = am;
                    break;
                }
            }
            // refresca el panel de la cuenta activa con su inventario
            const QString activeId = resolveDeviceId();
            for (int k = 0; k < targets.size(); ++k) {
                const FetchOut &o = outs.at(k);
                if (!o.ok || targets.at(k).first != activeId)
                    continue;
                m_gems.clear();
                for (const auto &g : o.gems)
                    m_gems.append(gemMap(g));
                m_selectedGem = m_gems.isEmpty() ? -1 : 0;
                emit gemsChanged();
                emit selectedGemChanged();
                break;
            }
            m_fetching = false;
            emit busyChanged();
            emit accountsChanged();
            // Persistir YA el limpiado de gemas (cuentas con inventory vacio
            // confirmado): sin saveAccounts, accounts.json seguia con los
            // campos de gema viejos y la UI los mostraba al proximo arranque.
            sortAccounts();
            saveAccounts();
            m_stateText = QStringLiteral("Login OK | gems updated for %1 accounts").arg(targets.size());
            emit stateTextChanged();
            thread->quit();
        }, Qt::QueuedConnection);
    }, Qt::DirectConnection);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// ===================== SHOP POR CUENTA (pedido 2026-08-08) =====================
// fetchShop(device): login HTTP de la cuenta + inventory slot=5 (gemas con
// precio) + coins. Todo en un thread propio; el resultado se aplica en el GUI
// thread (m_shopGems se lee desde QML). El formato de compra se verifico contra
// el server real: {"do":"buy","item":<id>} -> ok | funds_insufficient |
// invalid_item (el id se valida contra el catalogo del store).
void FarmController::fetchShop(const QString &device)
{
    if (m_shopBusy)
        return;
    if (device.isEmpty())
        return;
    // snapshot en GUI thread (NUNCA leer m_accounts desde el hilo: familia
    // 0x1CE857 de Qt 6.10.3 con QHash internos). Si la cuenta ya tiene el
    // catalogo precargado del arranque (fetchAllGems -> shopCache), se muestra
    // AL INSTANTE y el login de refresco corre en segundo plano (pedido
    // 2026-08-09: la gems shop carga en todas las cuentas guardadas).
    QString name;
    QVariantList cachedShop;
    bool hasCache = false;
    for (const auto &v : m_accounts) {
        const QVariantMap am = v.toMap();
        if (am.value(QStringLiteral("device")).toString() == device) {
            name = am.value(QStringLiteral("name")).toString();
            cachedShop = am.value(QStringLiteral("shopCache")).toList();
            hasCache = !cachedShop.isEmpty();
            break;
        }
    }
    if (hasCache) {
        // El caché guardado puede tener sprites con banda vieja persistida de
        // un build anterior (ej. 05 cuando el item es nivel 1). Se normaliza
        // la banda al NIVEL REAL de cada item para que no haya flicker 05->01
        // al refrescar (pedido 2026-08-09).
        QVariantList normalized;
        for (const auto &cv : cachedShop) {
            QVariantMap cm = cv.toMap();
            const int lvl = cm.value(QStringLiteral("level")).toInt();
            const QString sp = cm.value(QStringLiteral("sprite")).toString();
            const int dash = sp.lastIndexOf(QLatin1Char('-'));
            if (dash > 0) {
                int band = qBound(1, (lvl - 1) / 5 + 1, 5);
                cm.insert(QStringLiteral("sprite"),
                          sp.left(dash + 1) + QStringLiteral("%1.png").arg(band, 2, 10, QLatin1Char('0')));
            }
            normalized.append(cm);
        }
        m_shopGems = normalized;
        m_shopCoins = 0; // el coins fresco se actualiza con el refresh
        m_shopBusy = true;
        m_shopStatus = QStringLiteral("Shop (cached from startup)...");
        m_shopDeviceName = name.isEmpty() ? shortDevice(device) : name;
        m_shopDevice = device;
        emit shopChanged();
    } else {
        m_shopBusy = true;
        m_shopStatus = QStringLiteral("Loading shop...");
        m_shopDeviceName = name.isEmpty() ? shortDevice(device) : name;
        m_shopDevice = device;
        emit shopChanged();
    }
    const QString pemPath = fakeTpmPathForDevice(device);
    QThread *thread = QThread::create([this, device, pemPath]() {
        LoginManager local;
        if (!pemPath.isEmpty()) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
        }
        const LoginResult r = local.login(device);
        struct ShopOut {
            bool ok = false;
            qlonglong coins = 0;
            QVector<StoreItem> items;
            QString error;
        } out;
        if (!r.ok) {
            out.error = r.error;
        } else {
            out.coins = local.lastCoins();
            if (out.coins <= 0) {
                const QString n = local.fetchAccountName();
                if (!n.isEmpty())
                    out.coins = local.lastCoins();
            }
            out.items = local.fetchStore(10); // gemas del catalogo (do:store category=10)
            out.ok = true;
        }
        const ShopOut o = out;
        QMetaObject::invokeMethod(this, [this, o, device]() {
            m_shopGems.clear();
            if (o.ok) {
                for (const auto &s : o.items) {
                    QVariantMap m;
                    m.insert(QStringLiteral("id"), s.id);
                    m.insert(QStringLiteral("name"), translateGemName(s.name));
                    // sprite con el NIVEL REAL (banda 01-05), no el tope 05
                    m.insert(QStringLiteral("sprite"), gemSpritePath(s.name, s.level));
                    m.insert(QStringLiteral("level"), s.level);
                    m.insert(QStringLiteral("price"), s.price);
                    m.insert(QStringLiteral("exp"), s.exp);
                    m.insert(QStringLiteral("owned"), s.owned);
                    m.insert(QStringLiteral("purchasable"), s.purchasable);
                    m.insert(QStringLiteral("attrs"), s.attrs);
                    // attrsText: QStringList legible para QML ("speed +4", ...)
                    QStringList attrsText;
                    for (const auto &av : s.attrs) {
                        const QVariantList pair = av.toList();
                        if (pair.size() >= 2)
                            attrsText.append(pair[0].toString() + " +" + pair[1].toString());
                    }
                    m.insert(QStringLiteral("attrsText"), attrsText);
                    m_shopGems.append(m);
                }
                m_shopCoins = o.coins;
                m_shopStatus = QStringLiteral("%1 gems in shop, %2 coins").arg(m_shopGems.size()).arg(m_shopCoins);
                // refresca el shopCache de la cuenta para el proximo arranque
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() == device) {
                        if (!o.items.isEmpty())
                            am.insert(QStringLiteral("shopCache"), storeItemsCacheFrom(o.items));
                        else
                            am.remove(QStringLiteral("shopCache"));
                        m_accounts[i] = am;
                        break;
                    }
                }
            } else {
                m_shopStatus = QStringLiteral("Shop failed: %1").arg(o.error.left(80));
            }
            m_shopBusy = false;
            emit shopChanged();
        }, Qt::QueuedConnection);
    });
    thread->setObjectName(QStringLiteral("shopFetch"));
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// Compra una gema de la cuenta del shop con {"do":"buy","item":<id>}.
// El server valida el id contra el catalogo; si los coins no alcanzan
// responde funds_insufficient (verificado en vivo). Tras la compra se
// refresca el inventory para reflejar la gema nueva.
void FarmController::buyShopGem(int gemId)
{
    if (m_shopBusy || m_shopDevice.isEmpty())
        return;
    const QString device = m_shopDevice;
    const QString pemPath = fakeTpmPathForDevice(device);
    m_shopBusy = true;
    m_shopStatus = QStringLiteral("Buying gem %1...").arg(gemId);
    emit shopChanged();
    QThread *thread = QThread::create([this, device, pemPath, gemId]() {
        LoginManager local;
        if (!pemPath.isEmpty()) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
        }
        const LoginResult r = local.login(device);
        QString resultMsg;
        bool ok = false;
        if (r.ok) {
            const QJsonObject resp = local.apiCall(QStringLiteral("{\"do\":\"buy\",\"item\":%1}").arg(gemId));
            resultMsg = resp.value(QStringLiteral("message")).toString();
            ok = resp.value(QStringLiteral("result")).toString() == QLatin1String("ok");
            if (!ok && resultMsg.isEmpty())
                resultMsg = resp.value(QStringLiteral("result")).toString();
        } else {
            resultMsg = QStringLiteral("login failed: %1").arg(r.error.left(60));
        }
        struct BuyOut {
            bool ok = false;
            QString msg;
            qlonglong coins = 0;
            QVector<StoreItem> items;
            QVector<GemInfo> inventory; // refetch tras comprar (refleja la gema nueva)
            QString realName;
        } out;
        out.ok = ok;
        out.msg = resultMsg;
        // refresca coins + store si la compra fue exitosa o si al menos
        // el login funciono (el store siempre refleja el estado real)
        if (r.ok) {
            out.coins = local.lastCoins();
            out.items = local.fetchStore(10);
            if (out.coins <= 0)
                (void)local.fetchAccountName();
            // INVENTORY REFRESH tras compra (pedido 2026-08-09: la gema
            // comprada no se reflejaba en el Gem inventory de la GUI)
            if (ok) {
                QThread::msleep(700); // asienta la compra antes del inventory
                out.inventory = local.fetchInventory(5);
                out.realName = local.fetchAccountName();
                if (out.inventory.isEmpty()) {
                    QThread::msleep(1000);
                    out.inventory = local.fetchInventory(5);
                }
            }
        }
        const BuyOut o = out;
        QMetaObject::invokeMethod(this, [this, o]() {
            if (o.ok) {
                m_shopStatus = QStringLiteral("Bought gem %1!").arg(o.msg);
                appendLog(QStringLiteral("[Shop] Gem %1 bought (%2)").arg(o.msg).arg(m_shopDeviceName));
            } else {
                m_shopStatus = QStringLiteral("Buy failed: %1").arg(o.msg);
            }
            if (!o.items.isEmpty() || o.ok) {
                m_shopGems.clear();
                for (const auto &s : o.items) {
                    QVariantMap m;
                    m.insert(QStringLiteral("id"), s.id);
                    m.insert(QStringLiteral("name"), translateGemName(s.name));
                    m.insert(QStringLiteral("sprite"), gemSpritePath(s.name, s.level));
                    m.insert(QStringLiteral("level"), s.level);
                    m.insert(QStringLiteral("price"), s.price);
                    m.insert(QStringLiteral("exp"), s.exp);
                    m.insert(QStringLiteral("owned"), s.owned);
                    m.insert(QStringLiteral("purchasable"), s.purchasable);
                    m.insert(QStringLiteral("attrs"), s.attrs);
                    QStringList attrsText;
                    for (const auto &av : s.attrs) {
                        const QVariantList pair = av.toList();
                        if (pair.size() >= 2)
                            attrsText.append(pair[0].toString() + " +" + pair[1].toString());
                    }
                    m.insert(QStringLiteral("attrsText"), attrsText);
                    m_shopGems.append(m);
                }
                m_shopCoins = o.coins;
            }
            // aplica el inventory fresco de la cuenta del shop: la gema nueva
            // debe verse en el Gem inventory de la GUI y en el cache guardado
            if (o.ok && !o.inventory.isEmpty()) {
                const QString dev = m_shopDevice;
                // si la cuenta del shop es la activa, refresca el panel
                // (el QML ya conecta onGemsChanged -> syncGems())
                if (resolveDeviceId() == dev) {
                    m_gems.clear();
                    for (const auto &g : o.inventory)
                        m_gems.append(gemMap(g));
                    m_selectedGem = m_gems.isEmpty() ? -1 : 0;
                    emit gemsChanged();
                    emit selectedGemChanged();
                }
                // actualiza la entrada de la cuenta (cache + resumen de gema)
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != dev)
                        continue;
                    if (!o.realName.isEmpty())
                        am.insert(QStringLiteral("name"), o.realName);
                    if (o.coins > 0)
                        am.insert(QStringLiteral("coins"), o.coins);
                    const GemInfo &eg = o.inventory.first();
                    am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                    am.insert(QStringLiteral("gemSummary"),
                              QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                    am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                    am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                    am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                    am.insert(QStringLiteral("equippedGemId"), eg.id);
                    am.insert(QStringLiteral("gems"), gemsCacheFrom(o.inventory));
                    if (!o.items.isEmpty())
                        am.insert(QStringLiteral("shopCache"), storeItemsCacheFrom(o.items));
                    m_accounts[i] = am;
                    break;
                }
                saveAccounts();
            }
            m_shopBusy = false;
            emit shopChanged();
            emit accountsChanged();
        }, Qt::QueuedConnection);
    });
    thread->setObjectName(QStringLiteral("shopBuy"));
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// ===================== BUY X2 GEMAS =====================
// Compra 2 gemas del shop: dos sequential {"do":"buy","item":<id>} con
// refresh entre ellas. Se usa un solo thread (las compras son serializadas
// para evitar race del store entre cuentas).
void FarmController::buyShopGemX2(int gemId)
{
    if (m_shopBusy || m_shopDevice.isEmpty())
        return;
    const QString device = m_shopDevice;
    const QString pemPath = fakeTpmPathForDevice(device);
    m_shopBusy = true;
    m_shopStatus = QStringLiteral("Buying x2 gem %1...").arg(gemId);
    emit shopChanged();
    QThread *thread = QThread::create([this, device, pemPath, gemId]() {
        LoginManager local;
        if (!pemPath.isEmpty()) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
        }
        const LoginResult r = local.login(device);
        QString resultMsg1, resultMsg2;
        bool ok1 = false, ok2 = false;
        if (r.ok) {
            // primera compra
            const QJsonObject resp1 = local.apiCall(QStringLiteral("{\"do\":\"buy\",\"item\":%1}").arg(gemId));
            resultMsg1 = resp1.value(QStringLiteral("message")).toString();
            ok1 = resp1.value(QStringLiteral("result")).toString() == QLatin1String("ok");
            if (!ok1 && resultMsg1.isEmpty())
                resultMsg1 = resp1.value(QStringLiteral("result")).toString();
            if (ok1) {
                QThread::msleep(1200); // asienta la compra antes de la segunda
                // segunda compra
                const QJsonObject resp2 = local.apiCall(QStringLiteral("{\"do\":\"buy\",\"item\":%1}").arg(gemId));
                resultMsg2 = resp2.value(QStringLiteral("message")).toString();
                ok2 = resp2.value(QStringLiteral("result")).toString() == QLatin1String("ok");
                if (!ok2 && resultMsg2.isEmpty())
                    resultMsg2 = resp2.value(QStringLiteral("result")).toString();
            }
        } else {
            resultMsg1 = QStringLiteral("login failed: %1").arg(r.error.left(60));
        }
        struct BuyOut {
            bool ok = false;
            QString msg;
            qlonglong coins = 0;
            QVector<StoreItem> items;
            QVector<GemInfo> inventory;
            QString realName;
        } out;
        out.ok = ok1; // ok si al menos la primera funciono
        out.msg = ok1 ? (ok2 ? QStringLiteral("x2 bought!") : QStringLiteral("1/2 bought: %1").arg(resultMsg2)) : resultMsg1;
        if (r.ok) {
            out.coins = local.lastCoins();
            out.items = local.fetchStore(10);
            if (out.coins <= 0)
                (void)local.fetchAccountName();
            if (ok1) {
                QThread::msleep(700);
                out.inventory = local.fetchInventory(5);
                out.realName = local.fetchAccountName();
                if (out.inventory.isEmpty()) {
                    QThread::msleep(1000);
                    out.inventory = local.fetchInventory(5);
                }
            }
        }
        const BuyOut o = out;
        QMetaObject::invokeMethod(this, [this, o]() {
            if (o.ok) {
                m_shopStatus = QStringLiteral("Bought x2: %1").arg(o.msg);
                appendLog(QStringLiteral("[Shop] Gem x2 bought (%1)").arg(m_shopDeviceName));
            } else {
                m_shopStatus = QStringLiteral("Buy x2 failed: %1").arg(o.msg);
            }
            if (!o.items.isEmpty() || o.ok) {
                m_shopGems.clear();
                for (const auto &s : o.items) {
                    QVariantMap m;
                    m.insert(QStringLiteral("id"), s.id);
                    m.insert(QStringLiteral("name"), translateGemName(s.name));
                    m.insert(QStringLiteral("sprite"), gemSpritePath(s.name, s.level));
                    m.insert(QStringLiteral("level"), s.level);
                    m.insert(QStringLiteral("price"), s.price);
                    m.insert(QStringLiteral("exp"), s.exp);
                    m.insert(QStringLiteral("owned"), s.owned);
                    m.insert(QStringLiteral("purchasable"), s.purchasable);
                    m.insert(QStringLiteral("attrs"), s.attrs);
                    QStringList attrsText;
                    for (const auto &av : s.attrs) {
                        const QVariantList pair = av.toList();
                        if (pair.size() >= 2)
                            attrsText.append(pair[0].toString() + " +" + pair[1].toString());
                    }
                    m.insert(QStringLiteral("attrsText"), attrsText);
                    m_shopGems.append(m);
                }
                m_shopCoins = o.coins;
            }
            if (o.ok && !o.inventory.isEmpty()) {
                const QString dev = m_shopDevice;
                if (resolveDeviceId() == dev) {
                    m_gems.clear();
                    for (const auto &g : o.inventory)
                        m_gems.append(gemMap(g));
                    m_selectedGem = m_gems.isEmpty() ? -1 : 0;
                    emit gemsChanged();
                    emit selectedGemChanged();
                }
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != dev)
                        continue;
                    if (!o.realName.isEmpty())
                        am.insert(QStringLiteral("name"), o.realName);
                    if (o.coins > 0)
                        am.insert(QStringLiteral("coins"), o.coins);
                    if (!o.inventory.isEmpty()) {
                        const GemInfo &eg = o.inventory.first();
                        am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                        am.insert(QStringLiteral("gemSummary"),
                                  QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                        am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                        am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                        am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                        am.insert(QStringLiteral("equippedGemId"), eg.id);
                        am.insert(QStringLiteral("gems"), gemsCacheFrom(o.inventory));
                    }
                    if (!o.items.isEmpty())
                        am.insert(QStringLiteral("shopCache"), storeItemsCacheFrom(o.items));
                    m_accounts[i] = am;
                    break;
                }
                saveAccounts();
            }
            m_shopBusy = false;
            emit shopChanged();
            emit accountsChanged();
        }, Qt::QueuedConnection);
    });
    thread->setObjectName(QStringLiteral("shopBuyX2"));
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// ===================== REPAIR GEMAS =====================
// Repara una gema rota con {"do":"repair","item":<id>,"slot":5}.
// El server cobra un repair_price proporcional al dano y restaura la
// durability al maximo.
void FarmController::repairGem(int gemId)
{
    if (m_shopBusy || m_shopDevice.isEmpty())
        return;
    const QString device = m_shopDevice;
    const QString pemPath = fakeTpmPathForDevice(device);
    m_shopBusy = true;
    m_shopStatus = QStringLiteral("Repairing gem %1...").arg(gemId);
    emit shopChanged();
    QThread *thread = QThread::create([this, device, pemPath, gemId]() {
        LoginManager local;
        if (!pemPath.isEmpty()) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly)) {
                local.setAttestPem(QString::fromUtf8(pf.readAll()));
                pf.close();
            }
        }
        const LoginResult r = local.login(device);
        QString resultMsg;
        bool ok = false;
        if (r.ok) {
            const QJsonObject resp = local.apiCall(QStringLiteral("{\"do\":\"repair\",\"item\":%1,\"slot\":5}").arg(gemId));
            resultMsg = resp.value(QStringLiteral("message")).toString();
            ok = resp.value(QStringLiteral("result")).toString() == QLatin1String("ok");
            if (!ok && resultMsg.isEmpty())
                resultMsg = resp.value(QStringLiteral("result")).toString();
        } else {
            resultMsg = QStringLiteral("login failed: %1").arg(r.error.left(60));
        }
        struct RepairOut {
            bool ok = false;
            QString msg;
            qlonglong coins = 0;
            QVector<StoreItem> items;
            QVector<GemInfo> inventory;
            QString realName;
        } out;
        out.ok = ok;
        out.msg = resultMsg;
        if (r.ok) {
            out.coins = local.lastCoins();
            out.items = local.fetchStore(10);
            if (ok) {
                QThread::msleep(700);
                out.inventory = local.fetchInventory(5);
                out.realName = local.fetchAccountName();
            }
        }
        const RepairOut o = out;
        QMetaObject::invokeMethod(this, [this, o]() {
            if (o.ok) {
                m_shopStatus = QStringLiteral("Gem repaired!");
                appendLog(QStringLiteral("[Shop] Gem repaired (%1)").arg(m_shopDeviceName));
            } else {
                m_shopStatus = QStringLiteral("Repair failed: %1").arg(o.msg);
            }
            if (!o.items.isEmpty()) {
                m_shopGems.clear();
                for (const auto &s : o.items) {
                    QVariantMap m;
                    m.insert(QStringLiteral("id"), s.id);
                    m.insert(QStringLiteral("name"), translateGemName(s.name));
                    m.insert(QStringLiteral("sprite"), gemSpritePath(s.name, s.level));
                    m.insert(QStringLiteral("level"), s.level);
                    m.insert(QStringLiteral("price"), s.price);
                    m.insert(QStringLiteral("exp"), s.exp);
                    m.insert(QStringLiteral("owned"), s.owned);
                    m.insert(QStringLiteral("purchasable"), s.purchasable);
                    m.insert(QStringLiteral("attrs"), s.attrs);
                    QStringList attrsText;
                    for (const auto &av : s.attrs) {
                        const QVariantList pair = av.toList();
                        if (pair.size() >= 2)
                            attrsText.append(pair[0].toString() + " +" + pair[1].toString());
                    }
                    m.insert(QStringLiteral("attrsText"), attrsText);
                    m_shopGems.append(m);
                }
                m_shopCoins = o.coins;
            }
            if (o.ok && !o.inventory.isEmpty()) {
                const QString dev = m_shopDevice;
                if (resolveDeviceId() == dev) {
                    m_gems.clear();
                    for (const auto &g : o.inventory)
                        m_gems.append(gemMap(g));
                    m_selectedGem = m_gems.isEmpty() ? -1 : 0;
                    emit gemsChanged();
                    emit selectedGemChanged();
                }
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != dev)
                        continue;
                    if (!o.realName.isEmpty())
                        am.insert(QStringLiteral("name"), o.realName);
                    if (o.coins > 0)
                        am.insert(QStringLiteral("coins"), o.coins);
                    if (!o.inventory.isEmpty()) {
                        const GemInfo &eg = o.inventory.first();
                        am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                        am.insert(QStringLiteral("gemSummary"),
                                  QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                        am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                        am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                        am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                        am.insert(QStringLiteral("equippedGemId"), eg.id);
                        am.insert(QStringLiteral("gems"), gemsCacheFrom(o.inventory));
                    }
                    if (!o.items.isEmpty())
                        am.insert(QStringLiteral("shopCache"), storeItemsCacheFrom(o.items));
                    m_accounts[i] = am;
                    break;
                }
                saveAccounts();
            }
            m_shopBusy = false;
            emit shopChanged();
            emit accountsChanged();
        }, Qt::QueuedConnection);
    });
    thread->setObjectName(QStringLiteral("shopRepair"));
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// ===================== PRIORIDAD DE GEMAS (pedido 2026-08-08) =====================
// Prioridad de gemas: indices de color (0-19) en orden de farmeo.
// El auto-buy del spawn compra primero el color que esta mas arriba.
void FarmController::loadGemPriority()
{
    // v97e4: el orden por CUENTA persistido como un QVariantMap COMPLETO en
    // el QSettings ("gemPriorityAll": device -> lista). El mapa en memoria
    // siempre se reconstruye desde el archivo (sin desincronizaciones).
    const QString dev = resolveDeviceId();
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    const QVariantMap all = s.value(QStringLiteral("gemPriorityAll")).toMap();
    appendLog(QStringLiteral("[DEBUG] loadGemPriority dev=%1 claves=%2")
                  .arg(dev.left(16)).arg(all.keys().size()));
    m_gemPriorityByDevice.clear();
    for (auto it = all.constBegin(); it != all.constEnd(); ++it) {
        QVector<int> list;
        for (const auto &sv : it.value().toList()) {
            const int idx = sv.toInt();
            if (idx >= 0 && idx < 20)
                list.append(idx);
        }
        m_gemPriorityByDevice.insert(it.key(), list);
    }
    m_gemPriority.clear();
    if (m_gemPriorityByDevice.contains(dev))
        m_gemPriority = m_gemPriorityByDevice.value(dev);
    // rellenar las que faltan al final en orden natural
    for (int i = 0; i < 20; ++i)
        if (!m_gemPriority.contains(i))
            m_gemPriority.append(i);
    emit gemPriorityChanged();
}

void FarmController::saveGemPriority()
{
    // v97e4: persistir el QVariantMap COMPLETO (device -> lista) — el orden
    // de CADA cuenta queda en el archivo, sin depender del mapa en memoria.
    const QString dev = resolveDeviceId();
    QStringList orderDbg;
    for (int idx : m_gemPriority)
        orderDbg.append(QString::number(idx));
    appendLog(QStringLiteral("[DEBUG] saveGemPriority dev=%1 orden=%2")
                  .arg(dev.left(16), orderDbg.join(QLatin1Char(','))));
    m_gemPriorityByDevice.insert(dev, m_gemPriority);
    QVariantMap all;
    for (auto it = m_gemPriorityByDevice.constBegin(); it != m_gemPriorityByDevice.constEnd(); ++it) {
        QVariantList list;
        for (int idx : it.value())
            list.append(idx);
        all.insert(it.key(), list);
    }
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("gemPriorityAll"), all);
    // v97e1: sync inmediato (el cierre abrupto perdia la config).
    s.sync();
    emit gemPriorityChanged();
}

// 2026-08-10: auto-buy de la tienda por color. El boton "Auto buy" de la
// seccion de prioridad marca el color; la compra la ejecuta runStoreAutoBuy()
// 1 min despues del reinicio de la tienda (19:00/01:00 hora Colombia =
// 00:00/06:00 UTC).
void FarmController::toggleAutoBuyColor(int colorIdx, bool on)
{
    if (colorIdx < 0 || colorIdx >= 20)
        return;
    if (on)
        m_autoBuyColors.insert(colorIdx);
    else
        m_autoBuyColors.remove(colorIdx);
    QStringList raw;
    for (int idx : m_autoBuyColors)
        raw.append(QString::number(idx));
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("autoBuyColors"), raw);
    emit autoBuyColorsChanged();
}

bool FarmController::isAutoBuyColor(int colorIdx) const
{
    return m_autoBuyColors.contains(colorIdx);
}

// Proximo reinicio de la tienda en HORA LOCAL del usuario: Colombia es UTC-5
// sin DST, asi que 19:00/01:00 COT = 00:00/06:00 UTC. La compra va 1 min
// despues. Devuelve texto legible para el QML (e.g. "02:01" hora local).
QString FarmController::nextStoreBuyTime() const
{
    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    // slots UTC: 00:01 y 06:01 (reinicio + 1 min)
    for (int h : {0, 6}) {
        QDateTime slot(nowUtc.date(), QTime(h, 1), Qt::UTC);
        if (slot <= nowUtc)
            slot = slot.addDays(1);
        const QDateTime local = slot.toLocalTime();
        return local.toString(QStringLiteral("hh:mm")) + QStringLiteral(" (hora local)");
    }
    return QString();
}

// Timer cada 30s: si es el slot de compra (00:01-00:05 o 06:01-06:05 UTC) y
// aun no se compro en este slot, comprar los colores marcados en TODAS las
// cuentas guardadas. El server valida el id contra el catalogo (buy invalido
// -> invalid_item) y rechaza duplicados (owned=true -> no se recompran).
void FarmController::runStoreAutoBuy()
{
    if (m_autoBuyColors.isEmpty())
        return;
    if (m_shopBusy || m_qwsLoading || m_fetching || m_spawning.load())
        return;
    // v97af (pedido del usuario 2026-08-15): auto-buy TOTALMENTE desactivado
    // (tanto el de rotacion de tienda como el de prioridad en el spawn).
    Q_UNUSED(m_autoBuyColors);
    return;
    const QDateTime nowUtc = QDateTime::currentDateTimeUtc();
    const int hourUtc = nowUtc.time().hour();
    const int minuteUtc = nowUtc.time().minute();
    // slots de compra: 00:01-00:05 y 06:01-06:05 UTC (1 min despues del
    // reinicio de las 19:00/01:00 COT). Ventana de 4 min para tolerar el tick
    // de 30s y posibles reinicios del timer.
    if (!((hourUtc == 0 && minuteUtc >= 1 && minuteUtc <= 5)
          || (hourUtc == 6 && minuteUtc >= 1 && minuteUtc <= 5)))
        return;
    const QString slotKey = nowUtc.toString(QStringLiteral("yyyy-MM-dd HH"));
    if (m_lastStoreBuySlot == slotKey)
        return; // este slot ya se proceso
    m_lastStoreBuySlot = slotKey;
    appendLog(QStringLiteral("Store auto-buy: rotacion de tienda detectada (slot UTC %1)").arg(slotKey));

    // Comprar en todas las cuentas guardadas, secuencial (1 login a la vez
    // para no saturar el rate-limit del server).
    for (int i = 0; i < m_accounts.size(); ++i) {
        const QVariantMap am = m_accounts.at(i).toMap();
        const QString device = am.value(QStringLiteral("device")).toString();
        if (device.isEmpty())
            continue;
        const QString name = am.value(QStringLiteral("name")).toString();
        // login HTTP de la cuenta + store category=10 (gemas del catalogo)
        QThread *thread = new QThread(this);
        connect(thread, &QThread::started, thread, [this, thread, device, name]() {
            LoginManager local;
            const QString pemPath = fakeTpmPathForDevice(device);
            if (!pemPath.isEmpty()) {
                QFile pf(pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
            }
            const LoginResult r = local.login(device);
            struct BuyOut {
                bool ok = false;
                QString msg;
                int bought = 0;
            };
            BuyOut out;
            if (!r.ok) {
                out.msg = QStringLiteral("login failed: %1").arg(r.error.left(60));
            } else {
                const QVector<StoreItem> items = local.fetchStore(10);
                for (const StoreItem &it : items) {
                    // comprar SOLO los colores marcados con auto-buy
                    const int ci = gemColorIndexByName(it.name);
                    if (ci < 0 || !m_autoBuyColors.contains(ci))
                        continue;
                    if (it.owned || !it.purchasable)
                        continue;
                    const QJsonObject buyResp = local.apiCall(
                        QStringLiteral("{\"do\":\"buy\",\"item\":%1}").arg(it.id));
                    const bool buyOk = buyResp.value("result").toString() == QLatin1String("ok");
                    if (buyOk) {
                        ++out.bought;
                        appendLog(QStringLiteral("Store auto-buy: %1 compro '%2' (%3)")
                                      .arg(name).arg(it.name).arg(it.price));
                    } else {
                        appendLog(QStringLiteral("Store auto-buy: %1 fallo '%2': %3")
                                      .arg(name).arg(it.name)
                                      .arg(buyResp.value("message").toString().left(60)));
                    }
                }
                out.msg = QStringLiteral("%1 gemas del color marcado compradas").arg(out.bought);
            }
            QMetaObject::invokeMethod(this, [this, out]() {
                appendLog(QStringLiteral("Store auto-buy: %1").arg(out.msg));
            }, Qt::QueuedConnection);
            thread->quit();
        }, Qt::DirectConnection);
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
        // secuencial: esperar este login+compra antes del siguiente (evita
        // 10 logins simultaneos = rate-limit). Espera con tope de 25s.
        if (!thread->wait(25000)) {
            thread->quit();
            thread->wait(2000);
        }
    }
}

void FarmController::moveGemPriority(int from, int to)
{
    if (from < 0 || from >= m_gemPriority.size())
        return;
    if (to < 0) to = 0;
    if (to >= m_gemPriority.size()) to = m_gemPriority.size() - 1;
    if (from == to) return;
    const int item = m_gemPriority.at(from);
    m_gemPriority.remove(from);
    m_gemPriority.insert(to, item);
    saveGemPriority();
}

// El modelo QML (priorityQmlModel) se reordena en vivo durante el drag; el
// backend m_gemPriority NO se toco. Al soltar, la UI manda el orden final
// (lista de ids) y aqui se reconstruye m_gemPriority en ese orden exacto.
void FarmController::applyPriorityOrder(const QVariantList &orderedIds)
{
    QVector<int> newOrder;
    newOrder.reserve(m_gemPriority.size());
    for (const QVariant &value : orderedIds) {
        // QML puede entregar una lista de objetos del modelo o, como hace la
        // UI actual, una lista de ids simples. Aceptar ambos evita que el
        // orden llegue vacio al backend.
        const QVariantMap item = value.toMap();
        bool ok = false;
        const int id = item.isEmpty()
            ? value.toInt(&ok)
            : item.value(QStringLiteral("id")).toInt(&ok);
        if (ok && id >= 0 && id < 20 && m_gemPriority.contains(id)
            && !newOrder.contains(id)) {
            newOrder.append(id);
        }
    }

    // Si el modelo visible no contiene alguna gema, conservarla al final.
    // Comparar contra el orden anterior antes de asignar el nuevo: la version
    // previa asignaba primero y por eso siempre retornaba sin guardar.
    for (const int id : m_gemPriority) {
        if (!newOrder.contains(id))
            newOrder.append(id);
    }

    if (newOrder == m_gemPriority)
        return;

    m_gemPriority = newOrder;
    // saveGemPriority actualiza el mapa de la cuenta activa y sincroniza
    // QSettings antes de devolver el control a QML.
    saveGemPriority();
}

// 20 tipos de gema del juego (mismo orden que colorNames en gemSpritePath).
static const char *kGemColorNames[] = {
    "Black Gem", "Blue Gem", "Brown Gem", "Cyan Gem", "Green Gem",
    "Orange Gem", "Pink Gem", "Purple Gem", "Red Gem", "White Gem",
    "Yellow Gem", "Forest Gem", "Gold Gem", "Gray Gem", "Indigo Gem",
    "Magenta Gem", "Maroon Gem", "Rainbow Gem", "Silver Gem", "Teal Gem"
};

QString gemColorKey(const QString &spritePath)
{
    const QString file = spritePath.mid(spritePath.lastIndexOf(QLatin1Char('/')) + 1);
    const int dash1 = file.indexOf(QLatin1Char('-'));
    const int dash2 = file.indexOf(QLatin1Char('-'), dash1 + 1);
    return dash2 > 0 ? file.left(dash2) : file;
}

// Las 20 gemas ordenadas por prioridad de farmeo, con nivel maximo de las
// cuentas si existe, o banda 01 por defecto.
QVariantList FarmController::priorityGems() const
{
    QHash<QString, int> maxLvl; // colorKey -> nivel maximo encontrado
    for (const auto &v : m_accounts) {
        const QVariantList cached = v.toMap().value(QStringLiteral("gems")).toList();
        for (const auto &gv : cached) {
            const QVariantMap gm = gv.toMap();
            const QString ck = gemColorKey(gm.value(QStringLiteral("sprite")).toString());
            const int lvl = gm.value(QStringLiteral("level")).toInt();
            auto it = maxLvl.constFind(ck);
            if (it == maxLvl.constEnd() || lvl > it.value())
                maxLvl.insert(ck, lvl);
        }
    }
    QVariantList out;
    for (int ci : m_gemPriority) {
        if (ci < 0 || ci >= 20) continue;
        const QString colorName = QString::fromLatin1(kGemColorNames[ci]);
        // extraer el color del nombre: "Blue Gem" -> "blue"
        const QString colorLower = colorName.left(colorName.indexOf(QLatin1Char(' '))).toLower();
        // SIEMPRE la banda 05 (nivel maximo): el usuario quiere el sprite
        // tope de cada color, no el nivel real de las cuentas (2026-08-09).
        const QString sprite = QStringLiteral("qrc:/Astro/assets/gems/%1-%2-05.png")
                                   .arg(ci + 1, 2, 10, QLatin1Char('0')).arg(colorLower);
        QVariantMap e;
        e.insert(QStringLiteral("id"), ci);
        e.insert(QStringLiteral("name"), colorName);
        e.insert(QStringLiteral("sprite"), sprite);
        e.insert(QStringLiteral("level"), 25);
        out.append(e);
    }
    return out;
}


void FarmController::spawn()
{
    if (m_spawning.load() || (farmRunning() && !m_refreshRespawning)) {
        m_stateText = QStringLiteral("A farm is already running. Press Stop first.");
        emit stateTextChanged();
        emit toastMessage(m_stateText);
        return;
    }
    // v41: un STOP previo durante el spawn dejo el flag abortado; el nuevo
    // RUN lo resetea (los singleShot del stagger lo checan y no crean nada).
    m_abortingSpawn.store(false);
    m_spawning.store(true);
    emit spawningChanged();
    // Multi-farm PARALELO: spawnea UN farm por cada cuenta seleccionada con la
    // casilla (o la cuenta actual si no hay seleccion). Flujo 100% async:
    //   1. se lanzan N hilos de login LIVE (LoginManager) EN PARALELO, cada uno
    //      lee la gema equipada real del server (data.current) + nombre + coins;
    //   2. cuando TODOS los logins terminan, la GUI spawnea los N farms A LA VEZ
    //      (no en cascada), cada uno en su propio thread.
    // El login en vivo evita el equippedGemId stale de accounts.json (que hacia
    // fallar el equip con "Gem X could not be equipped" o saltarse cuentas sin
    // cache).
    QStringList devices;
    if (!m_farmSelection.isEmpty()) {
        for (const auto &v : m_farmSelection)
            devices.append(v.toString());
    } else {
        devices.append(resolveDeviceId());
    }
    if (devices.isEmpty()) {
        m_stateText = QStringLiteral("No account to farm");
        emit stateTextChanged();
        emit toastMessage(m_stateText);
        return;
    }
    const int total = devices.size();
    // la UI refleja la actividad YA, antes de que terminen los logins
    m_stateText = QStringLiteral("Spawning %1 account(s) in CTF...").arg(total);
    emit stateTextChanged();
    emit farmRunningChanged();

    // estado compartido entre los hilos de login (QSharedPointer = se libera
    // solo cuando el ultimo lambda deja de usarlo)
    QSharedPointer<QVector<SpawnPrep>> preps = QSharedPointer<QVector<SpawnPrep>>::create(total);
    QSharedPointer<std::atomic<int>> done = QSharedPointer<std::atomic<int>>::create(0);
    QVector<QThread *> loginThreads;
    loginThreads.reserve(total);

    for (int k = 0; k < total; ++k) {
        const QString deviceId = devices.at(k);
        // leer equippedGemId LOCAL ANTES de lanzar el hilo (GUI thread)
        int localId = -1;
        for (int i = 0; i < m_accounts.size(); ++i) {
            const QVariantMap am = m_accounts.at(i).toMap();
            if (am.value(QStringLiteral("device")).toString() == deviceId) {
                localId = am.value(QStringLiteral("equippedGemId")).toInt();
                break;
            }
        }
        // REVERTIDO 2026-08-10 (test #43): la teoria de 3 TPMs compartidos
        // (grupos 4+4+2) NO bajo los errores TCP (handshake fails 4 -> 10,
        // connect fails 11 -> 13, farming similar). El server no limita por
        // cantidad de mids por IP. Volver a PEM unica por device (verificado).
        const QString pemPath = fakeTpmPathForDevice(deviceId);
        const QVector<int> devicePriority = gemPriorityForDevice(deviceId);
        QThread *thread = new QThread(this);
        // rastrea el thread de login: shutdown()/dtor lo esperan antes de salir
        m_spawnThreads.append(thread);
        // LoginManager LOCAL dentro del lambda del started: su QNetworkAccessManager
        // nace en el hilo del worker (afinidad correcta). DirectConnection: el
        // started se emite EN el hilo nuevo, asi el lambda corre ahi (un receiver
        // QThread con AutoConnection correria en el hilo creador de la GUI).
        connect(thread, &QThread::started, thread, [this, thread, deviceId, pemPath, k, localId, devicePriority, preps, done, total]() {
            // slot propio de este hilo (indice k): sin carrera con los demas
            SpawnPrep &prep = (*preps)[k];
            prep.deviceId = deviceId;
            prep.priority = devicePriority;
            prep.localId = localId;
            prep.tpmGroup = k % 3;
            // Sin clave fake TPM propia NO hay atestacion valida: esta cuenta
            // NO puede loguear (jamas caer a la clave embebida compartida).
            // Marcar el skip aqui, antes del login, en vez de intentar 3 veces
            // sin atestacion (error enmascarado como "login fallo").
            if (pemPath.isEmpty()) {
                prep.lastError = QStringLiteral("fake TPM key gen fallo");
                writeLogFile(QStringLiteral("[DBG] spawnLogin device=%1 sin clave fake TPM, skip").arg(logName(deviceId, prep.realName)));
                const int d2 = ++(*done);
                QMetaObject::invokeMethod(this, [this, d2, total]() {
                    appendLog(QStringLiteral("Pre-spawn login %1/%2...").arg(d2).arg(total));
                }, Qt::QueuedConnection);
                QMetaObject::invokeMethod(this, [this, thread, preps, done, d2, total, k]() {
                    if (d2 == total) {
                        // todos terminaron: spawnea los que pudieron.
                        // STAGGER anti-bot: el server corta el handshake cuando
                        // 10 AUTHs llegan a la vez desde la misma IP ("TCP
                        // disconnected during handshake" en todas las cuentas).
                        // Cada farm arranca con 1.5s de retraso incremental.
                        int spawnIdx = 0;
                        for (const SpawnPrep &p : *preps) {
                            if (!p.ok) {
                                writeLogFile(QStringLiteral("[DBG] spawn skip %1: %2")
                                                 .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                                if (m_debugEnabled)
                                    appendDebug(QStringLiteral("spawn skip %1 (login fallo: %2)")
                                                    .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                                appendLog(QStringLiteral("Spawn skip (%1): login fallo: %2")
                                              .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                                continue;
                            }
                            if (p.gems.isEmpty()) {
                                writeLogFile(QStringLiteral("[DBG] spawn skip %1: sin gema equipada en slot 5 (inventory vacio)")
                                                 .arg(logName(p.deviceId, p.realName)));
                                if (m_debugEnabled)
                                    appendDebug(QStringLiteral("spawn skip %1 (sin gema equipada en slot 5, inventory vacio)")
                                                    .arg(logName(p.deviceId, p.realName)));
                                appendLog(QStringLiteral("Spawn skip (%1): sin gema equipada en slot 5 (inventory vacio)")
                                              .arg(logName(p.deviceId, p.realName)));
                                continue;
                            }
                            // Prioridad de la gema con la que se spawnea:
                            //   0. COLOR con mas prioridad del usuario (m_gemPriority:
                            //      las casillas de color de la UI, 2026-08-10). El farm
                            //      equipe automaticamente la gema del color preferido.
                            //   1. gema equipada LOCAL (equippedGemId elegido por el
                            //      usuario con equipGem) si existe en el inventario LIVE.
                            //   2. gema equipada LIVE del server (data.current).
                            //   3. primera gema del inventario.
                            int gemId = -1;
                            QString src;
                            // 0. prioridad de color: recorrer m_gemPriority en orden
                            // (el 1ro es el color MAS preferido) y elegir la primera
                            // gema del inventario de ese color con itemLevel < 25.
                            for (int ci : p.priority) {
                                if (ci < 0 || ci >= 20) continue;
                                for (const auto &g : p.gems) {
                                    if (g.itemLevel >= 25) continue;
                                    if (gemColorIndexByName(g.name) == ci) {
                                        gemId = g.id;
                                        src = QStringLiteral("priority(%1)").arg(ci);
                                        break;
                                    }
                                }
                                if (gemId > 0) break;
                            }
                            if (gemId < 0) {
                            if (p.localId > 0) {
                                for (const auto &g : p.gems)
                                    if (g.id == p.localId && g.itemLevel < 25) { gemId = p.localId; src = QStringLiteral("local"); break; }
                            }
                            if (gemId < 0) {
                                for (const auto &g : p.gems)
                                    if (g.id == p.equippedId && g.itemLevel < 25) { gemId = p.equippedId; src = QStringLiteral("server"); break; }
                            }
                            if (gemId < 0) {
                                for (const auto &g : p.gems)
                                    if (g.itemLevel < 25) { gemId = g.id; src = QStringLiteral("first"); break; }
                            }
                            // v42 (PROHIBIDO farmear gemas lvl 25): si TODAS las
                            // gemas del inventario son lvl 25, la cuenta NO
                            // spawnea (el fallback "first(25+)" la farmeaba).
                            if (gemId < 0) {
                                writeLogFile(QStringLiteral("[DBG] spawn skip %1: todas las gemas son lvl 25 (PROHIBIDO farmearlas)")
                                                 .arg(logName(p.deviceId, p.realName)));
                                if (m_debugEnabled)
                                    appendDebug(QStringLiteral("spawn skip %1 (solo gemas lvl 25)").arg(logName(p.deviceId, p.realName)));
                                appendLog(QStringLiteral("Spawn skip (%1): solo gemas lvl 25 (PROHIBIDO farmearlas)")
                                              .arg(logName(p.deviceId, p.realName)));
                                continue;
                            }
                            } // fin fallback local/server/first (solo si la prioridad no encontro)
                            const QString name = p.realName.isEmpty() ? p.deviceId.left(16) : p.realName;
                            writeLogFile(QStringLiteral("[DBG] spawn pick gem=%1 (%2) for %3")
                                             .arg(gemId).arg(src).arg(name));
                            if (m_debugEnabled)
                                appendDebug(QStringLiteral("spawn pick gem=%1 (%2) for %3").arg(gemId).arg(src).arg(name));
                            // La sesion del pre-spawn se pasa al farm: sin re-login
                            // en el arranque (9 doLogin simultaneos de los farms =
                            // race de Qt 6.10.3, AV 0x1CE857/0x1C8A4E con rdi=9).
                            // STAGGER anti-bot: el server corta AUTHs simultaneos
                            // de la misma IP (acepta ~1 conexion cada 2-3s).
                            // 2026-08-11 (9 cuentas en WAIT: el stagger de 1.5s
                            // hacia conectar todas en ~13s -> el server cortaba
                            // el handshake de las que se solapaban). Subido a
                            // 5s: imita a un usuario abriendo las ventanas del
                            // juego una por una (~40s para las 9).
                            {
                                const int delayMs = spawnIdx * 5000;
                                const QString dev = p.deviceId;
                                const int gId = gemId;
                                const QString nm = name;
                                const QString sSk = p.sk;
                                const QString sMg = p.magic;
                                const int grp = p.tpmGroup; // TEORIA 3 TPMs: grupo del prep
                                ++spawnIdx;
                                QTimer::singleShot(delayMs, this, [this, dev, gId, nm, sSk, sMg, grp]() {
                                    // v41 (STOP durante el spawn): si el usuario
                                    // aborto mientras esperaba su turno del stagger,
                                    // NO crear el farm (los workers nuevos se habrian
                                    // quedado sin stop -> "el boton de stop no para").
                                    if (m_abortingSpawn.load()) {
                                        writeLogFile(QStringLiteral("[DBG] spawn cancelado por STOP: %1").arg(nm));
                                        return;
                                    }
                                    spawnOneFarm(dev, gId, nm, sSk, sMg, grp); // loguea "Spawning ..."
                                });
                            }
                            // persiste la info fresca en la entrada de la cuenta
                            for (int i = 0; i < m_accounts.size(); ++i) {
                                QVariantMap am = m_accounts.at(i).toMap();
                                if (am.value(QStringLiteral("device")).toString() != p.deviceId)
                                    continue;
                                if (!p.realName.isEmpty())
                                    am.insert(QStringLiteral("name"), p.realName);
                                const GemInfo *egPtr = nullptr;
                                for (const auto &g : p.gems)
                                    if (g.id == gemId) { egPtr = &g; break; }
                                const GemInfo &eg = egPtr ? *egPtr : p.gems.first();
                                am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                                am.insert(QStringLiteral("gemSummary"),
                                          QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                                am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                                am.insert(QStringLiteral("xpBaselineGemId"), gemId);
                                am.insert(QStringLiteral("xpBaselineCexp"), qlonglong(eg.cexp));
                                am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                                am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                                am.insert(QStringLiteral("equippedGemId"), gemId);
                                if (p.coins > 0)
                                    am.insert(QStringLiteral("coins"), p.coins);
                                // 2026-08-10: badge PRIORIDAD — la gema se compro
                                // del shop por prioridad (inventario vacio)
                                am.insert(QStringLiteral("boughtByPriority"), p.boughtByPriority);
                                am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
                                am.insert(QStringLiteral("gems"), gemsCacheFrom(p.gems));
                                m_accounts[i] = am;
                                // 2026-08-10 (fuente unica de verdad): si la cuenta persistida
                                // es la ACTIVA, refrescar panel + inventario al instante
                                // (el bot farmea X -> X es la equipada).
                                if (am.value(QStringLiteral("device")).toString() == m_deviceId) {
                                    applyAccountCache(am);
                                    emit gemsChanged();
                                    emit selectedGemChanged();
                                    emit gemXpTextChanged();
                                }
                                break;
                            }
                        }
                        saveAccounts();
                        emit accountsChanged();
                        emit farmRunningChanged();
                        rebuildActiveSessions();
                        // BUG-10: si NINGUNA cuenta pudo spawnear, la UI quedaba en
                        // "Spawning N account(s)..." sin feedback de fallo total.
                        int spawnedCount = 0;
                        for (const SpawnPrep &p2 : *preps)
                            if (p2.ok && !p2.gems.isEmpty())
                                spawnedCount++;
                        if (spawnedCount == 0 && total > 0) {
                            m_stateText = QStringLiteral("No accounts could be spawned (login/inventory failed for all %1)").arg(total);
                            emit stateTextChanged();
                            appendLog(m_stateText);
                            emit toastMessage(m_stateText);
                        }
                    }
                    thread->quit();
                    m_spawnThreads.removeOne(thread);
                }, Qt::QueuedConnection);
                return;
            }
            LoginManager local;
            if (!pemPath.isEmpty()) {
                QFile pf(pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
            }
            // (prep se definio al inicio del lambda, antes del branch pemPath)
            // login LIVE con reintentos: un fallo transitorio (red, KNOCK/LIM del
            // server) NO debe saltarse la cuenta para toda la corrida. Hasta 3
            // intentos con 1500ms entre ellos; el error REAL de cada intento se
            // persiste SIEMPRE al archivo (astro_farm.log) para diagnosticar.
            LoginResult r;
            for (int intento = 1; intento <= 3; ++intento) {
                r = local.login(deviceId);
                if (r.ok)
                    break;
                prep.lastError = r.error;
                writeLogFile(QStringLiteral("[DBG] spawnLogin device=%1 intento=%2 fallo: %3")
                                 .arg(logName(deviceId, prep.realName)).arg(intento).arg(r.error));
                if (intento < 3)
                    QThread::msleep(1500);
            }
            if (r.ok) {
                prep.gems = local.fetchInventory(5);
                // inventory vacio es muchas veces un hiccup HTTP transitorio:
                // se reintenta UNA vez antes de dar por perdida la cuenta.
                if (prep.gems.isEmpty()) {
                    writeLogFile(QStringLiteral("[DBG] spawnLogin device=%1 inventory slot=5 vacio, reintento en 1000ms")
                                     .arg(logName(deviceId, prep.realName)));
                    QThread::msleep(1000);
                    prep.gems = local.fetchInventory(5);
                }
                // v97af (pedido del usuario 2026-08-15): auto-buy de gemas por
                // prioridad ELIMINADO TOTALMENTE — el bot ya no compra gemas
                // del shop. Si la cuenta no tiene gema equipada, queda sin
                // gema (el farm no la spawneara).
                if (prep.gems.isEmpty()) {
                    writeLogFile(QStringLiteral("[DBG] spawnLogin %1 sin gema (auto-buy DESACTIVADO)")
                                     .arg(logName(deviceId, prep.realName)));
                }
                prep.equippedId = local.lastCurrentItem(); // data.current real
                prep.realName = local.fetchAccountName();  // loginifneeded
                prep.coins = local.lastCoins();
                // sesion del pre-spawn para el farm (evita el doLogin del
                // arranque: 9 logins simultaneos = race de Qt 6.10.3)
                prep.sk = local.sessionKey();
                prep.magic = local.magic();
                prep.ok = true;
            }
            // debug SIEMPRE persistido (el switch solo controla el panel)
            writeLogFile(QStringLiteral("[DBG] spawnLogin device=%1 ok=%2 gems=%3 current=%4")
                             .arg(logName(deviceId, prep.realName)).arg(prep.ok).arg(prep.gems.size()).arg(prep.equippedId));
            if (m_debugEnabled)
                appendDebug(QStringLiteral("spawnLogin device=%1 ok=%2 gems=%3 current=%4")
                                .arg(logName(deviceId, prep.realName)).arg(prep.ok).arg(prep.gems.size()).arg(prep.equippedId));
            const int d = ++(*done);
            // feedback visual: el pre-spawn tarda ~3s por cuenta (logins
            // serializados por el mutex de login); sin esto el RUN parece
            // congelado durante el arranque
            QMetaObject::invokeMethod(this, [this, d, total]() {
                appendLog(QStringLiteral("Pre-spawn login %1/%2...").arg(d).arg(total));
            }, Qt::QueuedConnection);
            QMetaObject::invokeMethod(this, [this, thread, preps, done, d, total, k]() {
                if (d == total) {
                    // TODOS los logins terminaron: spawnea los N farms
                    // STAGGER anti-bot: 1.5s entre farms (el server corta
                    // AUTHs simultaneos de la misma IP)
                    int spawnIdx = 0;
                    for (const SpawnPrep &p : *preps) {
                        if (!p.ok) {
                            writeLogFile(QStringLiteral("[DBG] spawn skip %1: %2")
                                             .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                            if (m_debugEnabled)
                                appendDebug(QStringLiteral("spawn skip %1 (login fallo: %2)")
                                                .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                            appendLog(QStringLiteral("Spawn skip (%1): login fallo: %2")
                                          .arg(logName(p.deviceId, p.realName)).arg(p.lastError));
                            continue;
                        }
                        if (p.gems.isEmpty()) {
                            // la cuenta simplemente no tiene gema equipada en
                            // slot 5 en este momento: comportamiento correcto
                            // (se reintento el inventory 1x), se salta con aviso
                            writeLogFile(QStringLiteral("[DBG] spawn skip %1: sin gema equipada en slot 5 (inventory vacio)")
                                             .arg(logName(p.deviceId, p.realName)));
                            if (m_debugEnabled)
                                appendDebug(QStringLiteral("spawn skip %1 (sin gema equipada en slot 5, inventory vacio)")
                                                .arg(logName(p.deviceId, p.realName)));
                            appendLog(QStringLiteral("Spawn skip (%1): sin gema equipada en slot 5 (inventory vacio)")
                                          .arg(logName(p.deviceId, p.realName)));
                            continue;
                        }
                        // Prioridad de la gema con la que se spawnea:
                        //   0. COLOR con mas prioridad del usuario (m_gemPriority:
                        //      las casillas de color de la UI, 2026-08-10). El farm
                        //      equipe automaticamente la gema del color preferido.
                        //   1. gema equipada LOCAL (equippedGemId elegido por el
                        //      usuario con equipGem) si existe en el inventario LIVE.
                        //   2. gema equipada LIVE del server (data.current).
                        //   3. primera gema del inventario.
                        int gemId = -1;
                        QString src;
                        // 0. prioridad de color: recorrer m_gemPriority en orden
                        // (el 1ro es el color MAS preferido) y elegir la primera
                        // gema del inventario de ese color con itemLevel < 25.
                        for (int ci : p.priority) {
                            if (ci < 0 || ci >= 20) continue;
                            for (const auto &g : p.gems) {
                                if (g.itemLevel >= 25) continue;
                                if (gemColorIndexByName(g.name) == ci) {
                                    gemId = g.id;
                                    src = QStringLiteral("priority(%1)").arg(ci);
                                    break;
                                }
                            }
                            if (gemId > 0) break;
                        }
                        if (gemId < 0) {
                        if (p.localId > 0) {
                            for (const auto &g : p.gems)
                                if (g.id == p.localId && g.itemLevel < 25) { gemId = p.localId; src = QStringLiteral("local"); break; }
                        }
                        if (gemId < 0) {
                            for (const auto &g : p.gems)
                                if (g.id == p.equippedId && g.itemLevel < 25) { gemId = p.equippedId; src = QStringLiteral("server"); break; }
                        }
                        if (gemId < 0) {
                            for (const auto &g : p.gems)
                                if (g.itemLevel < 25) { gemId = g.id; src = QStringLiteral("first"); break; }
                        }
                        // v42 (PROHIBIDO farmear gemas lvl 25): si TODAS las
                        // gemas del inventario son lvl 25, la cuenta NO spawnea
                        // (el fallback "first(25+)" la farmeaba).
                        if (gemId < 0) {
                            writeLogFile(QStringLiteral("[DBG] spawn skip %1: todas las gemas son lvl 25 (PROHIBIDO farmearlas)")
                                             .arg(logName(p.deviceId, p.realName)));
                            if (m_debugEnabled)
                                appendDebug(QStringLiteral("spawn skip %1 (solo gemas lvl 25)").arg(logName(p.deviceId, p.realName)));
                            appendLog(QStringLiteral("Spawn skip (%1): solo gemas lvl 25 (PROHIBIDO farmearlas)")
                                          .arg(logName(p.deviceId, p.realName)));
                            continue;
                        }
                        } // fin fallback local/server/first (solo si la prioridad no encontro)
                        const QString name = p.realName.isEmpty() ? p.deviceId.left(16) : p.realName;
                        writeLogFile(QStringLiteral("[DBG] spawn pick gem=%1 (%2) for %3")
                                         .arg(gemId).arg(src).arg(name));
                        if (m_debugEnabled)
                            appendDebug(QStringLiteral("spawn pick gem=%1 (%2) for %3").arg(gemId).arg(src).arg(name));
                        // La sesion del pre-spawn se pasa al farm: sin re-login
                        // en el arranque (9 doLogin simultaneos de los farms =
                        // race de Qt 6.10.3, AV 0x1CE857/0x1C8A4E con rdi=9).
                        // STAGGER anti-bot: 1.5s entre farms (el server corta
                        // AUTHs simultaneos de la misma IP).
                        {
                            const int delayMs = spawnIdx * 1500;
                            const QString dev = p.deviceId;
                            const int gId = gemId;
                            const QString nm = name;
                            const QString sSk = p.sk;
                            const QString sMg = p.magic;
                            const int grp = p.tpmGroup; // TEORIA 3 TPMs: grupo del prep
                            ++spawnIdx;
                            QTimer::singleShot(delayMs, this, [this, dev, gId, nm, sSk, sMg, grp]() {
                                spawnOneFarm(dev, gId, nm, sSk, sMg, grp); // loguea "Spawning ..."
                            });
                        }
                        // persiste la info fresca en la entrada de la cuenta
                        for (int i = 0; i < m_accounts.size(); ++i) {
                            QVariantMap am = m_accounts.at(i).toMap();
                            if (am.value(QStringLiteral("device")).toString() != p.deviceId)
                                continue;
                            if (!p.realName.isEmpty())
                                am.insert(QStringLiteral("name"), p.realName);
                            const GemInfo *egPtr = nullptr;
                            for (const auto &g : p.gems)
                                if (g.id == gemId) { egPtr = &g; break; }
                            const GemInfo &eg = egPtr ? *egPtr : p.gems.first();
                            am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                            am.insert(QStringLiteral("gemSummary"),
                                          QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                            am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                            am.insert(QStringLiteral("xpBaselineGemId"), gemId);
                            am.insert(QStringLiteral("xpBaselineCexp"), qlonglong(eg.cexp));
                            am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                            am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                            am.insert(QStringLiteral("equippedGemId"), gemId);
                            if (p.coins > 0)
                                am.insert(QStringLiteral("coins"), p.coins);
                            // 2026-08-10: badge PRIORIDAD — la gema se compro
                            // del shop por prioridad (inventario vacio)
                            am.insert(QStringLiteral("boughtByPriority"), p.boughtByPriority);
                            am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
                            am.insert(QStringLiteral("gems"), gemsCacheFrom(p.gems));
                            m_accounts[i] = am;
                            // 2026-08-10 (fuente unica de verdad): si la cuenta persistida
                            // es la ACTIVA, refrescar panel + inventario al instante
                            // (el bot farmea X -> X es la equipada).
                            if (am.value(QStringLiteral("device")).toString() == m_deviceId) {
                                applyAccountCache(am);
                                emit gemsChanged();
                                emit selectedGemChanged();
                                emit gemXpTextChanged();
                            }
                            break;
                        }
                    }
                    saveAccounts();
                    emit accountsChanged();
                    emit farmRunningChanged();
                    rebuildActiveSessions();
                    // BUG-10: si NINGUNA cuenta pudo spawnear, la UI quedaba en
                    // "Spawning N account(s)..." sin feedback de fallo total.
                    int spawnedCount = 0;
                    for (const SpawnPrep &p2 : *preps)
                        if (p2.ok && !p2.gems.isEmpty())
                            spawnedCount++;
                    if (spawnedCount == 0 && total > 0) {
                        m_stateText = QStringLiteral("No accounts could be spawned (login/inventory failed for all %1)").arg(total);
                        emit stateTextChanged();
                        appendLog(m_stateText);
                        emit toastMessage(m_stateText);
                    }
                }
                thread->quit();
                m_spawnThreads.removeOne(thread);
            }, Qt::QueuedConnection);
        }, Qt::DirectConnection);
        connect(thread, &QThread::finished, thread, &QObject::deleteLater);
        thread->start();
    }
    // El flag m_spawning se limpia aqui: todo el trabajo de spawn ya esta en
    // marcha (hilos de login + hilos de farm). Sin esto, un 2do clic en RUN
    // durante los logins del pre-spawn (~16-25s) lanzaba otro lote de logins
    // y duplicaba todos los farms (13 sesiones con 7 cuentas, 2 lotes de
    // "Spawning" en el log - ver BUG 2026-08-08).
    m_spawning.store(false);
    emit spawningChanged();
    // v44 (auto-refresh solo con farms): el switch del usuario activa el
    // timer SOLO mientras hay farms corriendo.
    if (m_autoRefreshWanted && m_autoRefreshTimer && !m_autoRefreshTimer->isActive())
        m_autoRefreshTimer->start();
}

// ===================== SPAWN ONE FARM =====================
// Crea un QThread + FarmWorker para UNA cuenta, conecta signals y arranca.
// La sesion del pre-spawn (sk/magic) se pasa al worker para evitar el
// doLogin del arranque (9 logins simultaneos = race de Qt 6.10.3).
void FarmController::spawnOneFarm(const QString &deviceId, int gemId, const QString &accountName,
                                   const QString &sessionSk, const QString &sessionMagic,
                                   int tpmGroup)
{
    // v97ek: dedup leak 28 farms — si ya hay un farm vivo para este device, no duplicar
    for (int i = m_farms.size() - 1; i >= 0; --i) {
        if (m_farms.at(i).deviceId == deviceId) {
            if (m_farms.at(i).thread && m_farms.at(i).thread->isRunning()) {
                appendLog(QStringLiteral("Spawn skip %1: ya existe farm vivo (%2 handles)").arg(accountName).arg(m_farms.size()));
                return;
            }
            m_farms.removeAt(i);
        }
    }
    // REVERTIDO 2026-08-10 (test #43): PEM unica por device (verificado).
    const QString pemPath = fakeTpmPathForDevice(deviceId);
    if (pemPath.isEmpty()) {
        appendLog(QStringLiteral("Spawn failed for %1: no fake TPM key").arg(accountName));
        return;
    }
    // Busca el nombre de la gema para el log/handle
    QString gemName;
    for (int i = 0; i < m_accounts.size(); ++i) {
        const QVariantMap am = m_accounts.at(i).toMap();
        if (am.value(QStringLiteral("device")).toString() != deviceId) continue;
        const QVariantList cached = am.value(QStringLiteral("gems")).toList();
        for (const auto &gv : cached) {
            if (gv.toMap().value(QStringLiteral("id")).toInt() == gemId) {
                gemName = gv.toMap().value(QStringLiteral("name")).toString();
                break;
            }
        }
        break;
    }

    FarmHandle fh;
    fh.deviceId = deviceId;
    fh.pemPath = pemPath;
    fh.accountName = accountName;
    fh.gemName = gemName;
    fh.gemId = gemId;

    QThread *thread = new QThread(this);
    FarmWorker *worker = new FarmWorker();
    worker->setObjectName(QStringLiteral("farm_%1").arg(accountName.left(16)));
    worker->setAutoRespawn(m_autoRespawn);
    worker->setAutoRepair(m_autoRepair);
    worker->setAutoBuyX2(m_autoBuyX2);
    worker->configure(deviceId, pemPath, gemId);
    // prioridad de gemas (ids de color) para el cambio automatico de gema rota
    // v97e2: el orden POR CUENTA — la lista del device del worker.
    worker->setGemPriorityList(gemPriorityForDevice(deviceId));
    worker->setAbortFlag(&m_abortingRefreshAll);
    // Si la sesion del pre-spawn es valida, pasarsela al worker para que
    // haga un "warm start" sin re-login (9 doLogin simultaneos = race).
    if (!sessionSk.isEmpty())
        worker->setSession(sessionSk, sessionMagic, 0, -1, -1);
    worker->moveToThread(thread);

    // Conectar signals: debug -> debugLog, estado -> stateChanged, XP -> xpUpdate, etc.
    connect(worker, &FarmWorker::debugLog, this, &FarmController::onFarmDebug);
    connect(worker, &FarmWorker::stateChanged, this, [this, worker](const QString &text) {
        onFarmState(worker, text);
    });
    connect(worker, &FarmWorker::xpUpdate, this, [this, worker](double xpGained, double lastXp, int deaths, bool spawned) {
        onFarmXp(worker, xpGained, lastXp, deaths, spawned);
    });
    connect(worker, &FarmWorker::gemXpRead, this, [this, worker](qlonglong cexp, qlonglong exp) {
        onGemXpRead(worker, cexp, exp);
    });
    connect(worker, &FarmWorker::finishedOk, this, [this, worker](bool ok, const QString &err) {
        onFarmFinished(worker, ok, err);
    });
    connect(worker, &FarmWorker::accountState, this, &FarmController::onAccountState);
    connect(worker, &FarmWorker::regionChanged, this, &FarmController::onRegionChanged);
    connect(worker, &FarmWorker::xpRefreshDone, this, [this, worker](bool ok, qlonglong cexp, qlonglong exp, qlonglong delta, int lvl, const QString &err) {
        onXpRefreshDone(worker, ok, cexp, exp, delta, lvl, err);
    });

    fh.thread = thread;
    fh.worker = worker;
    fh.startedAt = QDateTime::currentMSecsSinceEpoch();
    m_farms.append(fh);

    connect(thread, &QThread::started, worker, &FarmWorker::run);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    // El worker se destruye CUANDO su thread termina (evita workers huerfanos
    // que seguian emitiendo señales tras m_farms.clear() -> punteros fantasma
    // -> crash latente al dar STOP). El handle se remueve de m_farms en el
    // mismo momento, asi la UI nunca muestra sesiones muertas.
    connect(thread, &QThread::finished, worker, &QObject::deleteLater);
    // v41 (bug 2026-08-12: handles huerfanos tras STOP/refresh): el worker se
    // destruye en SU thread cuando run() sale, y el QPointer del handle se
    // anula a nullptr. El lambda comparaba el QPointer (ya null) contra el
    // puntero crudo capturado -> nunca coincidian -> el handle quedaba en
    // m_farms para siempre ("9 farms vivos", sin respawn, doble login en el
    // refresh). Ahora se busca por deviceId (unico por handle, estable).
    // v43 (bug: el respawn crea un handle NUEVO con el mismo deviceId mientras
    // el viejo aun termina): buscar SOLO por deviceId removeria el handle del
    // farm NUEVO cuando el viejo emite finished. Comparar ademas el thread:
    // solo se remueve el handle cuyo thread es EL que termino.
    connect(thread, &QThread::finished, this, [this, deviceId, thread]() {
        for (int i = m_farms.size() - 1; i >= 0; --i) {
            if (m_farms.at(i).deviceId == deviceId && m_farms.at(i).thread == thread) {
                m_farms.removeAt(i);
                break;
            }
        }
        rebuildActiveSessions();
        emit farmRunningChanged();
        scheduleUiFlush();
    });

    // v42 (STOP no paraba todo): el singleShot del stagger y el click de STOP
    // pueden expirar en el MISMO ms del event loop — si el timer corre antes,
    // el check del singleShot ve el flag false y spawnea igual. Chequear el
    // flag AQUI, ya dentro de spawnOneFarm y antes de arrancar el thread: si
    // el usuario pidio STOP en cualquier instante anterior, no se crea nada.
    if (m_abortingSpawn.load()) {
        writeLogFile(QStringLiteral("[DBG] spawnOneFarm cancelado por STOP (flag ya puesto): %1").arg(accountName));
        for (int i = m_farms.size() - 1; i >= 0; --i) {
            if (m_farms.at(i).deviceId == deviceId) {
                m_farms.removeAt(i);
                break;
            }
        }
        delete worker;
        delete thread;
        rebuildActiveSessions();
        emit farmRunningChanged();
        return;
    }

    appendLog(QStringLiteral("Spawning %1 with gem %2 (%3)")
                  .arg(accountName, QString::number(gemId), gemName));
    thread->start();
    // 2026-08-10 (bug reportado por el usuario: el boton RUN nunca se marcaba
    // "RUNNING" y STOP no servia): spawn() emite farmRunningChanged() ANTES de
    // crear los threads (m_farms vacio -> false) y aqui NUNCA se re-emitia.
    // El binding QML quedaba con el valor viejo -> boton "RUN" + STOP
    // deshabilitado (enabled: farm.farmRunning = false) aunque los farms
    // estuvieran corriendo. Este emit post-start hace que farmRunning()=true
    // llegue a la UI (el thread ya esta vivo: isRunning() == true).
    emit farmRunningChanged();
}

// ===================== FARM SIGNAL HANDLERS =====================

void FarmController::onFarmDebug(const QString &text)
{
    if (!m_debugEnabled)
        return;
    appendDebug(text);
    // 2026-08-10: en modo headless/debug los debugLog del worker (HTTP >>,
    // PONG, opcodes) solo iban a la UI y el archivo astro_farm.log no los
    // mostraba — imposible diagnosticar el tiempo de cada HTTP. Escribirlos
    // tambien al archivo para el analisis en vivo.
    writeLogFile(text);
}

void FarmController::onFarmState(FarmWorker *w, const QString &text)
{
    // Actualiza el stateText con el nombre de la cuenta + estado
    FarmHandle *fh = handleFor(w);
    const QString prefix = fh ? logName(fh->deviceId, fh->accountName) : QStringLiteral("?");
    m_stateText = QStringLiteral("[%1] %2").arg(prefix, text);
    emit stateTextChanged();

    // Detecta eventos especiales del farm: "[SPAWNED]", "[DIED]", "[GAME OVER]"
    const QString lower = text.toLower();
    if (fh) {
        if (lower.contains(QStringLiteral("spawned"))) {
            fh->spawned = true;
            rebuildAggregate();
            rebuildActiveSessions();
        } else if (lower.contains(QStringLiteral("died")) || lower.contains(QStringLiteral("game over"))) {
            fh->deaths++;
            rebuildAggregate();
            rebuildActiveSessions();
        }
    }
    // Log legible (sin prefijo [DBG])
    appendLog(QStringLiteral("[%1] %2").arg(prefix, text));
}

void FarmController::onFarmXp(FarmWorker *w, double xpGained, double lastXp, int deaths, bool spawned)
{
    FarmHandle *fh = handleFor(w);
    if (!fh)
        return;
    fh->lastXp = lastXp;
    fh->deaths = deaths;
    fh->spawned = spawned;
    // Acumula el XP ganado en esta sesion (no el total absoluto)
    // m_totalXpGained se recalcula con rebuildAggregate
    rebuildAggregate();
    scheduleUiFlush();
}

void FarmController::onGemXpRead(FarmWorker *w, qlonglong cexp, qlonglong exp)
{
    FarmHandle *fh = handleFor(w);
    if (!fh)
        return;
    // Baseline: el primer valor leido es la referencia
    if (fh->lastGemCexp < 0)
        fh->lastGemCexp = cexp;
    const qlonglong delta = cexp - fh->lastGemCexp;
    fh->lastGemCexp = cexp;

    // v83 (FIX del contador dañado): el cexp de la gema (inventory slot=5) es
    // la UNICA fuente del XP de la gema. El op24 (fh->lastXp) es XP del MAPA
    // y NO debe mezclarse con el de las gemas — el qMax anterior pisaba el
    // cexp real con el del mapa y corrompia el contador persistido.
    const qlonglong shownXp = cexp;
    const qlonglong shownDelta = qMax(qlonglong(0), delta);

    // Actualiza el texto de XP de la gema (solo si es la cuenta activa)
    if (fh->deviceId == resolveDeviceId()) {
        m_gemXpText = QStringLiteral("Gem XP %1/%2 | Gained (delta): %3 | Level: %4")
                          .arg(shownXp).arg(exp).arg(shownDelta).arg((exp > 0) ? QString::number(int((cexp * 25) / qMax(exp, qlonglong(1)))) : QStringLiteral("--"));
        emit gemXpTextChanged();
    }
    scheduleUiFlush();
}

void FarmController::onFarmFinished(FarmWorker *w, bool ok, const QString &error)
{
    FarmHandle *fh = handleFor(w);
    const QString name = fh ? logName(fh->deviceId, fh->accountName) : QStringLiteral("?");
    if (ok) {
        appendLog(QStringLiteral("[%1] Farm finished OK").arg(name));
    } else {
        appendLog(QStringLiteral("[%1] Farm finished with error: %2").arg(name, error));
    }
    // El farm termino; si auto-respawn esta ON, el worker internamente
    // ya deberia estar re-spawneando (su loop run() lo maneja). Si no
    // esta activo, el worker simplemente sale.
    // v97e (pedido del usuario: "mate la cuenta y nunca se autorespawneo"):
    // el worker que muere por fail() (15 sesiones fallidas, TCP fail, etc.)
    // SALE del run() y NADIE lo re-lanza -> la cuenta queda parada hasta el
    // refresh de 600s (Expend +481 vs Action +2225 en el test 12min). Si el
    // autoRespawn esta ON, re-lanzar el spawn de ESA cuenta tras 8s.
    // Excepciones: "stopped" (stop manual o del refresh — el refresh ya
    // respawnea) y "Not spawning" (gema prohibida/agotada — el refresh
    // re-equipa por prioridad; reintentar aqui quemaria logins).
    if (!ok && fh && m_autoRespawn
        && !error.contains(QStringLiteral("stopped"))
        && !error.contains(QStringLiteral("Not spawning"))) {
        const QString deviceId = fh->deviceId;
        appendLog(QStringLiteral("[%1] autoRespawn: re-lanzando en 8s (error del farm)")
                      .arg(name));
        QTimer::singleShot(8000, this, [this, deviceId]() {
            if (m_autoRespawn) {
                respawnDevices({deviceId});
            }
        });
    }
    // Actualiza la UI
    emit farmRunningChanged();
    rebuildActiveSessions();
    scheduleUiFlush();
}

void FarmController::onAccountState(const QString &mode, const QString &region)
{

    m_accountMode = mode;
    m_farmRegion = region;
    m_serverText = QStringLiteral("State: %1 | Server: %2").arg(mode, region);
    emit serverTextChanged();
    rebuildActiveSessions();
}

void FarmController::onRegionChanged(const QString &region)
{
    m_farmRegion = region;
    m_serverText = QStringLiteral("State: %1 | Server: %2")
                       .arg(m_accountMode.isEmpty() ? QStringLiteral("--") : m_accountMode, region);
    emit serverTextChanged();
}

void FarmController::onXpRefreshDone(FarmWorker *w, bool ok, qlonglong cexp, qlonglong exp,
                                     qlonglong delta, int lvl, const QString &error)
{
    FarmHandle *fh = handleFor(w);
    const QString name = fh ? logName(fh->deviceId, fh->accountName) : QStringLiteral("?");

    if (ok) {
        // Actualiza la gema equipada en la DB de la cuenta
        for (int i = 0; i < m_accounts.size(); ++i) {
            QVariantMap am = m_accounts.at(i).toMap();
            if (am.value(QStringLiteral("device")).toString() != (fh ? fh->deviceId : QString()))
                continue;
            am.insert(QStringLiteral("cexp"), cexp);
            am.insert(QStringLiteral("exp"), exp);
            am.insert(QStringLiteral("gemLevel"), lvl);
            // v97ec (bug: tras el auto-refresh el +XP no aparecia en Chasing/Cross):
            // el delegate lee xpGained, que venia de fh.lastXp (op24 del worker) —
            // al re-spawnear el farm el FarmHandle es NUEVO con lastXp=0. Guardar
            // el delta REAL de la gema del refresh en la DB de la cuenta.
            am.insert(QStringLiteral("xpGained"), qMax(qlonglong(0), delta));
            am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
            m_accounts[i] = am;
            break;
        }
        // Actualiza el texto de XP de la gema si es la cuenta activa
        if (fh && fh->deviceId == resolveDeviceId()) {
            m_gemXpText = QStringLiteral("Gem XP %1/%2 | Gained (delta): %3 | Level: %4")
                              .arg(cexp).arg(exp).arg(qMax(qlonglong(0), delta)).arg(lvl);
            emit gemXpTextChanged();
        }
        appendLog(QStringLiteral("[%1] XP refresh: cexp=%2 exp=%3 delta=%4 lvl=%5")
                      .arg(name).arg(cexp).arg(exp).arg(delta).arg(lvl));
    } else {
        appendLog(QStringLiteral("[%1] XP refresh failed: %2").arg(name, error));
    }
    // Actualiza las cuentas persistidas
    emit accountsChanged();
    scheduleUiFlush();
}

// ===================== SHUTDOWN / QUIT =====================

// ===================== SHUTDOWN / QUIT =====================
void FarmController::shutdown()
{
    m_abortingRefreshAll.store(true);
    m_abortingSpawn.store(true);
    m_autoRefreshTimer->stop();
    // 4. Parar todos los farms
    for (int i = 0; i < m_farms.size(); ++i) {
        if (m_farms.at(i).worker)
            m_farms.at(i).worker->stop();
    }
    // Esperar a que los threads terminen (deadline 8s por farm)
    for (int i = 0; i < m_farms.size(); ++i) {
        if (m_farms.at(i).thread && m_farms.at(i).thread->isRunning()) {
            m_farms.at(i).thread->quit();
            if (!m_farms.at(i).thread->wait(8000)) {
                // Timeout: el worker esta bloqueado; no matar el thread
                // desde aqui (el dtor lo hace con TerminateProcess)
            }
        }
    }
    // 6. Esperar threads de login del spawn
    for (QThread *t : m_spawnThreads) {
        if (t && t->isRunning()) {
            t->quit();
            t->wait(8000);
        }
    }
    m_spawnThreads.clear();
    // 7. Esperar el thread orchestrador del pre-spawn
    if (m_spawnOrch && m_spawnOrch->isRunning()) {
        m_spawnOrch->quit();
        m_spawnOrch->wait(8000);
    }
    m_spawnOrch = nullptr;
    // 8. Esperar threads de refresh/fetch
    if (m_refreshThread && m_refreshThread->isRunning()) {
        m_refreshThread->quit();
        m_refreshThread->wait(8000);
    }
    if (m_fetchThread && m_fetchThread->isRunning()) {
        m_fetchThread->quit();
        m_fetchThread->wait(8000);
    }
    if (m_refreshAllThread && m_refreshAllThread->isRunning()) {
        m_refreshAllThread->wait(10000);
    }
    if (m_qwsThread && m_qwsThread->isRunning()) {
        m_qwsThread->quit();
        m_qwsThread->wait(8000);
    }
    // 9. Persistir cuentas antes de salir
    if (m_accountsLoaded)
        saveAccounts();
    // 10. Limpiar farms
    m_farms.clear();
    m_spawning.store(false);
    emit farmRunningChanged();
    emit spawningChanged();
}

void FarmController::stopFarm()
{
    // v41 (bug 2026-08-12: "el boton de stop no para nada"): si el STOP se
    // pulsa durante el pre-spawn en cascada (stagger de 5s por cuenta, hasta
    // 40s), los QTimer::singleShot pendientes SEGUIAN creando farms nuevos
    // despues del stop (los workers nuevos no recibian stop -> el farm no
    // paraba) y el orquestador de logins seguia vivo -> AV rip=0 con TPM
    // logins + recvFrame corrupto en el crash (workers abortados a mitad de
    // handshake mientras el spawn creaba mas). Abortar el spawn aqui: los
    // singleShot chequean el flag y no crean nada mas.
    m_abortingSpawn.store(true);
    // Parar todos los workers: cada uno aborta su socket y sale de run()
    // en <1s (recvFrame/waitForReadyRead se desbloquea con el abort).
    // NO se espera aqui: el wait(8000) por farm congelaba la UI hasta 72s
    // con 9 farms ("la interfaz enloquece"). El cleanup real lo hace el
    // connect(thread, finished, ...) de spawnOneFarm: remueve el handle y
    // emite farmRunningChanged cuando cada thread termina.
    for (int i = 0; i < m_farms.size(); ++i) {
        if (m_farms.at(i).worker)
            m_farms.at(i).worker->stop();
    }
    m_totalXpGained = 0;
    m_deaths = 0;
    m_spawned = false;
    // v45 (bug: "el stop no detiene el contador ni quita el Connecting"): los
    // handles de m_farms quedaban hasta que cada thread terminara (los
    // workers en reconnect pueden tardar segundos) -> la UI seguia mostrando
    // "Connecting"/"Farming" y el contador corria. Limpiar m_farms AHORA:
    // los workers vivos tienen m_stop=true y mueren solos (su lambda de
    // finished ya no encuentra el handle -> no pasa nada, solo rebuilds).
    m_farms.clear();
    emit farmRunningChanged();
    emit totalXpGainedChanged();
    emit xpTextChanged();
    rebuildActiveSessions();
    // v45: el QML limpia el contador cuando workflowAccounts deja de traer
    // farmStatus; emitir accountsChanged YA para que la UI reaccione al
    // instante (no esperar al proximo flush).
    emit accountsChanged();
    m_stateText = QStringLiteral("Stopping farms...");
    emit stateTextChanged();
    // v44 (bug: "el autorefresh nunca se paro con el stop"): el timer del
    // auto-refresh seguia disparando refreshAll aunque no hubiera farms.
    // Pararlo aqui; spawn() lo reactiva si el switch sigue activo.
    if (m_autoRefreshTimer)
        m_autoRefreshTimer->stop();
    appendLog(QStringLiteral("Farm stop requested by user"));
}

void FarmController::quitApp()
{
    shutdown();
    QCoreApplication::quit();
}

// ===================== ACCOUNTS MANAGEMENT =====================

void FarmController::loadAccounts()
{
    const QString path = accountsFilePath();
    QFile f(path);
    if (!f.open(QIODevice::ReadOnly))
        return;
    const QByteArray data = f.readAll();
    f.close();
    const QJsonDocument doc = QJsonDocument::fromJson(data);
    if (!doc.isArray())
        return;
    m_accounts = doc.array().toVariantList();
    sortAccounts();
    m_accountsLoaded = true;
    emit accountsChanged();
}

void FarmController::saveAccounts()
{
    if (!m_accountsLoaded)
        return;
    const QString path = accountsFilePath();
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate))
        return;
    const QJsonDocument doc(QJsonArray::fromVariantList(m_accounts));
    f.write(doc.toJson(QJsonDocument::Compact));
    f.close();
}

void FarmController::sortAccounts()
{
    // Favoritos primero, luego A-Z
    std::stable_sort(m_accounts.begin(), m_accounts.end(), [](const QVariant &a, const QVariant &b) {
        const bool fa = a.toMap().value(QStringLiteral("favorite")).toBool();
        const bool fb = b.toMap().value(QStringLiteral("favorite")).toBool();
        if (fa != fb) return fa;
        const QString na = a.toMap().value(QStringLiteral("name")).toString().toLower();
        const QString nb = b.toMap().value(QStringLiteral("name")).toString().toLower();
        return na < nb;
    });
}

void FarmController::useAccount(int index)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    const QVariantMap am = m_accounts.at(index).toMap();
    const QString device = am.value(QStringLiteral("device")).toString();
    if (device.isEmpty())
        return;
    setDeviceId(device);
    applyAccount(index);
}

// Busca por deviceId real (el modelo filtrado/ordenado de la UI puede no
// coincidir con el orden de m_accounts: usar device evita seleccionar otra cuenta)
void FarmController::useAccountByDevice(const QString &device)
{
    if (device.isEmpty())
        return;
    for (int i = 0; i < m_accounts.size(); ++i) {
        if (m_accounts.at(i).toMap().value(QStringLiteral("device")).toString() == device) {
            setDeviceId(device);
            applyAccount(i);
            return;
        }
    }
}

void FarmController::removeAccount(int index)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    m_accounts.removeAt(index);
    saveAccounts();
    emit accountsChanged();
}

void FarmController::toggleFavorite(int index)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    QVariantMap am = m_accounts.at(index).toMap();
    const bool fav = am.value(QStringLiteral("favorite")).toBool();
    am.insert(QStringLiteral("favorite"), !fav);
    m_accounts[index] = am;
    sortAccounts();
    saveAccounts();
    emit accountsChanged();
}

bool FarmController::toggleFarmSelection(int index, bool checked)
{
    if (index < 0 || index >= m_accounts.size())
        return false;
    const QVariantMap am = m_accounts.at(index).toMap();
    const QString device = am.value(QStringLiteral("device")).toString();
    if (checked) {
        if (m_farmSelection.size() >= kMaxFarmSelection)
            return false;
        if (!m_farmSelection.contains(device))
            m_farmSelection.append(device);
    } else {
        m_farmSelection.removeAll(device);
    }
    // Persistencia de la seleccion: las casillas marcadas sobreviven al cierre
    saveFarmSelection();
    emit farmSelectionChanged();
    return true;
}

bool FarmController::toggleFarmSelectionByDevice(const QString &device, bool checked)
{
    if (device.isEmpty())
        return false;
    int index = -1;
    for (int i = 0; i < m_accounts.size(); ++i) {
        if (m_accounts.at(i).toMap().value(QStringLiteral("device")).toString() == device) {
            index = i;
            break;
        }
    }
    if (index < 0)
        return false;
    if (checked) {
        if (m_farmSelection.size() >= kMaxFarmSelection)
            return false;
        if (!m_farmSelection.contains(device))
            m_farmSelection.append(device);
    } else {
        m_farmSelection.removeAll(device);
    }
    saveFarmSelection();
    emit farmSelectionChanged();
    return true;
}

void FarmController::clearFarmSelection()
{
    m_farmSelection.clear();
    saveFarmSelection();
    emit farmSelectionChanged();
}

QVariantList FarmController::filteredAccounts() const
{
    if (m_accountSearch.isEmpty())
        return m_accounts;
    QVariantList result;
    const QString search = m_accountSearch.toLower();
    for (const auto &v : m_accounts) {
        const QVariantMap am = v.toMap();
        const QString name = am.value(QStringLiteral("name")).toString().toLower();
        const QString device = am.value(QStringLiteral("device")).toString().toLower();
        if (name.contains(search) || device.contains(search))
            result.append(v);
    }
    return result;
}

QVariantList FarmController::workflowAccounts() const
{
    if (m_farmSelection.isEmpty())
        return QVariantList();
    QVariantList result;
    for (const auto &v : m_accounts) {
        QVariantMap am = v.toMap();
        const QString dev = am.value(QStringLiteral("device")).toString();
        if (!m_farmSelection.contains(dev))
            continue;
        // Enriquecer con datos de runtime del farm activo
        bool hasFarm = false;
        for (const auto &fh : m_farms) {
            if (fh.deviceId == dev && fh.thread) {
                hasFarm = true;
                am.insert(QStringLiteral("lastXp"), fh.lastXp);
                // v97ec: el delegate lee xpGained. Si el refresh persistio el
                // delta de la gema (xpGained en la DB), respetarlo — el lastXp
                // del op24 es XP de la partida, no de la gema, y ademas se
                // pierde al re-spawnear (FarmHandle nuevo con lastXp=0).
                if (am.value(QStringLiteral("xpGained")).toLongLong() <= 0)
                    am.insert(QStringLiteral("xpGained"), fh.lastXp);
                // v42 (bug workflow: mostraba la gema del cache, no la que se
                // farmeaba): el spawn elige la gema por PRIORIDAD (p.ej. rosa)
                // aunque el cache persistido diga otra (p.ej. roja) — el XP en
                // vivo y la barra deben mostrar la gema REAL del worker
                // (worker->gemItem()), no la del accounts.json. Buscarla en el
                // cache de la cuenta y sobrescribir sprite/summary/cexp/exp.
                const int liveGemId = (fh.worker && fh.thread->isRunning())
                    ? fh.worker->gemItem() : fh.gemId;
                if (liveGemId > 0) {
                    const QVariantList cached = am.value(QStringLiteral("gems")).toList();
                    for (const auto &gv : cached) {
                        const QVariantMap gm = gv.toMap();
                        if (gm.value(QStringLiteral("id")).toInt() != liveGemId)
                            continue;
                        const QString name = gm.value(QStringLiteral("name")).toString();
                        const QString sprite = gm.value(QStringLiteral("sprite")).toString();
                        const int lvl = gm.value(QStringLiteral("level")).toInt();
                        if (!sprite.isEmpty())
                            am.insert(QStringLiteral("sprite"), sprite);
                        if (!name.isEmpty())
                            am.insert(QStringLiteral("gemSummary"),
                                      QStringLiteral("%1 Lv%2").arg(name).arg(lvl));
                        am.insert(QStringLiteral("gemLevel"), lvl);
                        am.insert(QStringLiteral("cexp"), gm.value(QStringLiteral("cexp")));
                        am.insert(QStringLiteral("exp"), gm.value(QStringLiteral("exp")));
                        am.insert(QStringLiteral("equippedGemId"), liveGemId);
                        break;
                    }
                }
                // CEXP es el XP real de la gema. fh.lastXp viene del op24 y
                // representa XP del mapa/sesion; no se puede sumar a CEXP.
                // Mantener ambas medidas separadas evita falsear la barra.
                if (fh.lastGemCexp >= 0)
                    am.insert(QStringLiteral("cexp"), fh.lastGemCexp);
                am.insert(QStringLiteral("deaths"), fh.deaths);
                am.insert(QStringLiteral("spawned"), fh.spawned);
                am.insert(QStringLiteral("startedAt"), fh.startedAt);
                // v44 (bug: el contador no se detenia con STOP): fh.spawned
                // queda true cuando el worker muere pero el handle aun esta en
                // m_farms (ventana hasta el lambda de finished) -> farmStatus
                // "Farming" -> el timer QML seguia corriendo. "Farming" SOLO si
                // el thread sigue vivo; thread muerto = Idle (para el contador).
                am.insert(QStringLiteral("farmStatus"),
                    (fh.thread && fh.thread->isRunning() && fh.spawned) ? QStringLiteral("Farming") :
                    (fh.thread && fh.thread->isRunning() ? QStringLiteral("Connecting") : QStringLiteral("Idle")));
                // 2026-08-10: estado REAL del auto-buy x2 (indicador por cuenta)
                // 2026-08-12 (crash STOP): el worker se destruye en el thread
                // cuando run() sale, ANTES de que el GUI procese el lambda de
                // finished que lo quita de m_farms. En esa ventana fh.worker
                // es un puntero colgante -> x2State() = vtable NULL (SEH
                // 0xC0000005, rip=0). Nunca tocar el worker si el thread ya
                // no corre: el badge cae al estado persistido del inventario.
                if (fh.worker && fh.thread && fh.thread->isRunning()) {
                    am.insert(QStringLiteral("x2State"), fh.worker->x2State());
                    am.insert(QStringLiteral("x2Reason"), fh.worker->x2Reason());
                } else if (am.contains(QStringLiteral("x2State"))) {
                    // 2026-08-10 (pedido del usuario: "todas las cuentas"):
                    // estado PERSISTIDO por scanAllX2 (login propio aunque la
                    // cuenta no farmee) — el badge refleja el inventario real
                    // sin necesidad de sesion de farm.
                } else {
                    // cuenta seleccionada SIN farm activo ni scan: el badge
                    // refleja el flag CONFIGURADO (activado -> pendiente de
                    // sesion; desactivado -> razon clara).
                    am.insert(QStringLiteral("x2State"), 0);
                    am.insert(QStringLiteral("x2Reason"),
                              m_autoBuyX2 ? QStringLiteral("activado, esperando sesion de farm")
                                          : QStringLiteral("auto-buy x2 desactivado"));
                }
                break;
            }
        }
        // v44 (bug workflow: mostraba la gema VIEJA del cache cuando no hay
        // farm activo — p.ej. Hades66 con la roja persistida aunque el RUN
        // equipara la rosa por prioridad): simular la MISMA eleccion del
        // spawn() sobre el cache de la cuenta y mostrar ESA gema. Asi el
        // dashboard siempre anticipa la gema que se farmeara (y el refresh
        // de XP actualiza la correcta).
        if (!hasFarm) {
            const QVariantList cached = am.value(QStringLiteral("gems")).toList();
            int pickId = -1;
            // 1. prioridad de color (m_gemPriority): primera del cache del
            //    color mas preferido con itemLevel < 25 (igual que spawn()).
            for (int ci : gemPriorityForDevice(dev)) {
                if (ci < 0 || ci >= 20) continue;
                for (const auto &gv : cached) {
                    const QVariantMap gm = gv.toMap();
                    if (gm.value(QStringLiteral("level")).toInt() >= 25) continue;
                    if (gemColorIndexByName(gm.value(QStringLiteral("name")).toString()) == ci) {
                        pickId = gm.value(QStringLiteral("id")).toInt();
                        break;
                    }
                }
                if (pickId > 0) break;
            }
            // 2. gema equipada persistida, 3. primera del cache
            if (pickId < 0)
                pickId = am.value(QStringLiteral("equippedGemId")).toInt();
            if (pickId < 0 && !cached.isEmpty())
                pickId = cached.first().toMap().value(QStringLiteral("id")).toInt();
            for (const auto &gv : cached) {
                const QVariantMap gm = gv.toMap();
                if (gm.value(QStringLiteral("id")).toInt() != pickId)
                    continue;
                const QString name = gm.value(QStringLiteral("name")).toString();
                const QString sprite = gm.value(QStringLiteral("sprite")).toString();
                const int lvl = gm.value(QStringLiteral("level")).toInt();
                if (!sprite.isEmpty())
                    am.insert(QStringLiteral("sprite"), sprite);
                if (!name.isEmpty())
                    am.insert(QStringLiteral("gemSummary"),
                              QStringLiteral("%1 Lv%2").arg(name).arg(lvl));
                am.insert(QStringLiteral("gemLevel"), lvl);
                am.insert(QStringLiteral("cexp"), gm.value(QStringLiteral("cexp")));
                am.insert(QStringLiteral("exp"), gm.value(QStringLiteral("exp")));
                am.insert(QStringLiteral("equippedGemId"), pickId);
                break;
            }
        }
        result.append(am);
    }
    return result;
}

void FarmController::applyAccount(int real)
{
    if (real < 0 || real >= m_accounts.size())
        return;
    const QVariantMap am = m_accounts.at(real).toMap();
    const QString device = am.value(QStringLiteral("device")).toString();
    setDeviceId(device);
    m_accountText = am.value(QStringLiteral("name")).toString();
    if (m_accountText.isEmpty())
        m_accountText = shortDevice(device);
    // Restaura las gemas cacheadas
    m_gems.clear();
    const QVariantList cached = am.value(QStringLiteral("gems")).toList();
    for (const auto &gv : cached)
        m_gems.append(gv.toMap());
    // FUENTE UNICA DE VERDAD (2026-08-10, bug de consistencia Java): la gema
    // equipada es equippedGemId de la cuenta; TODAS las vistas (tarjeta del
    // Workflow, panel "Current gem progress", badge "Equipped" del inventario)
    // derivan de ESE campo. applyAccountCache carga el inventario y deriva
    // m_selectedGem + m_gemXpText de la MISMA fila del cache.
    applyAccountCache(am);
    emit accountTextChanged();
    emit gemsChanged();
    emit selectedGemChanged();
    emit gemXpTextChanged();
}

// 2026-08-10 (fuente unica de verdad): carga m_gems desde el cache de la
// cuenta y deriva m_selectedGem del equippedGemId buscando la fila en el
// inventario. Antes applyAccount ponia SIEMPRE 0 -> el panel "Current gem
// progress" mostraba el icono de la primera gema del cache (Cyan) con la XP
// de la equipada (Pink) y el inventario marcaba "Equipped" en la fila
// equivocada. El XP/nivel salen de la MISMA fila (cexp/exp/level del cache),
// no de campos sueltos del am.
void FarmController::applyAccountCache(const QVariantMap &am)
{
    m_gems.clear();
    const QVariantList cached = am.value(QStringLiteral("gems")).toList();
    for (const auto &gv : cached)
        m_gems.append(gv.toMap());
    m_selectedGem = -1;
    const int equippedId = am.value(QStringLiteral("equippedGemId")).toInt();
    for (int i = 0; i < m_gems.size(); ++i) {
        if (m_gems.at(i).toMap().value(QStringLiteral("id")).toInt() == equippedId) {
            m_selectedGem = i;
            break;
        }
    }
    if (m_selectedGem < 0 && !m_gems.isEmpty())
        m_selectedGem = 0; // fallback: primera gema (equippedId no esta en el cache)
    if (m_selectedGem >= 0) {
        const QVariantMap gm = m_gems.at(m_selectedGem).toMap();
        const qlonglong cexp = gm.value(QStringLiteral("cexp")).toLongLong();
        const qlonglong exp = gm.value(QStringLiteral("exp")).toLongLong();
        const int lvl = gm.value(QStringLiteral("level")).toInt();
        if (cexp > 0 || exp > 0) {
            m_gemXpText = QStringLiteral("Gem XP %1/%2 | Gained (delta): -- | Level: %3")
                              .arg(cexp).arg(exp).arg(lvl);
        }
    }
}

int FarmController::accountIndexForFiltered(int filteredIndex) const
{
    if (m_accountSearch.isEmpty())
        return filteredIndex;
    int count = 0;
    const QString search = m_accountSearch.toLower();
    for (int i = 0; i < m_accounts.size(); ++i) {
        const QVariantMap am = m_accounts.at(i).toMap();
        const QString name = am.value(QStringLiteral("name")).toString().toLower();
        const QString device = am.value(QStringLiteral("device")).toString().toLower();
        if (name.contains(search) || device.contains(search)) {
            if (count == filteredIndex)
                return i;
            count++;
        }
    }
    return -1;
}

void FarmController::applyRefreshResult(int index, const QVariantMap &result, bool emitChange)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    QVariantMap am = m_accounts.at(index).toMap();
    for (auto it = result.constBegin(); it != result.constEnd(); ++it)
        am.insert(it.key(), it.value());
    am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
    m_accounts[index] = am;
    if (emitChange)
        emit accountsChanged();
}

// ===================== REFRESH ALL ACCOUNTS =====================

void FarmController::refreshAllAccounts()
{
    QStringList devices;
    for (const QVariant &account : m_accounts) {
        const QString device = account.toMap().value(QStringLiteral("device")).toString();
        if (!device.isEmpty() && !devices.contains(device))
            devices.append(device);
    }
    refreshAccounts(devices, false);
}

// El timer solo refresca las cuentas que siguen marcadas Y tienen un farm
// activo. Tomar este snapshot evita que un cambio de checkbox a mitad del
// ciclo haga login en una cuenta que el usuario ya desmarco.
void FarmController::refreshSelectedFarmAccounts()
{
    QStringList devices;
    for (const FarmHandle &farm : m_farms) {
        if (!farm.worker || !farm.thread || !farm.thread->isRunning())
            continue;
        if (!m_farmSelection.contains(farm.deviceId) || devices.contains(farm.deviceId))
            continue;
        devices.append(farm.deviceId);
    }
    refreshAccounts(devices, true);
}

void FarmController::refreshAccounts(const QStringList &devices, bool automatic)
{
    if (m_refreshingAll)
        return;
    if (devices.isEmpty()) {
        if (!automatic)
            emit toastMessage(QStringLiteral("No accounts to refresh"));
        return;
    }

    m_refreshTargetDevices = devices;
    m_refreshIsAutomatic = automatic;
    m_refreshingAll = true;
    m_refreshAllProgress = 0;
    m_refreshAllStatus = automatic
        ? QStringLiteral("Auto-refresh: stopping selected farms...")
        : QStringLiteral("Stopping farms...");
    emit refreshAllProgressChanged();
    m_abortingRefreshAll.store(false);

    // v38 (pedido del usuario: "volver a hacer todo el proceso"): el refresh
    // SIMPLE = STOP de las sesiones objetivo + login nuevo de las cuentas
    // objetivo + re-spawn de las que estaban farmeando. Al terminar la sesion
    // el server materializa el cexp real (el cexp en partida se congela), asi
    // el login nuevo lee el XP correcto. Sin kick FFA ni settle de worker.
    QStringList respawnDevices;
    for (const auto &fh : m_farms) {
        if (!fh.worker || !fh.thread || !fh.thread->isRunning())
            continue;
        if (!m_refreshTargetDevices.contains(fh.deviceId))
            continue;
        if (!respawnDevices.contains(fh.deviceId))
            respawnDevices.append(fh.deviceId);
        fh.worker->stop();
    }
    // si no habia farms, el respawn no aplica: solo se refresca la data
    m_refreshRespawnDevices = respawnDevices;

    appendLog(QStringLiteral("%1: stopping %2 farm(s), then fresh login of %3 account(s)")
                  .arg(automatic ? QStringLiteral("Auto-refresh") : QStringLiteral("Refresh"))
                  .arg(respawnDevices.size()).arg(m_refreshTargetDevices.size()));
    writeLogFile(QStringLiteral("[Refresh] stopping %1 farm(s)").arg(respawnDevices.size()));

    // poll: espera asincrona a que todos los threads de farm terminen (el
    // connect(thread, finished) los quita de m_farms), luego login de todas.
    // v40 (bug 2026-08-12: el login nunca arrancaba y la app crasheo): si un
    // worker queda colgado en backoff/reconnect (msleep de hasta ~16s que NO
    // chequea m_stop), m_farms nunca se vacia y el poll esperaba para siempre.
    // Timeout de 30s (cubre el backoff maximo): pasado el plazo se procede
    // igual, pero filtrando del respawn los devices aun vivos. El login del
    // refresh NUNCA debe solaparse con un worker vivo de la MISMA cuenta
    // (doble login simultaneo = race de Qt 6.10.3, AV; los TPM eh warnings
    // del crash apuntaban a un worker viejo reintentando login mientras el
    // refresh logueaba esa misma cuenta).
    m_refreshWaitDeadline = QDateTime::currentMSecsSinceEpoch() + 30000;
    m_refreshWaitingFarms = true;
    QTimer::singleShot(0, this, [this]() { maybeStartRefreshAllLogin(); });
}

void FarmController::maybeStartRefreshAllLogin()
{
    if (!m_refreshingAll)
        return;
    // v41: limpiar handles huerfanos (worker o thread ya muertos pero aun en
    // m_farms por el bug del QPointer). Sin esto el poll los contaba como
    // "farms vivos" y el login del refresh nunca arrancaba.
    for (int i = m_farms.size() - 1; i >= 0; --i) {
        const FarmHandle &fh = m_farms.at(i);
        if (!fh.thread || !fh.thread->isRunning())
            m_farms.removeAt(i);
    }
    int runningTargetFarms = 0;
    for (const FarmHandle &farm : m_farms) {
        if (m_refreshTargetDevices.contains(farm.deviceId)
            && farm.thread && farm.thread->isRunning()) {
            ++runningTargetFarms;
        }
    }
    if (m_refreshWaitingFarms) {
        const bool stillRunning = runningTargetFarms > 0;
        if (stillRunning) {
            // v40: timeout — si un worker no termina, no bloquear el refresh
            // para siempre. Los devices cuyo thread sigue vivo se quitan del
            // respawn.
            if (QDateTime::currentMSecsSinceEpoch() < m_refreshWaitDeadline) {
                QTimer::singleShot(250, this, [this]() { maybeStartRefreshAllLogin(); });
                return;
            }
            appendLog(QStringLiteral("Refresh: %1 farm(s) no terminaron en 30s, continuando sin ellos")
                          .arg(runningTargetFarms));
            writeLogFile(QStringLiteral("[Refresh] %1 farms colgados tras el timeout, login sigue")
                             .arg(runningTargetFarms));
            // v97el: leak 28 farms — los handles colgados quedan en m_farms y el siguiente ciclo duplica
            // De 9->15->28 en el log. Forzar limpieza: abortar y sacar de m_farms para no bloquear spawn.
            for (int i = m_farms.size() - 1; i >= 0; --i) {
                const FarmHandle &fh = m_farms.at(i);
                if (m_refreshTargetDevices.contains(fh.deviceId) && fh.thread && fh.thread->isRunning()) {
                    if (fh.worker) fh.worker->stop();
                    if (fh.thread) fh.thread->requestInterruption();
                    m_farms.removeAt(i);
                }
            }
        }
    }
    m_refreshWaitingFarms = false;

    appendLog(QStringLiteral("Refresh: login nuevo de %1 cuentas...").arg(m_refreshTargetDevices.size()));
    writeLogFile(QStringLiteral("[Refresh] login nuevo de %1 cuentas, respawn %2")
                     .arg(m_refreshTargetDevices.size()).arg(m_refreshRespawnDevices.size()));

    // Snapshot de devices (GUI thread): TODAS las cuentas, sin saltarse las
    // que farmeaban. Se capturan tambien el orden de colores priorizados
    // (para re-equipar segun prioridad si la gema desaparecio) y el cache de
    // gemas de cada cuenta.
    // v43 (pedido del usuario: "espera 30s y vuelve a hacer el login de las
    // cuentas y todo lo demas"): ANTES se EXCLUIA del login a las cuentas
    // cuyo worker seguia vivo tras el timeout -> esas cuentas nunca se
    // refrescaban y el respawn daba 0. AHORA se loguean TODAS: el login
    // nuevo kicnea la sesion vieja del worker en el server (que ya tiene
    // m_stop=true, no reintenta), el worker viejo muere solo y el respawn
    // final solo descarta las que genuinamente sigan colgadas.
    struct RefreshTarget {
        QString deviceId;
        QString name;
        QVector<int> priority;
        QVariantList cachedGems;
    };
    QVector<RefreshTarget> targets;
    for (const auto &v : m_accounts) {
        const QVariantMap m = v.toMap();
        if (!m_refreshTargetDevices.contains(m.value(QStringLiteral("device")).toString()))
            continue;
        RefreshTarget t;
        t.deviceId = m.value(QStringLiteral("device")).toString();
        t.name = m.value(QStringLiteral("name")).toString();
        t.priority = gemPriorityForDevice(t.deviceId);
        t.cachedGems = m.value(QStringLiteral("gems")).toList();
        targets.append(t);
    }
    const int total = targets.size();
    if (total == 0) {
        m_refreshingAll = false;
        m_refreshTargetDevices.clear();
        m_refreshIsAutomatic = false;
        emit refreshAllProgressChanged();
        emit toastMessage(QStringLiteral("No accounts to refresh"));
        return;
    }

    QThread *thread = new QThread(this);
    m_refreshAllThread = thread;
    connect(thread, &QThread::started, thread, [this, thread, targets, total]() {
        for (int k = 0; k < total; ++k) {
            if (m_abortingRefreshAll.load())
                break;
            const QString deviceId = targets.at(k).deviceId;
            const QVector<int> &priority = targets.at(k).priority;
            const QString pemPath = fakeTpmPathForDevice(deviceId);
            struct RefreshOut {
                bool ok = false;
                bool gemsEmptyConfirmed = false;
                QString name;
                qlonglong coins = 0;
                QVector<GemInfo> gems;
                int equippedId = -1;     // v41: data.current del inventario (la EQUIPADA real)
                QString repairLog;   // v39: resultado del auto-repair
                QString reequipLog;  // v39: resultado del re-equip por prioridad
                int x2State = -1;    // v44: x2 detectado/comrado en el refresh
                QString x2Reason;
            } out;
            if (!pemPath.isEmpty()) {
                LoginManager local;
                QFile pf(pemPath);
                if (pf.open(QIODevice::ReadOnly)) {
                    local.setAttestPem(QString::fromUtf8(pf.readAll()));
                    pf.close();
                }
                const LoginResult r = local.login(deviceId);
                if (r.ok) {
                    out.ok = true;
                    out.name = local.fetchAccountName();
                    out.coins = local.lastCoins();
                    out.gems = local.fetchInventory(5);
                    out.equippedId = local.lastCurrentItem();
                    if (out.gems.isEmpty()) {
                        QThread::msleep(1000);
                        out.gems = local.fetchInventory(5);
                        out.equippedId = local.lastCurrentItem();
                    }
                    // v39 (pedido del usuario): el refresh mantiene las gemas
                    // operativas. 1) REPAIR: la gema EQUIPADA (data.current,
                    // no gems.first()) solo se repara si esta ROTA de verdad
                    // (durability 0 — las gemas no se danan parcialmente,
                    // pasan de sanas a 0/100). 2) RE-EQUIP: si la gema
                    // equipada DESAPARECIO del inventario (limite de XP o
                    // rotura total), se equipa otra segun el gem priority.
                    // v45 (bug: el re-equip solo corria con el inventario
                    // VACIO — la gema que llega al limite de XP se va sola
                    // pero quedan otras gemas, y el fallback gems.first()
                    // la equipaba sin respetar la prioridad).
                    if (!out.gems.isEmpty()) {
                        const GemInfo *egPtr = nullptr;
                        for (const GemInfo &g : out.gems) {
                            if (g.id == out.equippedId) { egPtr = &g; break; }
                        }
                        if (egPtr) {
                            // la equipada sigue en el inventario: repair si rota
                            const GemInfo &eg = *egPtr;
                            if (eg.maxDurability > 0 && eg.durability == 0) {
                                const QJsonObject resp = local.apiCall(
                                    QStringLiteral("{\"do\":\"repair\",\"item\":%1,\"slot\":5}").arg(eg.id));
                                const bool okRepair = resp.value(QStringLiteral("result")).toString() == QLatin1String("ok");
                                out.repairLog = okRepair
                                    ? QStringLiteral("repaired gem %1 (%2/%3)")
                                          .arg(eg.id).arg(eg.durability).arg(eg.maxDurability)
                                    : QStringLiteral("repair gem %1 failed: %2")
                                          .arg(eg.id).arg(resp.value(QStringLiteral("message")).toString().left(40));
                                if (okRepair) {
                                    QThread::msleep(600);
                                    out.gems = local.fetchInventory(5);
                                    out.equippedId = local.lastCurrentItem();
                                }
                            }
                        } else {
                            // la equipada desaparecio (limite de XP): elegir la
                            // siguiente por PRIORIDAD entre las gemas del
                            // inventario REAL (no el cache viejo).
                            int bestId = -1;
                            QString bestCk;
                            for (int ci : priority) {
                                if (ci < 0 || ci >= 20) continue;
                                for (const GemInfo &g : out.gems) {
                                    if (g.itemLevel >= 25) continue;
                                    if (gemColorIndexByName(g.name) != ci) continue;
                                    if (g.id == out.equippedId) continue;
                                    if (g.durability == 0 && g.maxDurability > 0) continue;
                                    bestId = g.id;
                                    bestCk = QString::number(ci);
                                    break;
                                }
                                if (bestId > 0) break;
                            }
                            if (bestId > 0) {
                                const QJsonObject resp = local.apiCall(
                                    QStringLiteral("{\"do\":\"equip\",\"item\":%1,\"slot\":5}").arg(bestId));
                                const bool okEquip = resp.value(QStringLiteral("result")).toString() == QLatin1String("ok");
                                out.reequipLog = okEquip
                                    ? QStringLiteral("gema equipada desaparecio (limite XP) - re-equipped gem %1 por prioridad (%2)")
                                          .arg(bestId).arg(bestCk)
                                    : QStringLiteral("re-equip gem %1 failed: %2")
                                          .arg(bestId).arg(resp.value(QStringLiteral("message")).toString().left(40));
                                if (okEquip) {
                                    QThread::msleep(600);
                                    out.gems = local.fetchInventory(5);
                                    out.equippedId = local.lastCurrentItem();
                                }
                            } else {
                                out.reequipLog = QStringLiteral("gema equipada desaparecio y no hay otra gema valida para re-equipar");
                            }
                        }
                    } else if (!priority.isEmpty()) {
                        // buscar en el cache de la cuenta la primera gema cuyo
                        // color este mas arriba en la prioridad
                        const QVariantList cached = targets.at(k).cachedGems;
                        int bestId = -1;
                        QString bestCk;
                        for (int ci : priority) {
                            for (const auto &gv : cached) {
                                const QVariantMap gm = gv.toMap();
                                if (gemColorIndexByName(gm.value(QStringLiteral("name")).toString()) != ci)
                                    continue;
                                const int dur = gm.value(QStringLiteral("durability")).toInt();
                                if (dur <= 0)
                                    continue;
                                // v42: las gemas lvl 25 estan PROHIBIDAS
                                if (gm.value(QStringLiteral("level")).toInt() >= 25)
                                    continue;
                                bestId = gm.value(QStringLiteral("id")).toInt();
                                bestCk = QString::number(ci);
                                break;
                            }
                            if (bestId > 0)
                                break;
                        }
                        if (bestId > 0) {
                            const QJsonObject resp = local.apiCall(
                                QStringLiteral("{\"do\":\"equip\",\"item\":%1,\"slot\":5}").arg(bestId));
                            const bool okEquip = resp.value(QStringLiteral("result")).toString() == QLatin1String("ok");
                            out.reequipLog = okEquip
                                ? QStringLiteral("re-equipped gem %1 (%2) por prioridad").arg(bestId).arg(bestCk)
                                : QStringLiteral("re-equip gem %1 failed: %2")
                                      .arg(bestId).arg(resp.value(QStringLiteral("message")).toString().left(40));
                            if (okEquip) {
                                QThread::msleep(600);
                                out.gems = local.fetchInventory(5);
                            }
                        }
                    }
                    out.gemsEmptyConfirmed = out.gems.isEmpty();
                    // v44 (pedido del usuario: "si el x2 se acaba, el refresh
                    // deberia detectarlo y volverlo a comprar"): el worker ya
                    // renueva el x2 cada 5 min MIENTRAS farmea (checkX2), pero
                    // las cuentas sin farm no. Aqui, con el login nuevo, se
                    // verifica el consumible 8590 (Double Gem XP) en slots 3/4:
                    // activo -> x2State=1; agotado/ausente + autoBuyX2 ON ->
                    // COMPRAR del store (cat 6); sin coins -> 3.
                    if (m_autoBuyX2) {
                        // v97eo: deteccion via buy (already_owned = activo 24h) — no depende de inventory hiccup
                        const QJsonObject store = local.apiCall(
                            QStringLiteral("{\"do\":\"store\",\"category\":6,\"evo\":false}"));
                        const QJsonArray storeItems = store.value(QStringLiteral("data")).toObject()
                                                          .value(QStringLiteral("items")).toArray();
                        int x2StoreId = -1;
                        qlonglong x2Price = 0;
                        QString x2StoreName;
                        for (const auto &si : storeItems) {
                            const QJsonObject item = si.toObject();
                            if (item.value(QStringLiteral("id")).toInt() != 8590)
                                continue;
                            x2StoreId = item.value(QStringLiteral("id")).toInt();
                            x2Price = item.value(QStringLiteral("price")).toVariant().toLongLong();
                            x2StoreName = item.value(QStringLiteral("name")).toString();
                            break;
                        }
                        if (x2StoreId > 0) {
                            const QJsonObject buy = local.apiCall(
                                QStringLiteral("{\"do\":\"buy\",\"item\":%1}").arg(x2StoreId));
                            const QString buyMsg = buy.value(QStringLiteral("message")).toString();
                            const bool buyOk = buy.value(QStringLiteral("result")).toString() == QLatin1String("ok");
                            if (buyOk) {
                                out.x2State = 1;
                                out.x2Reason = QStringLiteral("x2 comprado: %1").arg(x2StoreName);
                            } else if (buyMsg.contains(QLatin1String("already_owned"))) {
                                out.x2State = 1;
                                out.x2Reason = QStringLiteral("x2 activo (already_owned)");
                            } else if (buyMsg.contains(QLatin1String("insufficient")) || buyMsg.contains(QLatin1String("coins"))) {
                                out.x2State = 3;
                                out.x2Reason = QStringLiteral("sin coins para x2 (necesita %1, tiene %2)").arg(x2Price).arg(out.coins);
                            } else if (!buyMsg.isEmpty()) {
                                out.x2State = 2;
                                out.x2Reason = QStringLiteral("x2 no activo: %1").arg(buyMsg.left(40));
                            } else {
                                out.x2State = 2;
                                out.x2Reason = QStringLiteral("x2 no activo");
                            }
                        } else {
                            out.x2State = 2;
                            out.x2Reason = QStringLiteral("x2 no disponible en tienda");
                        }
                    }
                }
            }
            const RefreshOut o = out;
            const int progress = k + 1;
            QMetaObject::invokeMethod(this, [this, deviceId, o, progress, total]() {
                m_refreshAllProgress = progress;
                m_refreshAllStatus = QStringLiteral("Refreshed %1/%2").arg(progress).arg(total);
                // Aplica el resultado a la cuenta
                for (int i = 0; i < m_accounts.size(); ++i) {
                    QVariantMap am = m_accounts.at(i).toMap();
                    if (am.value(QStringLiteral("device")).toString() != deviceId)
                        continue;
                    if (o.ok) {
                        if (!o.name.isEmpty())
                            am.insert(QStringLiteral("name"), o.name);
                        if (o.coins > 0)
                            am.insert(QStringLiteral("coins"), o.coins);
                        if (!o.gems.isEmpty()) {
                            // v41: la gema del dashboard debe ser la EQUIPADA
                            // (data.current), no la primera del inventario —
                            // antes mostraba una gema sin prioridad.
                            const GemInfo *egPtr = nullptr;
                            for (const GemInfo &g : o.gems) {
                                if (g.id == o.equippedId) { egPtr = &g; break; }
                            }
                            const GemInfo &eg = egPtr ? *egPtr : o.gems.first();
                            // Comparar contra la instantanea tomada al presionar
                            // RUN, nunca contra el cache que pudo quedar de una
                            // sesion previa o de otra gema.
                            const qlonglong newCexp = qlonglong(eg.cexp);
                            const int baselineGemId = am.value(QStringLiteral("xpBaselineGemId"), -1).toInt();
                            const qlonglong baselineCexp = am.value(QStringLiteral("xpBaselineCexp"), -1).toLongLong();
                            am.remove(QStringLiteral("xpGainRefresh"));
                            if (baselineGemId == eg.id && baselineCexp >= 0 && newCexp >= baselineCexp)
                                am.insert(QStringLiteral("xpGainRefresh"), newCexp - baselineCexp);
                            // El siguiente auto-refresh mide su propio intervalo.
                            am.insert(QStringLiteral("xpBaselineGemId"), eg.id);
                            am.insert(QStringLiteral("xpBaselineCexp"), newCexp);
                            am.insert(QStringLiteral("sprite"), gemSpritePath(eg.name, eg.itemLevel));
                            am.insert(QStringLiteral("gemSummary"),
                                      QStringLiteral("%1 Lv%2").arg(translateGemName(eg.name)).arg(eg.itemLevel));
                            am.insert(QStringLiteral("gemLevel"), eg.itemLevel);
                            am.insert(QStringLiteral("cexp"), qlonglong(eg.cexp));
                            am.insert(QStringLiteral("exp"), qlonglong(eg.exp));
                            am.insert(QStringLiteral("equippedGemId"), eg.id);
                            am.insert(QStringLiteral("gems"), gemsCacheFrom(o.gems));
                        } else if (o.gemsEmptyConfirmed) {
                            am.remove(QStringLiteral("sprite"));
                            am.remove(QStringLiteral("gemSummary"));
                            am.remove(QStringLiteral("gemLevel"));
                            am.remove(QStringLiteral("cexp"));
                            am.remove(QStringLiteral("exp"));
                            am.remove(QStringLiteral("equippedGemId"));
                            am.remove(QStringLiteral("gems"));
                        }
                        am.insert(QStringLiteral("lastRefresh"), qint64(QDateTime::currentSecsSinceEpoch()));
                        // v44: persiste el x2 detectado/comprado en el refresh
                        if (o.x2State >= 0) {
                            am.insert(QStringLiteral("x2State"), o.x2State);
                            am.insert(QStringLiteral("x2Reason"), o.x2Reason);
                            appendLog(QStringLiteral("[Refresh] %1: x2 -> %2 (%3)")
                                          .arg(am.value(QStringLiteral("name")).toString().isEmpty()
                                                   ? shortDevice(deviceId)
                                                   : am.value(QStringLiteral("name")).toString())
                                          .arg(o.x2State)
                                          .arg(o.x2Reason));
                        }
                        if (!o.repairLog.isEmpty())
                            appendLog(QStringLiteral("[Refresh] %1: %2")
                                          .arg(am.value(QStringLiteral("name")).toString().isEmpty()
                                                   ? shortDevice(deviceId)
                                                   : am.value(QStringLiteral("name")).toString(),
                                               o.repairLog));
                        if (!o.reequipLog.isEmpty())
                            appendLog(QStringLiteral("[Refresh] %1: %2")
                                          .arg(am.value(QStringLiteral("name")).toString().isEmpty()
                                                   ? shortDevice(deviceId)
                                                   : am.value(QStringLiteral("name")).toString(),
                                               o.reequipLog));
                    }
                    m_accounts[i] = am;
                    break;
                }
                emit refreshAllProgressChanged();
                emit accountsChanged();
                if (progress == total) {
                    m_refreshingAll = false;
                    sortAccounts();
                    saveAccounts();
                    m_refreshAllStatus = m_refreshIsAutomatic
                        ? QStringLiteral("Auto-refresh: %1 farm account(s) refreshed").arg(total)
                        : QStringLiteral("All %1 accounts refreshed").arg(total);
                    emit refreshAllProgressChanged();
                    emit toastMessage(m_refreshAllStatus);
                    appendLog(QStringLiteral("Refresh completo: %1 cuentas, re-spawning %2 farm(s)")
                                  .arg(total).arg(m_refreshRespawnDevices.size()));
                    writeLogFile(QStringLiteral("[Refresh] done %1 cuentas, respawn %2")
                                     .arg(total).arg(m_refreshRespawnDevices.size()));
                    // v38: las cuentas que estaban farmeando se re-spawnean.
                    // v43 (pedido del usuario: "espera 30s y vuelve a hacer el
                    // login de las cuentas y todo lo demas"): el login nuevo
                    // ya kicneo las sesiones viejas (los workers tienen m_stop
                    // y mueren solos). Esperar hasta 30s mas a que terminen
                    // antes de respawnear — no descartarlos como antes.
                    if (!m_refreshRespawnDevices.isEmpty()) {
                        m_refreshWaitDeadline = QDateTime::currentMSecsSinceEpoch() + 30000;
                        maybeRespawnAfterRefresh();
                    }
                    m_refreshTargetDevices.clear();
                    m_refreshIsAutomatic = false;
                }
            }, Qt::QueuedConnection);
            // Pausa entre cuentas para no saturar el server
            if (k < total - 1)
                QThread::msleep(500);
        }
        QMetaObject::invokeMethod(this, [this, thread]() {
            m_refreshAllThread = nullptr;
            m_refreshingAll = false;
            m_refreshTargetDevices.clear();
            m_refreshIsAutomatic = false;
            thread->quit();
        }, Qt::QueuedConnection);
    }, Qt::DirectConnection);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// v38: re-spawnea las cuentas indicadas tras el refresh. spawn() toma su
// lista de m_farmSelection: se rellena temporalmente con los devices que
// estaban farmeando (spawn() hace el snapshot al entrar), se lanza y se
// restaura la seleccion original del usuario.
void FarmController::respawnDevices(const QStringList &devices)
{
    const QVariantList savedSelection = m_farmSelection;
    m_farmSelection.clear();
    for (const QString &d : devices)
        m_farmSelection.append(d);
    m_refreshRespawning = true;
    spawn();
    m_refreshRespawning = false;
    m_farmSelection = savedSelection;
    emit farmSelectionChanged();
}

// v43 (pedido del usuario: "espera 30s y vuelve a hacer el login de las
// cuentas y todo lo demas"): tras el login nuevo, los workers viejos tienen
// m_stop=true y mueren solos (su sesion fue kicneada por el login). Poll de
// hasta 30s esperando a que m_farms quede vacio; cuando ocurre (o el plazo
// expira) se respawnean los devices que quedan pendientes.
void FarmController::maybeRespawnAfterRefresh()
{
    // v43: NO chequear m_refreshingAll aqui — el caller (progress==total) ya
    // lo puso false antes de llamarnos. Solo la lista pendiente gobierna.
    if (m_refreshRespawnDevices.isEmpty())
        return;
    bool anyAlive = false;
    for (const auto &fh : m_farms) {
        if (m_refreshRespawnDevices.contains(fh.deviceId)
            && fh.thread && fh.thread->isRunning()) {
            anyAlive = true;
            break;
        }
    }
    if (anyAlive) {
        if (QDateTime::currentMSecsSinceEpoch() < m_refreshWaitDeadline) {
            QTimer::singleShot(500, this, [this]() { maybeRespawnAfterRefresh(); });
            return;
        }
        appendLog(QStringLiteral("Refresh: %1 farm(s) aun vivos tras 30s de espera, respawn sin ellos")
                      .arg(m_farms.size()));
        writeLogFile(QStringLiteral("[Refresh] %1 farms vivos tras espera, respawn sin ellos")
                         .arg(m_farms.size()));
    }
    // v97el: dedup leak 28->6 — toRespawn tenia duplicados por m_farms leakado
    QStringList toRespawn = m_refreshRespawnDevices;
    {
        QSet<QString> seen; QStringList uniq;
        for (const QString &d : toRespawn) if (!seen.contains(d)) { seen.insert(d); uniq.append(d); }
        toRespawn = uniq;
    }
    m_refreshRespawnDevices.clear();
    if (toRespawn.isEmpty()) {
        appendLog(QStringLiteral("Refresh: sin respawn"));
        writeLogFile(QStringLiteral("[Refresh] sin respawn"));
        return;
    }
    // v43 (respawn bloqueado por farmRunning): los workers viejos tienen
    // m_stop=true (mueren solos, sus threads se limpian via deleteLater del
    // finished) pero pueden seguir en m_farms (colgados esperando el mutex de
    // login del refresh) -> farmRunning()==true -> spawn() abortaba con "A
    // farm is already running" y el respawn quedaba en 0. Limpiar los handles
    // viejos de los devices a respawnear: el worker viejo muere solo (m_stop)
    // y el nuevo puede arrancar.
    for (int i = m_farms.size() - 1; i >= 0; --i) {
        if (toRespawn.contains(m_farms.at(i).deviceId))
            m_farms.removeAt(i);
    }
    appendLog(QStringLiteral("Refresh: respawn de %1 farm(s)").arg(toRespawn.size()));
    writeLogFile(QStringLiteral("[Refresh] respawn %1").arg(toRespawn.size()));
    respawnDevices(toRespawn);
}

// ===================== REFRESH XP =====================

void FarmController::refreshXp()
{
    if (m_fetching)
        return;
    // Busca el farm activo de la cuenta actual
    const QString device = resolveDeviceId();
    FarmWorker *targetWorker = nullptr;
    for (int i = 0; i < m_farms.size(); ++i) {
        if (m_farms.at(i).deviceId == device && m_farms.at(i).worker) {
            targetWorker = m_farms.at(i).worker;
            break;
        }
    }
    if (!targetWorker) {
        emit toastMessage(QStringLiteral("No active farm for this account to refresh XP"));
        return;
    }
    // Lanza el refreshXp del worker en su thread
    QMetaObject::invokeMethod(targetWorker, &FarmWorker::refreshXp, Qt::QueuedConnection);
    appendLog(QStringLiteral("XP refresh requested for %1").arg(logName(device, QString())));
}

// ===================== QWS FILE LOADING =====================

void FarmController::loadQwsFiles(const QVariantList &paths)
{
    if (m_qwsLoading)
        return;
    const QStringList files = expandQwsPaths(paths);
    if (files.isEmpty()) {
        emit toastMessage(QStringLiteral("No .sol/.qws files found"));
        return;
    }
    m_qwsLoading = true;
    m_qwsProgress = 0;
    m_qwsStatus = QStringLiteral("Loading %1 files...").arg(int(files.size()));
    emit qwsProgressChanged();

    QThread *thread = new QThread(this);
    m_qwsThread = thread;
    connect(thread, &QThread::started, thread, [this, thread, files]() {
        QVariantList newAccounts;
        for (int i = 0; i < files.size(); ++i) {
            QFile f(files.at(i));
            if (!f.open(QIODevice::ReadOnly))
                continue;
            const QByteArray data = f.readAll();
            f.close();
            const QStringList devices = extractAllDeviceIds(data);
            for (const QString &dev : devices) {
                // Evita duplicados
                bool dup = false;
                for (const auto &nv : newAccounts) {
                    if (nv.toMap().value(QStringLiteral("device")).toString() == dev) {
                        dup = true;
                        break;
                    }
                }
                if (!dup) {
                    QVariantMap account;
                    account.insert(QStringLiteral("device"), dev);
                    account.insert(QStringLiteral("favorite"), false);
                    newAccounts.append(account);
                }
            }
            const int progress = i + 1;
            QMetaObject::invokeMethod(this, [this, progress, total = files.size()]() {
                m_qwsProgress = progress;
                m_qwsStatus = QStringLiteral("Loaded %1/%2 files").arg(progress).arg(total);
                emit qwsProgressChanged();
            }, Qt::QueuedConnection);
        }
        QMetaObject::invokeMethod(this, [this, thread, newAccounts, files]() {
            // Merge con cuentas existentes (sin borrar las que ya estan)
            for (const auto &nv : newAccounts) {
                const QString dev = nv.toMap().value(QStringLiteral("device")).toString();
                bool exists = false;
                for (int i = 0; i < m_accounts.size(); ++i) {
                    if (m_accounts.at(i).toMap().value(QStringLiteral("device")).toString() == dev) {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                    m_accounts.append(nv);
            }
            sortAccounts();
            saveAccounts();
            m_qwsLoading = false;
            emit accountsChanged();
            emit qwsProgressChanged();
                emit toastMessage(QStringLiteral("Loaded %1 accounts from %2 files").arg(newAccounts.size()).arg(files.size()));
            thread->quit();
        }, Qt::QueuedConnection);
    }, Qt::DirectConnection);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    thread->start();
}

// ===================== AUTO-REFRESH =====================

void FarmController::configureAutoRefresh(bool enabled, int intervalSeconds)
{
    const int secs = qMax(10, intervalSeconds);
    m_autoRefreshWanted = enabled;
    m_autoRefreshTimer->setInterval(secs * 1000);
    // v44: el timer solo corre con farms activos (spawn lo arranca, stopFarm
    // lo para). Aqui se aplica el estado solo si hay farms o el usuario pide
    // apagar.
    if (!enabled)
        m_autoRefreshTimer->stop();
    else if (farmRunning() || !m_farms.isEmpty())
        m_autoRefreshTimer->start();
    // Persistir
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("autoRefreshEnabled"), enabled);
    s.setValue(QStringLiteral("autoRefreshInterval"), secs);
    emit autoRefreshChanged();
}

// ===================== THEME =====================

bool FarmController::isValidTheme(const QString &theme)
{
    static const QStringList valid = {
        QStringLiteral("midnight"),
        QStringLiteral("light"),
        QStringLiteral("dark"),
        QStringLiteral("ocean"),
        QStringLiteral("forest"),
        QStringLiteral("sunset"),
        QStringLiteral("cyberpunk"),
        QStringLiteral("retro"),
    };
    return valid.contains(theme);
}

QString FarmController::theme() const
{
    const QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    const QString t = s.value(QStringLiteral("theme"), QStringLiteral("midnight")).toString();
    return isValidTheme(t) ? t : QStringLiteral("midnight");
}

void FarmController::saveTheme(const QString &t)
{
    const QString valid = isValidTheme(t) ? t : QStringLiteral("midnight");
    QSettings s(QStringLiteral("Astro Labs"), QStringLiteral("Astro"));
    s.setValue(QStringLiteral("theme"), valid);
}

QString FarmController::loadTheme()
{
    return theme();
}

// ===================== UI HELPERS =====================

void FarmController::flushUi()
{
    m_uiDirty = false;
    emit accountsChanged();
    emit activeSessionsChanged();
    // CRITICO: workflowAccounts se enriquece con datos de m_farms (lastXp,
    // startedAt, farmStatus) y su NOTIFY es farmSelectionChanged. Sin este
    // emit, el dashboard NUNCA refresca la XP ganada, el timer ni el status
    // de cada cuenta (bug 2026-08-10: solo se veian tras re-seleccionar).
    emit farmSelectionChanged();
}

void FarmController::scheduleUiFlush()
{
    m_uiDirty = true;
    if (!m_uiFlushTimer->isActive())
        m_uiFlushTimer->start();
}

void FarmController::setAccountSearch(const QString &text)
{
    if (m_accountSearch == text)
        return;
    m_accountSearch = text;
    emit accountSearchChanged();
}

bool FarmController::copyToClipboard(const QString &text)
{
    QClipboard *clip = QGuiApplication::clipboard();
    if (!clip)
        return false;
    clip->setText(text);
    return true;
}

// ===================== ACTIVE SESSIONS =====================

void FarmController::rebuildActiveSessions()
{
    QVariantList sessions;
    for (const auto &fh : m_farms) {
        if (!fh.thread)
            continue;
        QVariantMap s;
        s.insert(QStringLiteral("device"), fh.deviceId);
        s.insert(QStringLiteral("name"), logName(fh.deviceId, fh.accountName));
        s.insert(QStringLiteral("gemName"), fh.gemName);
        s.insert(QStringLiteral("running"), fh.thread->isRunning());
        s.insert(QStringLiteral("spawned"), fh.spawned);
        s.insert(QStringLiteral("deaths"), fh.deaths);
        s.insert(QStringLiteral("lastXp"), fh.lastXp);
        sessions.append(s);
    }
    m_activeSessions = sessions;
    emit activeSessionsChanged();
}

void FarmController::rebuildAggregate()
{
    double totalXp = 0;
    int totalDeaths = 0;
    bool anySpawned = false;
    for (const auto &fh : m_farms) {
        totalXp += fh.lastXp;
        totalDeaths += fh.deaths;
        if (fh.spawned)
            anySpawned = true;
    }
    bool changed = false;
    if (qAbs(totalXp - m_totalXpGained) > 0.001) {
        m_totalXpGained = totalXp;
        changed = true;
    }
    if (totalDeaths != m_deaths) {
        m_deaths = totalDeaths;
        changed = true;
    }
    if (anySpawned != m_spawned) {
        m_spawned = anySpawned;
        changed = true;
    }
    if (changed) {
        emit totalXpGainedChanged();
        emit xpTextChanged();
    }
}

// ===================== HELPERS =====================

FarmController::FarmHandle* FarmController::handleFor(FarmWorker *w)
{
    for (int i = 0; i < m_farms.size(); ++i)
        if (m_farms[i].worker == w)
            return &m_farms[i];
    return nullptr;
}

QString FarmController::shortDevice(const QString &d) const
{
    if (d.size() <= 16)
        return d;
    return d.left(12) + QStringLiteral("...");
}

QString FarmController::logName(const QString &device, const QString &knownName) const
{
    if (!knownName.isEmpty())
        return knownName;
    return shortDevice(device);
}
