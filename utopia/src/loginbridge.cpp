// loginbridge.cpp - Bridge QML para el login HTTP de Mitos.is
#include "loginbridge.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTimer>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QDateTime>
#include <QStandardPaths>
#include <QtConcurrent>

#include <windows.h>
#include <cstring>

#include "crypto.h"

// ================================================================
// Catalogo de recetas del laboratorio (id real del server)
// ================================================================
static const LabRecipe kLabRecipes[] = {
    { 1,  "3x Mythical Speed Potion",       "Mythical Speed Potion",       43200 },
    { 2,  "3x Superior Portal Glue",        "Powerful Portal Glue",        14400 },
    { 3,  "3x Speed Shot",                  "Speed Shot",                  14400 },
    { 4,  "3x Speed Anticellular Shield",   "Speed Anticellular Shield",   14400 },
    { 5,  "3x Speed & Gravity Potion",      "Speed & Gravity Potion",      14400 },
    { 6,  "5x Thor's Chainsaw Hammer",      "Powerful Chainsaw",           14400 },
    { 7,  "3x Portal Shield Armor",         "Portal Shield Armor",         14400 },
    { 8,  "2x Legendary Speed Potion",      "Legendary Speed Potion",      21600 },
    { 9,  "2x Legendary Gravity Potion",    "Legendary Gravity Potion",    21600 },
    { 10, "2x Legendary Blink",             "Legendary Blink",             21600 },
    { 13, "3x Super Glue Potion",           "Super Glue Potion",           57600 },
    { 16, "3x Superior Portal Gun",         "Superior Portal Gun",         64800 },
    { 19, "3x Anticellular Armor",          "Anticellular Armor",          28800 },
    { 22, "3x Superior Blink",              "Superior Blink",              64800 },
    { 23, "5x Bubble Gun",                  "Bubble Gun",                  57600 },
    { 24, "3x Antiviral Portal Gun",        "Antiviral Portal Gun",        14400 },
    { 25, "3x Superior Immunity Shield",    "Superior Immunity Shield",    14400 },
    { 26, "3x Superior Gravity Blink",      "Superior Gravity Blink",      14400 },
};
static const int kLabRecipeCount = sizeof(kLabRecipes) / sizeof(kLabRecipes[0]);

// Ingredientes que requiere cada receta del lab: {shopId, cantidad}
// (capturados del JSON real del servidor: campo "ingredients")
// shopId=0 => el ingrediente es otra receta del lab (se craftea, no se compra)
struct LabIngredient { int shopId; int qty; };
static const QHash<int, QList<LabIngredient>> kLabIngredients = {
    // 1 Mythical Speed Potion: sin ingredientes (free)
    // 2 Powerful Portal Glue: 2x Super Glue + 4x Superior Portal Gun
    { 2,  { { 98, 2 }, { 274, 4 } } },
    // 3 Speed Shot: 3x Superior Petrifying Shoot + 3x Mythical
    { 3,  { { 156, 3 }, { 97, 3 } } },
    // 4 Speed Anticellular Shield: 3x Superior Petrifying Shoot + 3x Anticellular Armor
    { 4,  { { 156, 3 }, { 147, 3 } } },
    // 5 Speed & Gravity Potion: 2x Superior Petrifying Shoot + 4x Superior Gravity
    { 5,  { { 156, 2 }, { 101, 4 } } },
    // 6 Thor's Chainsaw Hammer: 2x Powerful Chainsaw + 3x Thor's Golden Hammer
    { 6,  { { 320, 2 }, { 213, 3 } } },
    // 7 Portal Shield Armor: 3x Anticellular Armor + 3x Superior Portal Gun
    { 7,  { { 147, 3 }, { 274, 3 } } },
    // 8 Legendary Speed Potion: 4x Mythical
    { 8,  { { 97, 4 } } },
    // 9 Legendary Gravity Potion: 4x Superior Gravity
    { 9,  { { 101, 4 } } },
    // 10 Legendary Blink: 4x Superior Blink
    { 10, { { 104, 4 } } },
    // 13 Super Glue Potion: sin ingredientes (free)
    // 16 Superior Portal Gun: sin ingredientes (free)
    // 19 Anticellular Armor: sin ingredientes (free)
    // 22 Superior Blink: sin ingredientes (free)
    // 23 Bubble Gun: sin ingredientes (free)
    // 24 Antiviral Portal Gun: 3x Superior Antiviral Shield + 3x Superior Portal Gun
    { 24, { { 145, 3 }, { 274, 3 } } },
    // 25 Superior Immunity Shield: 3x Anticellular Armor + 3x Superior Antiviral Shield
    { 25, { { 147, 3 }, { 145, 3 } } },
    // 26 Superior Gravity Blink: 3x Legendary Blink + 3x Legendary Gravity (lab-crafted)
    { 26, { { 0, 3 }, { 0, 3 } } },
};

// Traduce el nombre mostrado en la UI (o el nombre del server) al id del lab.
// Devuelve -1 si no existe.
static int labIdForName(const QString &name)
{
    for (int i = 0; i < kLabRecipeCount; ++i) {
        if (name == kLabRecipes[i].display || name == kLabRecipes[i].name)
            return kLabRecipes[i].id;
    }
    return -1;
}

// Cantidad de pociones que produce la receta (ej: "3x Super Glue Potion" -> 3,
// "5x Bubble Gun" -> 5, "2x Legendary Blink" -> 2). Devuelve 1 si no la encuentra.
static int recipeQtyForName(const QString &name)
{
    for (int i = 0; i < kLabRecipeCount; ++i) {
        if (name == kLabRecipes[i].display || name == kLabRecipes[i].name) {
            // el primer token del nombre es "3x" / "5x" / "2x"
            QString n = kLabRecipes[i].name;
            int x = n.indexOf('x');
            if (x > 0) {
                bool ok = false;
                int qty = n.left(x).trimmed().toInt(&ok);
                if (ok && qty > 0)
                    return qty;
            }
            return 1;
        }
    }
    return 1;
}

// Traduce el nombre de una receta del lab al id de compra en la tienda (do=buy item=<id>).
// Devuelve 0 si no hay item de tienda para esa receta.
static int shopIdForName(const QString &name)
{
    static const QHash<QString, int> shopIds = {
        { QStringLiteral("Mythical Speed Potion"), 97 },
        { QStringLiteral("Powerful Portal Glue"), 1654 },
        { QStringLiteral("Speed Shot"), 2013 },
        { QStringLiteral("Speed Anticellular Shield"), 148 },
        { QStringLiteral("Speed & Gravity Potion"), 101 },
        { QStringLiteral("Powerful Chainsaw"), 320 },
        { QStringLiteral("Portal Shield Armor"), 145 },
        { QStringLiteral("Legendary Speed Potion"), 1646 },
        { QStringLiteral("Legendary Gravity Potion"), 101 },
        { QStringLiteral("Legendary Blink"), 104 },
        { QStringLiteral("Super Glue Potion"), 98 },
        { QStringLiteral("Superior Portal Gun"), 274 },
        { QStringLiteral("Anticellular Armor"), 147 },
        { QStringLiteral("Superior Blink"), 104 },
        { QStringLiteral("Bubble Gun"), 1494 },
        { QStringLiteral("Antiviral Portal Gun"), 145 },
        { QStringLiteral("Superior Immunity Shield"), 145 },
        { QStringLiteral("Superior Gravity Blink"), 101 }
    };
    auto it = shopIds.constFind(name);
    return it != shopIds.constEnd() ? it.value() : 0;
}

// ================================================================
// LoginWorker
// ================================================================

// Lee el inventario de pociones de la cuenta: slot 3/4 del endpoint inventory.
// El campo "durability" es la cantidad real que posee la cuenta de cada poción.
// Devuelve id -> cantidad.
static QHash<int, int> fetchPotionStock(LoginManager &mgr)
{
    QHash<int, int> stock;
    for (int slot : {3, 4}) {
        QJsonObject body;
        body.insert("do", QStringLiteral("inventory"));
        body.insert("slot", slot);
        QByteArray resp = mgr.postEncrypted(body);
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(resp, &err);
        if (err.error != QJsonParseError::NoError || !doc.isObject())
            continue;
        QJsonArray items = doc.object().value("data").toObject().value("items").toArray();
        for (const QJsonValue &v : items) {
            QJsonObject o = v.toObject();
            int id = o.value("id").toInt();
            int qty = o.value("durability").toInt(0);
            if (id > 0 && qty > 0)
                stock[id] = qty;
        }
    }
    return stock;
}

// Lee el catálogo de la tienda (category=6) y devuelve el tamaño de pack
// ("multiple") de cada item: comprar 1 vez el item = <multiple> pociones.
static QHash<int, int> fetchStoreMultiples(LoginManager &mgr)
{
    QHash<int, int> multiples;
    QJsonObject body;
    body.insert("do", QStringLiteral("store"));
    body.insert("category", 6);
    QByteArray resp = mgr.postEncrypted(body);
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(resp, &err);
    if (err.error != QJsonParseError::NoError || !doc.isObject())
        return multiples;
    QJsonArray items = doc.object().value("data").toObject().value("items").toArray();
    for (const QJsonValue &v : items) {
        QJsonObject o = v.toObject();
        int id = o.value("id").toInt();
        int mult = o.value("multiple").toInt(0);
        if (id > 0 && mult > 0)
            multiples[id] = mult;
    }
    return multiples;
}

// Compra items en la tienda y devuelve (okCount, gasto estimado).
static int buyItems(LoginManager &mgr, const QList<int> &shopIds, int &spent)
{
    int ok = 0;
    for (int shopId : shopIds) {
        QJsonObject body;
        body.insert("do", QStringLiteral("buy"));
        body.insert("item", shopId);
        QByteArray resp = mgr.postEncrypted(body);
        QString t = QString::fromUtf8(resp);
        if (t.contains("\"result\":\"ok\"")) {
            ok++;
            // el server devuelve el nuevo saldo en data.coins; calculamos el gasto por diferencia
            QJsonParseError err;
            QJsonDocument doc = QJsonDocument::fromJson(t.toUtf8(), &err);
            if (err.error == QJsonParseError::NoError && doc.isObject()) {
                // se descuenta del balance: no lo sabemos aquí; el caller suma precios
            }
        }
    }
    return ok;
}

void LoginWorker::doLogin(const QString &deviceId, const QString &pemPath)
{
    // PEM de atestacion: si no existe el archivo, genera un par fake
    QString pem = pemPath;
    if (pem.isEmpty() || !QFile::exists(pem)) {
        QString genPem;
        if (generateRsaPem2048(&genPem)) {
            pem = genPem;
        } else {
            emit loginFinished(false, "Fake PEM generation failed", QString(), 0, deviceId);
            return;
        }
    } else {
        QFile f(pem);
        if (f.open(QIODevice::ReadOnly)) {
            pem = QString::fromUtf8(f.readAll());
        }
    }

    m_mgr.setAttestPem(pem);
    LoginResult r = m_mgr.login(deviceId);
    if (!r.ok) {
        emit loginFinished(false, r.error, QString(), 0, r.deviceId);
        return;
    }

    QString name = m_mgr.fetchAccountName();
    qlonglong coins = m_mgr.lastCoins();
    emit loginFinished(true, QString(), name, coins, r.deviceId);
}

void LoginWorker::doCraft(int slot, const QString &itemName)
{
    int id = labIdForName(itemName);
    if (id < 0) {
        emit craftFinished(false, "Recipe not found: " + itemName, -1, QVariantList());
        return;
    }

    // El endpoint real del lab: do=laboratory + cmd=craft + item=<id numerico>
    QJsonObject body;
    body.insert("do", QStringLiteral("laboratory"));
    body.insert("slot", slot);
    body.insert("cmd", QStringLiteral("craft"));
    body.insert("item", id);
    QByteArray resp = m_mgr.postEncrypted(body);
    QString t = QString::fromUtf8(resp);

    if (t.contains("\"result\":\"ok\"")) {
        QVariantList crafted;
        crafted.append(itemName);
        emit craftFinished(true, "Crafting " + itemName + " in slot " + QString::number(slot) + " (ok)", -1, crafted);
    } else {
        // extrae el mensaje del server (invalid_craft / invalid_slot / please_wait_30secs)
        QString msg = t;
        QRegularExpression re("\"message\":\"([^\"]+)\"");
        QRegularExpressionMatch m = re.match(t);
        if (m.hasMatch())
            msg = m.captured(1);
        emit craftFinished(false, "Craft failed: " + msg, -1, QVariantList());
    }
}

void LoginWorker::doCraftPlan(const QString &deviceId, const QVariantList &potionNames)
{
    if (potionNames.isEmpty()) {
        emit craftFinished(false, "Plan is empty", -1, QVariantList());
        return;
    }

    try {
        LoginManager mgr;
        QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
        if (QFile::exists(pemPath)) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly))
                mgr.setAttestPem(QString::fromUtf8(pf.readAll()));
        }

        LoginResult r = mgr.login(deviceId);
        if (!r.ok) {
            emit craftFinished(false, "Login failed: " + r.error.left(60), -1, QVariantList());
            return;
        }

        // estado actual del laboratorio: recoger pociones listas y slots libres (ready)
        QJsonObject labBody;
        labBody.insert("do", QStringLiteral("laboratory"));
        QByteArray labResp = mgr.postEncrypted(labBody);
        QVector<int> freeSlots;
        QStringList picked;
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(labResp, &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonArray arr = doc.object().value("data").toObject().value("slots").toArray();
            for (const QJsonValue &v : arr) {
                QJsonObject o = v.toObject();
                // slot con poción terminada (craft=ready): recogerla para liberarlo
                if (o.value("craft").toString() == "ready" && o.value("index").toInt(-1) >= 0) {
                    int slot = o.value("index").toInt(-1);
                    QJsonObject pickBody;
                    pickBody.insert("do", QStringLiteral("laboratory"));
                    pickBody.insert("slot", slot);
                    pickBody.insert("cmd", QStringLiteral("pick"));
                    QByteArray pickResp = mgr.postEncrypted(pickBody);
                    if (QString::fromUtf8(pickResp).contains("\"result\":\"ok\"")) {
                        picked << o.value("name").toString();
                        freeSlots.append(slot);
                    }
                } else if (o.value("status").toString() == "ready") {
                    freeSlots.append(o.value("index").toInt(-1));
                }
            }
        }

        QStringList okList, failList;
        int used = 0;
        for (int i = 0; i < potionNames.size(); ++i) {
            const QString name = potionNames.at(i).toString();
            int itemId = labIdForName(name);
            if (itemId < 0) {
                failList << name + " (unknown recipe)";
                continue;
            }
            if (used >= freeSlots.size()) {
                failList << name + " (no free slot)";
                continue;
            }
            int slot = freeSlots.at(used++);

            QJsonObject body;
            body.insert("do", QStringLiteral("laboratory"));
            body.insert("slot", slot);
            body.insert("cmd", QStringLiteral("craft"));
            body.insert("item", itemId);
            QByteArray resp = mgr.postEncrypted(body);
            QString t = QString::fromUtf8(resp);
            if (t.contains("\"result\":\"ok\"")) {
                okList << name;
            } else {
                QString msg = t;
                QRegularExpression re("\"message\":\"([^\"]+)\"");
                QRegularExpressionMatch m = re.match(t);
                if (m.hasMatch())
                    msg = m.captured(1);
                failList << name + " (" + msg + ")";
            }
        }

        QString msg = "Craft plan: " + QString::number(okList.size()) + " ok, " + QString::number(failList.size()) + " failed";
        if (!picked.isEmpty())
            msg += "\n  PICKED: " + picked.join(", ");
        if (!okList.isEmpty())
            msg += "\n  OK: " + okList.join(", ");
        if (!failList.isEmpty())
            msg += "\n  FAIL: " + failList.join(", ");
        QVariantList crafted;
        for (const QString &name : okList)
            crafted.append(name);
        emit craftFinished(okList.size() > 0, msg, -1, crafted);
    } catch (const std::exception &e) {
        emit craftFinished(false, QString("Craft plan exception: %1").arg(e.what()).left(120), -1, QVariantList());
    } catch (...) {
        emit craftFinished(false, QStringLiteral("Craft plan unknown exception"), -1, QVariantList());
    }
}

void LoginWorker::doAutobuy(const QString &deviceId, const QVariantList &itemIds)
{
    if (itemIds.isEmpty()) {
        emit craftFinished(false, "Autobuy: no items to buy", -1, QVariantList());
        return;
    }
    try {
        LoginManager mgr;
        QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
        if (QFile::exists(pemPath)) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly))
                mgr.setAttestPem(QString::fromUtf8(pf.readAll()));
        }
        LoginResult r = mgr.login(deviceId);
        if (!r.ok) {
            emit craftFinished(false, "Autobuy login failed: " + r.error.left(60), -1, QVariantList());
            return;
        }
        // captura el balance real antes de comprar/craftear
        mgr.fetchAccountName();

        // Resolver nombres de las pociones del plan (pueden venir como nombres o como ids)
        QStringList names;
        QList<int> labIds;
        for (const QVariant &v : itemIds) {
            if (v.metaType().id() == QMetaType::QString || v.canConvert<QString>()) {
                QString s = v.toString();
                int lab = labIdForName(s);
                if (lab < 0) { emit craftFinished(false, "Autobuy: unknown recipe: " + s, -1, QVariantList()); return; }
                names << s;
                labIds << lab;
            } else {
                int labId = v.toInt();
                if (labId <= 0) { emit craftFinished(false, "Autobuy: invalid recipe id", -1, QVariantList()); return; }
                names << QString::number(labId);
                labIds << labId;
            }
        }

        // Estado actual del laboratorio: recoger pociones listas y slots libres (ready)
        QJsonObject labBody;
        labBody.insert("do", QStringLiteral("laboratory"));
        QByteArray labResp = mgr.postEncrypted(labBody);
        QVector<int> freeSlots;
        QStringList picked;
        QJsonParseError err;
        QJsonDocument doc = QJsonDocument::fromJson(labResp, &err);
        if (err.error == QJsonParseError::NoError && doc.isObject()) {
            QJsonArray arr = doc.object().value("data").toObject().value("slots").toArray();
            for (const QJsonValue &v : arr) {
                QJsonObject o = v.toObject();
                // slot con poción terminada (craft=ready): recogerla para liberarlo
                if (o.value("craft").toString() == "ready" && o.value("index").toInt(-1) >= 0) {
                    int slot = o.value("index").toInt(-1);
                    QJsonObject pickBody;
                    pickBody.insert("do", QStringLiteral("laboratory"));
                    pickBody.insert("slot", slot);
                    pickBody.insert("cmd", QStringLiteral("pick"));
                    QByteArray pickResp = mgr.postEncrypted(pickBody);
                    if (QString::fromUtf8(pickResp).contains("\"result\":\"ok\"")) {
                        picked << o.value("name").toString();
                        freeSlots.append(slot);
                    }
                } else if (o.value("status").toString() == "ready") {
                    freeSlots.append(o.value("index").toInt(-1));
                }
            }
        }

        // Inventario real de pociones de la cuenta (id -> cantidad)
        QHash<int, int> stock = fetchPotionStock(mgr);

        // Tamaño de pack de la tienda por item (id -> multiple)
        QHash<int, int> multiples = fetchStoreMultiples(mgr);

        // Calcular que ingredientes faltan para todas las recetas del plan
        QHash<int, int> missing; // shopId -> cuantos faltan
        QStringList missingLabels;
        for (int labId : labIds) {
            auto it = kLabIngredients.constFind(labId);
            if (it == kLabIngredients.constEnd())
                continue; // receta sin ingredientes
            for (const LabIngredient &ing : it.value()) {
                if (ing.shopId <= 0)
                    continue; // ingrediente lab-only (se craftea aparte)
                int have = stock.value(ing.shopId, 0);
                if (have < ing.qty)
                    missing[ing.shopId] = missing.value(ing.shopId, 0) + (ing.qty - have);
            }
        }

        // Comprar solo los ingredientes que faltan, respetando el pack de la tienda
        // (1 compra = <multiple> pociones; comprar ceil(faltante/multiple) veces)
        QStringList buyOk, buyFail;
        int spent = 0;
        QList<int> missingIds = missing.keys();
        std::sort(missingIds.begin(), missingIds.end());
        for (int shopId : missingIds) {
            int need = missing.value(shopId);
            int mult = multiples.value(shopId, 1);
            int purchases = (need + mult - 1) / mult; // ceil
            int bought = 0;
            bool okAll = true;
            for (int i = 0; i < purchases; ++i) {
                QJsonObject body;
                body.insert("do", QStringLiteral("buy"));
                body.insert("item", shopId);
                QByteArray resp = mgr.postEncrypted(body);
                QString t = QString::fromUtf8(resp);
                if (t.contains("\"result\":\"ok\"")) {
                    bought += mult;
                    QJsonParseError perr;
                    QJsonDocument pdoc = QJsonDocument::fromJson(t.toUtf8(), &perr);
                    if (perr.error == QJsonParseError::NoError && pdoc.isObject()) {
                        int price = pdoc.object().value("data").toObject().value("price").toInt(0);
                        if (price > 0)
                            spent += price;
                    }
                } else {
                    okAll = false;
                    break;
                }
            }
            QString label = "item " + QString::number(shopId);
            // nombre del item desde el catalogo si lo tenemos
            for (int i = 0; i < kLabRecipeCount; ++i) {
                if (shopIdForName(QString(kLabRecipes[i].display)) == shopId) {
                    label = kLabRecipes[i].display;
                    break;
                }
            }
            if (okAll && bought > 0)
                buyOk << label + " x" + QString::number(bought);
            else
                buyFail << label + " x" + QString::number(need) + " (buy failed)";
        }
        QString buySummary = buyOk.join(", ");

        // Craftear las recetas del plan en los slots libres
        QStringList craftOk, craftFail;
        int used = 0;
        qlonglong coinsBefore = mgr.lastCoins();
        for (int i = 0; i < names.size(); ++i) {
            const QString name = names.at(i);
            if (used >= freeSlots.size()) {
                craftFail << name + " (no free slot)";
                continue;
            }
            int slot = freeSlots.at(used++);
            QJsonObject cbody;
            cbody.insert("do", QStringLiteral("laboratory"));
            cbody.insert("slot", slot);
            cbody.insert("cmd", QStringLiteral("craft"));
            cbody.insert("item", labIds.at(i));
            QByteArray resp = mgr.postEncrypted(cbody);
            QString t = QString::fromUtf8(resp);
            if (t.contains("\"result\":\"ok\"")) {
                craftOk << name;
            } else {
                QString msg = t;
                QRegularExpression re("\"message\":\"([^\"]+)\"");
                QRegularExpressionMatch m = re.match(t);
                if (m.hasMatch())
                    msg = m.captured(1);
                craftFail << name + " (" + msg + ")";
            }
        }
        // balance real al final (una llamada mas, fiable)
        mgr.fetchAccountName();
        qlonglong coinsAfter = mgr.lastCoins();

        QString msg = "Autobuy: " + QString::number(craftOk.size()) + " crafted, " + QString::number(craftFail.size()) + " failed";
        if (!picked.isEmpty())
            msg += "\n  PICKED: " + picked.join(", ");
        if (!buySummary.isEmpty())
            msg += "\n  BOUGHT: " + buySummary;
        if (!buyFail.isEmpty())
            msg += "\n  BUY FAIL: " + buyFail.join(", ");
        if (!craftOk.isEmpty())
            msg += "\n  CRAFTED: " + craftOk.join(", ");
        if (!craftFail.isEmpty())
            msg += "\n  FAIL: " + craftFail.join(", ");
        if (coinsBefore > 0 && coinsAfter > 0)
            msg += QString("\n  COINS: %1 -> %2 (-%3)").arg(coinsBefore).arg(coinsAfter).arg(coinsBefore - coinsAfter);
        QVariantList crafted;
        for (const QString &name : craftOk)
            crafted.append(name);
        emit craftFinished(craftOk.size() > 0, msg, coinsAfter, crafted);
    } catch (const std::exception &e) {
        emit craftFinished(false, QString("Autobuy exception: %1").arg(e.what()).left(120), -1, QVariantList());
    } catch (...) {
        emit craftFinished(false, QStringLiteral("Autobuy unknown exception"), -1, QVariantList());
    }
}

void LoginWorker::doBuyMany(const QVariantList &accountsInfo, int itemId, int packs)
{
    if (accountsInfo.isEmpty() || itemId <= 0) {
        emit buyManyFinished(false, "No accounts selected or invalid item", QVariantList());
        return;
    }
    if (packs < 1)
        packs = 1;
    try {
        QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
        QString pem;
        if (QFile::exists(pemPath)) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly))
                pem = QString::fromUtf8(pf.readAll());
        }

        QVariantList coinUpdates;
        QStringList okNames, failList;
        for (const QVariant &v : accountsInfo) {
            QVariantMap acc = v.toMap();
            QString name = acc.value("name").toString();
            QString deviceId = acc.value("deviceId").toString();
            int accIndex = acc.value("index").toInt();
            if (!acc.value("index").isValid())
                accIndex = -1;

            LoginManager mgr;
            if (!pem.isEmpty())
                mgr.setAttestPem(pem);
            LoginResult r = mgr.login(deviceId);
            if (!r.ok) {
                failList << name + " (login: " + r.error.left(30) + ")";
                continue;
            }
            int bought = 0;
            qlonglong coins = -1;
            QString itemName = QString::number(itemId);
            for (int p = 0; p < packs; ++p) {
                QJsonObject body;
                body.insert("do", QStringLiteral("buy"));
                body.insert("item", itemId);
                QByteArray resp = mgr.postEncrypted(body);
                QString t = QString::fromUtf8(resp);
                if (t.contains("\"result\":\"ok\"")) {
                    bought++;
                    QJsonParseError err;
                    QJsonDocument doc = QJsonDocument::fromJson(t.toUtf8(), &err);
                    if (err.error == QJsonParseError::NoError && doc.isObject()) {
                        QJsonObject d = doc.object().value("data").toObject();
                        itemName = d.value("name").toString();
                        coins = d.value("coins").toVariant().toLongLong();
                    }
                } else {
                    QString msg = t;
                    QRegularExpression re("\"message\":\"([^\"]+)\"");
                    QRegularExpressionMatch m = re.match(t);
                    if (m.hasMatch())
                        msg = m.captured(1);
                    failList << name + " (pack " + QString::number(p + 1) + ": " + msg + ")";
                    break;
                }
            }
            if (bought > 0 && coins < 0) {
                // Algunas respuestas de buy no incluyen data.coins; consulta
                // el balance real antes de notificar a Inventory y al header.
                mgr.fetchAccountName();
                coins = mgr.lastCoins();
            }
            if (bought > 0) {
                okNames << name + " (" + itemName + " x" + QString::number(bought) + ")";
                if (accIndex >= 0 && coins >= 0)
                    coinUpdates.append(QVariantMap{{"index", accIndex}, {"coins", coins}});
            }
        }

        QString msg = "Buy: " + QString::number(okNames.size()) + " ok, " + QString::number(failList.size()) + " failed";
        if (!okNames.isEmpty())
            msg += "\n  OK: " + okNames.join(", ");
        if (!failList.isEmpty())
            msg += "\n  FAIL: " + failList.join(", ");
        emit buyManyFinished(okNames.size() > 0, msg, coinUpdates);
    } catch (const std::exception &e) {
        emit buyManyFinished(false, QString("Buy exception: %1").arg(e.what()).left(120), QVariantList());
    } catch (...) {
        emit buyManyFinished(false, QStringLiteral("Buy unknown exception"), QVariantList());
    }
}

void LoginWorker::doFetchInventory()
{
    QVector<GemInfo> gems = m_mgr.fetchInventory(5);
    QVariantList items;
    for (const GemInfo &g : gems) {
        QVariantMap m;
        m.insert("id", g.id);
        m.insert("name", g.name);
        m.insert("sprite", g.sprite);
        m.insert("item_level", g.itemLevel);
        m.insert("exp", g.exp);
        m.insert("price", g.price);
        items.append(m);
    }
    emit inventoryFinished(items);
}

void LoginWorker::doFetchLaboratory()
{
    QJsonObject body;
    body.insert("do", QStringLiteral("laboratory"));
    QByteArray resp = m_mgr.postEncrypted(body);
    QString t = QString::fromUtf8(resp);

    QVariantList slotList;
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(t.toUtf8(), &err);
    if (err.error == QJsonParseError::NoError && doc.isObject()) {
        QJsonArray arr = doc.object().value("data").toObject().value("slots").toArray();
        for (const QJsonValue &v : arr) {
            QJsonObject o = v.toObject();
            QVariantMap s;
            s.insert("index", o.value("index").toInt(-1));
            s.insert("status", o.value("craft").toString() == "crafting" ? "crafting" : o.value("status").toString());
            s.insert("name", o.value("name").toString());
            s.insert("time", o.value("time").toInt(0));
            s.insert("qty", o.value("qty").toInt(0));
            s.insert("sprite", o.value("sprite").toString());
            s.insert("price", o.value("price").toInt(0));
            slotList.append(s);
        }
    }
    emit laboratoryFinished(slotList);
}

void LoginWorker::doScanAllLabs(const QVariantList &accountsInfo)
{
    QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
    QString pem;
    if (QFile::exists(pemPath)) {
        QFile pf(pemPath);
        if (pf.open(QIODevice::ReadOnly))
            pem = QString::fromUtf8(pf.readAll());
    }

    // Procesar cuentas SECUENCIALMENTE en el hilo del worker: el login necesita
    // su event loop (QtConcurrent rompe la red con err=99). Secuencial con
    // pausa corta evita el rate-limit de KNOCK del server.
    QVariantList result;
    auto scanAccount = [pem](const QVariant &v) {
        QVariantMap acc = v.toMap();
        QString name = acc.value("name").toString();
        QString deviceId = acc.value("deviceId").toString();

        QVariantMap entry;
        entry.insert("name", name);
        entry.insert("deviceId", deviceId);
        entry.insert("labMultiplier", qBound(1, acc.value("labMultiplier", 1).toInt(), 3));
        QVariantList slotArr;

        auto doScan = [&](LoginManager &mgr, QString *scanError) -> bool {
            QJsonObject body;
            body.insert("do", QStringLiteral("laboratory"));
            QByteArray resp = mgr.postEncrypted(body);
            QJsonParseError err;
            QJsonDocument doc = QJsonDocument::fromJson(resp, &err);
            if (err.error != QJsonParseError::NoError || !doc.isObject()) {
                if (scanError)
                    *scanError = resp.isEmpty() ? QStringLiteral("empty laboratory response") : QStringLiteral("invalid laboratory response");
                return false;
            }
            QJsonValue slotsValue = doc.object().value("data").toObject().value("slots");
            if (!slotsValue.isArray()) {
                if (scanError)
                    *scanError = QStringLiteral("laboratory response has no slots");
                return false;
            }
            QJsonArray arr = slotsValue.toArray();
            for (const QJsonValue &sv : arr) {
                QJsonObject o = sv.toObject();
                QVariantMap s;
                s.insert("index", o.value("index").toInt(-1));
                s.insert("status", o.value("craft").toString() == "crafting" ? "crafting" : o.value("status").toString());
                s.insert("name", o.value("name").toString());
                s.insert("time", o.value("time").toInt(0));
                s.insert("qty", o.value("qty").toInt(0));
                s.insert("price", o.value("price").toInt(0));
                slotArr.append(s);
            }
            return true;
        };

        try {
            LoginResult r;
            {
                LoginManager mgr;
                if (!pem.isEmpty())
                    mgr.setAttestPem(pem);
                // Reintento ligero: el server responde KNOCK vacio bajo ráfaga
                // (rate-limit). 1 reintento con espera corta; un backoff largo
                // dejaría la app bloqueada en busy durante minutos.
                for (int attempt = 0; attempt < 2; ++attempt) {
                    r = mgr.login(deviceId);
                    if (r.ok)
                        break;
                    QThread::msleep(300 + attempt * 900);
                }
                if (!r.ok) {
                    entry.insert("ok", false);
                    entry.insert("error", r.error.left(60));
                    return entry;
                }
                // captura coins reales (el login por si solo no los trae)
                QString realName = mgr.fetchAccountName();
                if (!realName.isEmpty())
                    entry.insert("name", realName);
                QString scanError;
                if (!doScan(mgr, &scanError)) {
                    entry.insert("ok", false);
                    entry.insert("error", scanError.left(60));
                    return entry;
                }
                entry.insert("ok", true);
                entry.insert("error", QString());
                entry.insert("slots", slotArr);
                entry.insert("coins", mgr.lastCoins());
            }
        } catch (const std::exception &e) {
            entry.insert("ok", false);
            entry.insert("error", QString("exception: %1").arg(e.what()).left(60));
        } catch (...) {
            entry.insert("ok", false);
            entry.insert("error", QStringLiteral("unknown exception"));
        }
        return entry;
    };

    // Cuentas en LOTES de 3 en paralelo: verificado en vivo (paratest) que
    // QtConcurrent + las DLLs correctas de Qt hacen el login sin err=99 y
    // sin rate-limit. 9 cuentas en ~6s vs ~35s secuencial con pausas.
    const int kBatch = 3;
    for (int i = 0; i < accountsInfo.size(); i += kBatch) {
        QVariantList batch;
        for (int j = i; j < accountsInfo.size() && j < i + kBatch; ++j)
            batch.append(accountsInfo.at(j));
        auto batchResults = QtConcurrent::blockingMapped(batch, scanAccount);
        for (const QVariant &r : batchResults) {
            result.append(r);
            // Mostrar cada cuenta en Account Labs en cuanto termina su scan;
            // esperar a las 9 cuentas hacía parecer que el botón no funcionaba.
            emit allLabsProgress(QVariantList{result.last()});
        }
    }

    bool anySuccess = false;
    for (const QVariant &value : result) {
        if (value.toMap().value("ok").toBool()) {
            anySuccess = true;
            break;
        }
    }
    emit allLabsFinished(anySuccess, anySuccess ? QString() : QStringLiteral("All laboratory scans failed"), result);
}

// Abre el chest diario del engine: do=news devuelve data.chest.id y ese id se
// pasa a do=openchest. Formato verificado en vivo (captura frida): 
//   REQ  {"do":"openchest","id":54331555}
//   RESP {"result":"ok","message":"openchest","data":{"rewards":[...],"coins":...}}
void LoginWorker::doOpenChest(const QString &deviceId)
{
    try {
        LoginManager mgr;
        QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
        if (QFile::exists(pemPath)) {
            QFile pf(pemPath);
            if (pf.open(QIODevice::ReadOnly))
                mgr.setAttestPem(QString::fromUtf8(pf.readAll()));
        }

        LoginResult r = mgr.login(deviceId);
        if (!r.ok) {
            emit chestFinished(false, "Login failed: " + r.error.left(60), -1, deviceId);
            return;
        }
        mgr.fetchAccountName();

        QJsonObject newsBody;
        newsBody.insert("do", QStringLiteral("news"));
        QByteArray newsResp = mgr.postEncrypted(newsBody);
        QJsonParseError err;
        QJsonDocument newsDoc = QJsonDocument::fromJson(newsResp, &err);
        int chestId = -1;
        if (err.error == QJsonParseError::NoError && newsDoc.isObject())
            chestId = newsDoc.object().value("data").toObject().value("chest").toObject().value("id").toInt(-1);
        if (chestId <= 0) {
            emit chestFinished(false, "No chest available (do=news has no chest.id)", -1, deviceId);
            return;
        }

        QJsonObject openBody;
        openBody.insert("do", QStringLiteral("openchest"));
        openBody.insert("id", chestId);
        QByteArray openResp = mgr.postEncrypted(openBody);
        QString t = QString::fromUtf8(openResp);
        QJsonDocument openDoc = QJsonDocument::fromJson(openResp, &err);
        if (err.error != QJsonParseError::NoError || !openDoc.isObject()) {
            emit chestFinished(false, "Open chest invalid response", -1, deviceId);
            return;
        }
        QJsonObject data = openDoc.object().value("data").toObject();
        QStringList rewards;
        QJsonArray rArr = data.value("rewards").toArray();
        for (const QJsonValue &rv : rArr) {
            QJsonObject rObj = rv.toObject();
            int amount = rObj.value("amount").toInt(0);
            QString title = rObj.value("title").toString();
            QString type = rObj.value("type").toString();
            if (title.isEmpty())
                title = type;
            rewards << (amount > 1 ? QString::number(amount) + "x " + title : title);
        }
        QString msg = "Chest " + QString::number(chestId) + " opened";
        if (!rewards.isEmpty())
            msg += ": " + rewards.join(", ");
        emit chestFinished(true, msg, data.value("coins").toVariant().toLongLong(), deviceId);
    } catch (const std::exception &e) {
        emit chestFinished(false, QString("Open chest exception: %1").arg(e.what()).left(120), -1, deviceId);
    } catch (...) {
        emit chestFinished(false, QStringLiteral("Open chest unknown exception"), -1, deviceId);
    }
}

// Abre el chest diario en N cuentas (lotes de 3 en paralelo, igual que el scan).
// Resultado por cuenta: {name, deviceId, ok, error, chestId, coins, rewards:[...]}
void LoginWorker::doOpenChestMany(const QVariantList &accountsInfo)
{
    QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
    QString pem;
    if (QFile::exists(pemPath)) {
        QFile pf(pemPath);
        if (pf.open(QIODevice::ReadOnly))
            pem = QString::fromUtf8(pf.readAll());
    }

    QVariantList result;
    auto openAccount = [pem](const QVariant &v) {
        QVariantMap acc = v.toMap();
        QString name = acc.value("name").toString();
        QString deviceId = acc.value("deviceId").toString();

        QVariantMap entry;
        entry.insert("name", name);
        entry.insert("deviceId", deviceId);

        try {
            LoginManager mgr;
            if (!pem.isEmpty())
                mgr.setAttestPem(pem);
            LoginResult r;
            // Reintento ligero contra el rate-limit del server (KNOCK vacio)
            for (int attempt = 0; attempt < 2; ++attempt) {
                r = mgr.login(deviceId);
                if (r.ok)
                    break;
                QThread::msleep(300 + attempt * 900);
            }
            if (!r.ok) {
                entry.insert("ok", false);
                entry.insert("error", r.error.left(60));
                return entry;
            }
            QString realName = mgr.fetchAccountName();
            if (!realName.isEmpty())
                entry.insert("name", realName);

            // 1) chest diario ya reclamado por el juego -> aparece en do=news
            QJsonObject newsBody;
            newsBody.insert("do", QStringLiteral("news"));
            QByteArray newsResp = mgr.postEncrypted(newsBody);
            QJsonParseError err;
            QJsonDocument newsDoc = QJsonDocument::fromJson(newsResp, &err);
            int chestId = -1;
            if (err.error == QJsonParseError::NoError && newsDoc.isObject())
                chestId = newsDoc.object().value("data").toObject().value("chest").toObject().value("id").toInt(-1);

            // 2) si no hay chest en news, reclamar el achievement del cofre
            //    (do=getreward con el id del achievement; verificado en vivo)
            if (chestId <= 0) {
                QJsonObject achBody;
                achBody.insert("do", QStringLiteral("achievements"));
                achBody.insert("user", QJsonValue::Null);
                QByteArray achResp = mgr.postEncrypted(achBody);
                QJsonDocument achDoc = QJsonDocument::fromJson(achResp, &err);
                if (err.error == QJsonParseError::NoError && achDoc.isObject()) {
                    QJsonArray list = achDoc.object().value("data").toObject().value("list").toArray();
                    int bestId = -1;
                    int bestIndex = -1;
                    for (const QJsonValue &v : list) {
                        QJsonObject a = v.toObject();
                        int cur = a.value("current").toInt();
                        int tot = a.value("total").toInt();
                        bool awarded = a.value("awarded").toBool();
                        int idx = a.value("index").toInt(-1);
                        if (cur < tot || awarded)
                            continue;
                        // chest diario (2297) y legendary diario (2295) del evento
                        if (idx == 2297 || idx == 2295) {
                            bestId = a.value("id").toInt();
                            bestIndex = idx;
                            break;
                        }
                    }
                    if (bestId > 0) {
                        QJsonObject grBody;
                        grBody.insert("do", QStringLiteral("getreward"));
                        grBody.insert("achievement", bestId);
                        QByteArray grResp = mgr.postEncrypted(grBody);
                        // tras reclamar, el chest aparece en news
                        newsResp = mgr.postEncrypted(newsBody);
                        QJsonDocument news2 = QJsonDocument::fromJson(newsResp, &err);
                        if (err.error == QJsonParseError::NoError && news2.isObject())
                            chestId = news2.object().value("data").toObject().value("chest").toObject().value("id").toInt(-1);
                        if (chestId <= 0) {
                            entry.insert("ok", false);
                            entry.insert("error", "getreward ok (idx " + QString::number(bestIndex) + ") but no chest appeared in news");
                            return entry;
                        }
                    }
                }
            }
            if (chestId <= 0) {
                entry.insert("ok", false);
                entry.insert("error", QStringLiteral("no chest available"));
                return entry;
            }

            QJsonObject openBody;
            openBody.insert("do", QStringLiteral("openchest"));
            openBody.insert("id", chestId);
            QByteArray openResp = mgr.postEncrypted(openBody);
            QJsonDocument openDoc = QJsonDocument::fromJson(openResp, &err);
            if (err.error != QJsonParseError::NoError || !openDoc.isObject()) {
                entry.insert("ok", false);
                entry.insert("error", QStringLiteral("invalid openchest response"));
                return entry;
            }
            QJsonObject data = openDoc.object().value("data").toObject();
            QVariantList rewards;
            QJsonArray rArr = data.value("rewards").toArray();
            for (const QJsonValue &rv : rArr) {
                QJsonObject rObj = rv.toObject();
                QVariantMap rm;
                rm.insert("type", rObj.value("type").toString());
                rm.insert("sprite", rObj.value("sprite").toString());
                rm.insert("amount", rObj.value("amount").toInt(0));
                rm.insert("title", rObj.value("title").toString());
                rewards.append(rm);
            }
            entry.insert("ok", true);
            entry.insert("error", QString());
            entry.insert("chestId", chestId);
            entry.insert("rewards", rewards);
            entry.insert("coins", data.value("coins").toVariant().toLongLong());
        } catch (const std::exception &e) {
            entry.insert("ok", false);
            entry.insert("error", QString("exception: %1").arg(e.what()).left(60));
        } catch (...) {
            entry.insert("ok", false);
            entry.insert("error", QStringLiteral("unknown exception"));
        }
        return entry;
    };

    // Cuentas en LOTES de 3 en paralelo (verificado: QtConcurrent funciona con
    // las DLLs correctas; 9 cuentas en ~6s). Sin pausa entre lotes.
    const int kBatch = 3;
    for (int i = 0; i < accountsInfo.size(); i += kBatch) {
        QVariantList batch;
        for (int j = i; j < accountsInfo.size() && j < i + kBatch; ++j)
            batch.append(accountsInfo.at(j));
        auto batchResults = QtConcurrent::blockingMapped(batch, openAccount);
        for (const QVariant &r : batchResults) {
            result.append(r);
            QVariantList partial;
            partial.append(r);
            emit chestManyProgress(partial);
        }
    }

    int opened = 0, failed = 0;
    for (const QVariant &value : result) {
        if (value.toMap().value("ok").toBool())
            opened++;
        else
            failed++;
    }
    QString msg = "Chests: " + QString::number(opened) + " opened, " + QString::number(failed) + " failed";
    emit chestManyFinished(opened > 0, msg, result);
}

// Parsea un valor de serializacion Haxe: busca la clave y devuelve el string
// que la sigue (formato y<N>:<value>). key ya incluye el sufijo "y".
static QString haxeValueAfter(const QByteArray &txt, const char *key, int *outPos = nullptr)
{
    int ki = txt.indexOf(key);
    if (ki < 0)
        return QString();
    QByteArray after = txt.mid(ki + int(strlen(key)));
    int c = after.indexOf(':');
    if (c <= 0)
        return QString();
    int n = after.left(c).toInt();
    if (n <= 0 || n > 200 || c + 1 + n > after.size())
        return QString();
    QByteArray raw = after.mid(c + 1, n);
    if (outPos)
        *outPos = ki;
    // deviceIds van URL-encoded; nombres de cuenta van en crudo
    return QUrl::fromPercentEncoding(raw);
}

void LoginWorker::doScanQW(const QString &qwPath)
{
    // qwPath es la ruta de UN archivo qw.sol elegido por el usuario
    if (!QFile::exists(qwPath)) {
        emit scanFinished(false, "File not found: " + qwPath, QVariantList());
        return;
    }

    QFile f(qwPath);
    if (!f.open(QIODevice::ReadOnly)) {
        emit scanFinished(false, "Cannot read " + qwPath, QVariantList());
        return;
    }
    QByteArray txt = f.readAll();

    // --- parsear qw.sol (serializacion Haxe): puede contener UNA o VARIAS cuentas.
    // Cada cuenta = un deviceId + su user_account_N. El archivo de farm trae
    // deviceId, deviceId4..9, deviceIdSecondary, deviceIdthird, deviceIdfourth.
    QList<QPair<QString, QString>> entries; // (nombre, deviceId)

    // deviceId "principal" (user_account_0)
    QString dev0 = haxeValueAfter(txt, "deviceIdy");
    QString name0 = haxeValueAfter(txt, "user_account_0y");
    if (!dev0.isEmpty())
        entries.append({name0.isEmpty() ? QStringLiteral("account_0") : name0, dev0});

    // deviceId4..deviceId9 (user_account_4..9)
    for (int i = 4; i <= 9; ++i) {
        QString key = QString("deviceId%1y").arg(i);
        QString dev = haxeValueAfter(txt, key.toUtf8().constData());
        if (dev.isEmpty())
            continue;
        QString ua = QString("user_account_%1y").arg(i);
        QString name = haxeValueAfter(txt, ua.toUtf8().constData());
        entries.append({name.isEmpty() ? QString("account_%1").arg(i) : name, dev});
    }

    // deviceIdSecondary (user_account_1), deviceIdthird (2), deviceIdfourth (3)
    struct { const char *devKey; int accountIdx; } extra[] = {
        {"deviceIdSecondaryy", 1},
        {"deviceIdthirdy", 2},
        {"deviceIdfourthy", 3},
    };
    for (const auto &e : extra) {
        QString dev = haxeValueAfter(txt, e.devKey);
        if (dev.isEmpty())
            continue;
        QString ua = QString("user_account_%1y").arg(e.accountIdx);
        QString name = haxeValueAfter(txt, ua.toUtf8().constData());
        entries.append({name.isEmpty() ? QString("account_%1").arg(e.accountIdx) : name, dev});
    }

    if (entries.isEmpty()) {
        emit scanFinished(false, "No deviceId found in " + qwPath, QVariantList());
        return;
    }

    QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
    QString pem;
    if (QFile::exists(pemPath)) {
        QFile pf(pemPath);
        if (pf.open(QIODevice::ReadOnly))
            pem = QString::fromUtf8(pf.readAll());
    }

    QVariantList results;
    for (const auto &entry : entries) {
        QString account = entry.first;
        QString deviceId = entry.second;

        try {
            LoginManager mgr;
            if (!pem.isEmpty())
                mgr.setAttestPem(pem);

            LoginResult r = mgr.login(deviceId);
            if (!r.ok) {
                QFile logf(QCoreApplication::applicationDirPath() + "/scan_debug.log");
                if (logf.open(QIODevice::Append)) {
                    QTextStream ts(&logf);
                    ts << QDateTime::currentDateTime().toString("HH:mm:ss")
                       << " account=" << account
                       << " deviceId=" << deviceId.left(20)
                       << " error=[" << r.error << "]"
                       << Qt::endl;
                }
                results.append(QVariantMap{
                    {"name", account}, {"deviceId", deviceId},
                    {"ok", false}, {"error", r.error.left(60)},
                    {"coins", 0}, {"labSlots", 0}, {"lockedSlots", 0},
                });
                continue;
            }

            QString realName = mgr.fetchAccountName();
            if (!realName.isEmpty())
                account = realName;
            qlonglong coins = mgr.lastCoins();

            // slots del laboratorio: cuenta cuantos no estan locked
            QJsonObject body;
            body.insert("do", QStringLiteral("laboratory"));
            QByteArray resp = mgr.postEncrypted(body);
            int labSlots = 0, lockedSlots = 0;
            QJsonParseError err;
            QJsonDocument doc = QJsonDocument::fromJson(resp, &err);
            if (err.error == QJsonParseError::NoError && doc.isObject()) {
                QJsonArray arr = doc.object().value("data").toObject().value("slots").toArray();
                for (const QJsonValue &v : arr) {
                    if (v.toObject().value("status").toString() == "locked")
                        lockedSlots++;
                    else
                        labSlots++;
                }
            }

            results.append(QVariantMap{
                {"name", account}, {"deviceId", deviceId},
                {"ok", true}, {"error", QString()},
                {"coins", coins}, {"labSlots", labSlots}, {"lockedSlots", lockedSlots},
            });
        } catch (const std::exception &e) {
            results.append(QVariantMap{
                {"name", account}, {"deviceId", deviceId},
                {"ok", false}, {"error", QString("exception: %1").arg(e.what()).left(60)},
                {"coins", 0}, {"labSlots", 0}, {"lockedSlots", 0},
            });
        } catch (...) {
            results.append(QVariantMap{
                {"name", account}, {"deviceId", deviceId},
                {"ok", false}, {"error", QStringLiteral("unknown exception")},
                {"coins", 0}, {"labSlots", 0}, {"lockedSlots", 0},
            });
        }
    }

    bool anySuccess = false;
    for (const QVariant &value : results) {
        if (value.toMap().value("ok").toBool()) {
            anySuccess = true;
            break;
        }
    }
    emit scanFinished(anySuccess,
                      anySuccess ? QString() : QStringLiteral("No QW account could be logged in"),
                      results);
}

// ================================================================
// LoginBridge
// ================================================================
LoginBridge::LoginBridge(QObject *parent) : QObject(parent)
{
    m_worker = new LoginWorker;
    m_worker->moveToThread(&m_thread);

    connect(&m_thread, &QThread::finished, m_worker, &QObject::deleteLater);
    connect(this, &LoginBridge::loginRequested, m_worker, &LoginWorker::doLogin);
    connect(this, &LoginBridge::craftRequested, m_worker, &LoginWorker::doCraft);
    connect(this, &LoginBridge::craftPlanRequested, m_worker, &LoginWorker::doCraftPlan);
    connect(this, &LoginBridge::autobuyRequested, m_worker, &LoginWorker::doAutobuy);
    connect(this, &LoginBridge::buyManyRequested, m_worker, &LoginWorker::doBuyMany);
    connect(this, &LoginBridge::inventoryRequested, m_worker, &LoginWorker::doFetchInventory);
    connect(this, &LoginBridge::laboratoryRequested, m_worker, &LoginWorker::doFetchLaboratory);
    connect(this, &LoginBridge::allLabsRequested, m_worker, &LoginWorker::doScanAllLabs);
    connect(this, &LoginBridge::scanRequested, m_worker, &LoginWorker::doScanQW);
    connect(this, &LoginBridge::chestRequested, m_worker, &LoginWorker::doOpenChest);
    connect(this, &LoginBridge::chestManyRequested, m_worker, &LoginWorker::doOpenChestMany);

    connect(m_worker, &LoginWorker::loginFinished,
            this, &LoginBridge::onLoginFinished);
    connect(m_worker, &LoginWorker::craftFinished,
            this, &LoginBridge::onCraftFinished);
    connect(m_worker, &LoginWorker::inventoryFinished,
            this, &LoginBridge::onInventoryFinished);
    connect(m_worker, &LoginWorker::laboratoryFinished,
            this, &LoginBridge::onLaboratoryFinished);
    connect(m_worker, &LoginWorker::allLabsProgress,
            this, &LoginBridge::onAllLabsProgress);
    connect(m_worker, &LoginWorker::allLabsFinished,
            this, &LoginBridge::onAllLabsFinished);
    connect(m_worker, &LoginWorker::buyManyFinished,
            this, &LoginBridge::onBuyManyFinished);
    connect(m_worker, &LoginWorker::scanFinished,
            this, &LoginBridge::onScanFinished);
    connect(m_worker, &LoginWorker::chestFinished,
            this, &LoginBridge::onChestFinished);
    connect(m_worker, &LoginWorker::chestManyProgress,
            this, &LoginBridge::onChestManyProgress);
    connect(m_worker, &LoginWorker::chestManyFinished,
            this, &LoginBridge::onChestManyFinished);

    m_craftRefreshTimer.setSingleShot(true);
    m_craftRefreshTimer.setInterval(4000);
    connect(&m_craftRefreshTimer, &QTimer::timeout,
            this, &LoginBridge::onCraftRefreshDebounce);

    m_thread.start();
    m_recipes = buildRecipes();
    loadAccounts();
}

LoginBridge::~LoginBridge()
{
    m_thread.quit();
    m_thread.wait();
}

QVariantList LoginBridge::buildRecipes()
{
    QVariantList list;
    for (int i = 0; i < kLabRecipeCount; ++i) {
        QVariantMap m;
        m.insert("id", kLabRecipes[i].id);
        m.insert("name", kLabRecipes[i].display);
        m.insert("serverName", kLabRecipes[i].name);
        m.insert("seconds", kLabRecipes[i].seconds);
        list.append(m);
    }
    return list;
}

void LoginBridge::login(const QString &deviceId)
{
    if (m_busy) return;
    setBusy(true);
    m_status = "Logging in...";
    emit statusChanged();

    // Busca la PEM fake en el directorio de la app o genera una
    QString pemPath = QCoreApplication::applicationDirPath() + "/embedded_rsa_private_14.pem";
    emit loginRequested(deviceId, pemPath);
}

void LoginBridge::craft(int slot, const QString &itemName)
{
    if (m_busy || !m_loggedIn) {
        m_status = "Login required before crafting";
        emit statusChanged();
        return;
    }
    setBusy(true);
    m_status = "Crafting " + itemName + " in slot " + QString::number(slot) + "...";
    emit statusChanged();
    emit craftRequested(slot, itemName);
}

void LoginBridge::craftPlan(int accountIndex, const QVariantList &potionNames)
{
    if (m_busy) {
        m_status = "Busy...";
        emit statusChanged();
        return;
    }
    if (accountIndex < 0 || accountIndex >= m_accounts.size()) {
        m_status = "Select a QW account first";
        emit statusChanged();
        return;
    }
    const QString deviceId = m_accounts.at(accountIndex).toMap().value("deviceId").toString();
    if (deviceId.isEmpty()) {
        m_status = "Account has no deviceId";
        emit statusChanged();
        return;
    }
    m_lastActionDeviceId = deviceId;
    setBusy(true);
    m_status = "Crafting plan on " + m_accounts.at(accountIndex).toMap().value("name").toString() + "...";
    emit statusChanged();
    emit craftPlanRequested(deviceId, potionNames);
}

void LoginBridge::autobuy(int accountIndex, const QVariantList &itemIds)
{
    if (m_busy) {
        m_status = "Busy...";
        emit statusChanged();
        return;
    }
    if (accountIndex < 0 || accountIndex >= m_accounts.size()) {
        m_status = "Select a QW account first";
        emit statusChanged();
        return;
    }
    const QString deviceId = m_accounts.at(accountIndex).toMap().value("deviceId").toString();
    if (deviceId.isEmpty()) {
        m_status = "Account has no deviceId";
        emit statusChanged();
        return;
    }
    m_lastActionDeviceId = deviceId;
    setBusy(true);
    m_status = "Autobuy on " + m_accounts.at(accountIndex).toMap().value("name").toString() + "...";
    emit statusChanged();
    emit autobuyRequested(deviceId, itemIds);
}

void LoginBridge::buyOnAccounts(const QVariantList &accountIndexes, int itemId, int packs)
{
    if (m_busy) {
        m_status = "Busy...";
        emit statusChanged();
        return;
    }
    QVariantList accountsInfo;
    for (const QVariant &v : accountIndexes) {
        int idx = v.toInt();
        if (idx < 0 || idx >= m_accounts.size())
            continue;
        QVariantMap acc = m_accounts.at(idx).toMap();
        acc.insert("index", idx);
        accountsInfo.append(acc);
    }
    if (accountsInfo.isEmpty()) {
        m_status = "Select at least one QW account";
        emit statusChanged();
        return;
    }
    setBusy(true);
    m_status = QString("Buying %1 pack(s) on %2 accounts...").arg(packs).arg(accountsInfo.size());
    emit statusChanged();
    emit buyManyRequested(accountsInfo, itemId, packs);
}

void LoginBridge::refreshInventory()
{
    if (m_busy || !m_loggedIn) return;
    setBusy(true);
    emit inventoryRequested();
}

void LoginBridge::refreshLaboratory()
{
    if (m_busy || !m_loggedIn) return;
    setBusy(true);
    emit laboratoryRequested();
}

void LoginBridge::scanAllLabs()
{
    if (m_busy) {
        m_status = "Busy...";
        emit statusChanged();
        return;
    }
    if (m_accounts.isEmpty()) {
        m_status = "No QW accounts loaded";
        emit statusChanged();
        return;
    }
    setBusy(true);
    m_status = QString("Scanning labs of %1 accounts...").arg(m_accounts.size());
    emit statusChanged();
    emit allLabsRequested(m_accounts);
}

void LoginBridge::onLoginFinished(bool ok, const QString &error, const QString &name,
                                  qlonglong coins, const QString &deviceId)
{
    m_loggedIn = ok;
    m_accountName = name;
    m_coins = coins;
    m_loggedDeviceId = ok ? deviceId : QString();
    if (ok)
        m_lastActionDeviceId = deviceId;
    m_status = ok ? "Logged in as " + name
                  : "Login failed: " + error.left(80);
    setBusy(false);
    emit loggedInChanged();
    emit accountNameChanged();
    emit coinsChanged();
    emit statusChanged();
    if (ok)
        refreshInventory();
}

void LoginBridge::appendLogEntry(bool ok, const QString &message)
{
    QString stamp = QDateTime::currentDateTime().toString("HH:mm:ss");
    QString entry = QString("[%1] %2 %3").arg(stamp).arg(ok ? "OK" : "ERR").arg(message);
    m_logText = entry + "\n" + m_logText;
    if (m_logText.size() > 8000)
        m_logText = m_logText.left(8000);
    emit logTextChanged();

    // Persistir a %APPDATA%\Utopia Labs\autobuy.log
    QString dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (dir.isEmpty())
        dir = QDir::homePath() + "/.utopia";
    QDir().mkpath(dir);
    QFile logf(dir + "/autobuy.log");
    if (logf.open(QIODevice::Append | QIODevice::Text)) {
        logf.write((entry + "\n").toUtf8());
        logf.close();
    }
}

void LoginBridge::appendCraftHistory(const QVariantList &crafted)
{
    if (crafted.isEmpty() || m_lastActionDeviceId.isEmpty())
        return;

    for (int accountIndex = 0; accountIndex < m_accounts.size(); ++accountIndex) {
        QVariantMap account = m_accounts.at(accountIndex).toMap();
        if (account.value("deviceId").toString() != m_lastActionDeviceId)
            continue;

        int total = account.value("craftCount").toInt();
        QVariantList history = account.value("craftHistory").toList();
        for (const QVariant &craftedValue : crafted) {
            const QString potionName = craftedValue.toString();
            if (potionName.isEmpty())
                continue;
            // cantidad real de pociones que produce la receta (3x/5x/2x)
            int qty = recipeQtyForName(potionName);
            if (qty < 1)
                qty = 1;
            // A lab boost multiplies the output of one recipe craft. Keep
            // history in real potion units, not just number of craft actions.
            const int multiplier = qBound(1, account.value("labMultiplier", 1).toInt(), 3);
            qty *= multiplier;

            bool found = false;
            for (int historyIndex = 0; historyIndex < history.size(); ++historyIndex) {
                QVariantMap entry = history.at(historyIndex).toMap();
                if (entry.value("name").toString() != potionName)
                    continue;
                entry.insert("count", entry.value("count").toInt() + qty);
                entry.insert("crafts", entry.value("crafts").toInt() + 1);
                entry.insert("qty", qty);
                history[historyIndex] = entry;
                found = true;
                break;
            }
            if (!found)
                history.append(QVariantMap{{"name", potionName}, {"count", qty}, {"crafts", 1}, {"qty", qty}});
            total += qty;
        }

        account.insert("craftCount", total);
        account.insert("craftHistory", history);
        account.insert("lastCraftAt", QDateTime::currentDateTime().toString(Qt::ISODate));
        m_accounts[accountIndex] = account;
        saveAccounts();
        emit accountsChanged();
        return;
    }
}

void LoginBridge::onCraftFinished(bool ok, const QString &message, qlonglong coins,
                                  const QVariantList &crafted)
{
    m_status = message;
    setBusy(false);
    emit statusChanged();
    appendLogEntry(ok, message);
    if (ok && !crafted.isEmpty())
        appendCraftHistory(crafted);
    if (ok) {
        // Refresh post-craft con DEBOUNCE: escanear tras cada craft en ráfaga
        // saturaba al server (login+lab por craft = decenas de requests).
        // Se agrupa el refresh: 4s tras el ultimo craft, solo si no hay otra
        // operacion en curso.
        m_craftRefreshTarget = m_lastActionDeviceId;
        if (!m_craftRefreshTimer.isActive())
            m_craftRefreshTimer.start(4000);
    }

    // actualizar el balance real de la cuenta que ejecuto la accion
    if (coins >= 0 && !m_lastActionDeviceId.isEmpty()) {
        for (QVariant &av : m_accounts) {
            QVariantMap a = av.toMap();
            if (a.value("deviceId").toString() == m_lastActionDeviceId) {
                if (a.value("coins").toLongLong() != coins) {
                    a.insert("coins", coins);
                    av = a;
                    saveAccounts();
                    emit accountsChanged();
                }
                if (a.value("deviceId").toString() == m_loggedDeviceId && m_coins != coins) {
                    m_coins = coins;
                    emit coinsChanged();
                }
                break;
            }
        }
    }
    m_lastActionDeviceId.clear();
}

void LoginBridge::onInventoryFinished(const QVariantList &items)
{
    m_inventory = items;
    setBusy(false);
    emit inventoryChanged();
    emit statusChanged();
}

void LoginBridge::onLaboratoryFinished(const QVariantList &slotList)
{
    m_labSlots = slotList;
    setBusy(false);
    emit labSlotsChanged();
    emit statusChanged();
}

void LoginBridge::onAllLabsProgress(const QVariantList &accountsLab)
{
    if (accountsLab.isEmpty())
        return;

    QVariantList merged = m_allLabs;
    for (const QVariant &incoming : accountsLab) {
        const QString deviceId = incoming.toMap().value("deviceId").toString();
        bool replaced = false;
        for (int i = 0; i < merged.size(); ++i) {
            if (merged.at(i).toMap().value("deviceId").toString() == deviceId) {
                merged[i] = incoming;
                replaced = true;
                break;
            }
        }
        if (!replaced)
            merged.append(incoming);
    }
    m_allLabs = merged;
    emit allLabsChanged();
}

void LoginBridge::onAllLabsFinished(bool ok, const QString &error, const QVariantList &accountsLab)
{
    if (ok) {
        int scanOk = 0, scanFail = 0;
        QStringList failWho;
        for (const QVariant &v : accountsLab) {
            QVariantMap m = v.toMap();
            if (m.value("ok").toBool())
                scanOk++;
            else {
                scanFail++;
                failWho << m.value("name").toString() + ": " + m.value("error").toString().left(40);
            }
        }
        appendLogEntry(scanFail == 0, QString("Labs scan: %1 ok, %2 failed").arg(scanOk).arg(scanFail)
                       + (failWho.isEmpty() ? QString() : " (" + failWho.join(" | ") + ")"));
        // A craft refresh can target one account. Merge partial results so a
        // single-account refresh never makes the other labs disappear from UI.
        if (accountsLab.size() < m_accounts.size() && !m_allLabs.isEmpty()) {
            QVariantList merged = m_allLabs;
            for (const QVariant &incoming : accountsLab) {
                const QString deviceId = incoming.toMap().value("deviceId").toString();
                bool replaced = false;
                for (int i = 0; i < merged.size(); ++i) {
                    if (merged.at(i).toMap().value("deviceId").toString() == deviceId) {
                        merged[i] = incoming;
                        replaced = true;
                        break;
                    }
                }
                if (!replaced)
                    merged.append(incoming);
            }
            m_allLabs = merged;
        } else {
            m_allLabs = accountsLab;
        }
        int crafting = 0;
        bool coinsUpdated = false;
        for (const QVariant &v : accountsLab) {
            QVariantMap labEntry = v.toMap();
            // sincronizar coins reales en m_accounts y persistir
            for (QVariant &av : m_accounts) {
                QVariantMap a = av.toMap();
                if (a.value("deviceId").toString() == labEntry.value("deviceId").toString()) {
                    if (labEntry.contains("coins") && labEntry.value("coins").toLongLong() >= 0
                        && a.value("coins").toLongLong() != labEntry.value("coins").toLongLong()) {
                        a.insert("coins", labEntry.value("coins"));
                        av = a;
                        coinsUpdated = true;
                    }
                    if (a.value("deviceId").toString() == m_loggedDeviceId
                        && labEntry.contains("coins")
                        && labEntry.value("coins").toLongLong() >= 0
                        && m_coins != labEntry.value("coins").toLongLong()) {
                        m_coins = labEntry.value("coins").toLongLong();
                        emit coinsChanged();
                    }
                    break;
                }
            }
            for (const QVariant &sv : labEntry.value("slots").toList()) {
                if (sv.toMap().value("status").toString() == "crafting")
                    crafting++;
            }
        }
        if (coinsUpdated)
            saveAccounts();
        m_status = QString("Labs scanned: %1 accounts, %2 crafting").arg(accountsLab.size()).arg(crafting);
        emit accountsChanged();
        emit allLabsChanged();
    } else {
        m_status = "Labs scan failed: " + error.left(80);
        if (!accountsLab.isEmpty()) {
            m_allLabs = accountsLab;
            emit allLabsChanged();
        }
    }
    setBusy(false);
    emit statusChanged();
}

void LoginBridge::onBuyManyFinished(bool ok, const QString &message, const QVariantList &accountCoins)
{
    // actualiza las coins de cada cuenta comprada y guarda
    bool updated = false;
    for (const QVariant &v : accountCoins) {
        QVariantMap upd = v.toMap();
        int idx = upd.value("index").toInt();
        qlonglong coins = upd.value("coins").toLongLong();
        if (idx < 0 || idx >= m_accounts.size() || coins < 0)
            continue;
        QVariantMap acc = m_accounts.at(idx).toMap();
        acc.insert("coins", coins);
        m_accounts[idx] = acc;
        if (acc.value("deviceId").toString() == m_loggedDeviceId && m_coins != coins) {
            m_coins = coins;
            emit coinsChanged();
        }
        updated = true;
    }
    if (updated) {
        saveAccounts();
        emit accountsChanged();
    }
    m_status = message;
    setBusy(false);
    emit statusChanged();

    // Shop y Inventory deben reflejar la misma operación. Si la cuenta
    // comprada es la sesión activa, vuelve a pedir su inventario real para
    // actualizar cantidades, stock y coins aunque la respuesta de compra
    // haya omitido algún campo.
    if (updated && m_loggedIn)
        refreshInventory();
}

void LoginBridge::scanQW(const QString &qwPath)
{
    if (m_busy) return;
    setBusy(true);
    m_status = "Adding QW account: " + QFileInfo(qwPath).fileName();
    emit statusChanged();
    emit scanRequested(qwPath);
}

void LoginBridge::chooseQwFile()
{
#ifdef Q_OS_WIN
    // Dialogo nativo de Windows para elegir el archivo qw.sol
    wchar_t filename[MAX_PATH] = L"";
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = GetActiveWindow();
    ofn.lpstrFilter = L"qw.sol files (*.sol)\0*.sol\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = filename;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY | OFN_NOCHANGEDIR;
    ofn.lpstrTitle = L"Select qw.sol account";
    if (GetOpenFileNameW(&ofn)) {
        QString path = QString::fromWCharArray(filename);
        m_status = "Adding QW account: " + QFileInfo(path).fileName();
        setBusy(true);
        emit statusChanged();
        emit scanRequested(path);
    }
#endif
}

// Abre el chest diario de la cuenta (index en m_accounts): consulta do=news
// para obtener chest.id y ejecuta do=openchest con ese id.
void LoginBridge::openChest(int accountIndex)
{
    if (m_busy) return;
    if (accountIndex < 0 || accountIndex >= m_accounts.size()) {
        m_status = "Open chest: invalid account index";
        emit statusChanged();
        return;
    }
    QString deviceId = m_accounts.at(accountIndex).toMap().value("deviceId").toString();
    if (deviceId.isEmpty()) {
        m_status = "Open chest: account has no deviceId";
        emit statusChanged();
        return;
    }
    setBusy(true);
    m_status = "Opening chest (" + m_accounts.at(accountIndex).toMap().value("name").toString() + ")...";
    m_lastActionDeviceId = deviceId;
    emit statusChanged();
    emit chestRequested(deviceId);
}

// Abre el chest diario en varias cuentas a la vez (lotes paralelos en el worker).
void LoginBridge::openChestOnAccounts(const QVariantList &accountIndexes)
{
    if (m_busy) return;
    QVariantList infos;
    for (const QVariant &iv : accountIndexes) {
        int idx = iv.toInt();
        if (idx < 0 || idx >= m_accounts.size())
            continue;
        QVariantMap acc = m_accounts.at(idx).toMap();
        infos.append(QVariantMap{{"name", acc.value("name")}, {"deviceId", acc.value("deviceId")}});
    }
    if (infos.isEmpty()) {
        m_status = "Open chest: no accounts selected";
        emit statusChanged();
        return;
    }
    setBusy(true);
    m_chestResults.clear();
    emit chestResultsChanged();
    m_status = "Opening chests on " + QString::number(infos.size()) + " account(s)...";
    emit statusChanged();
    emit chestManyRequested(infos);
}

void LoginBridge::onChestManyProgress(const QVariantList &results)
{
    for (const QVariant &value : results)
        m_chestResults.append(value);

    m_status = QString("Opening chests: %1 account(s) processed...")
                   .arg(m_chestResults.size());
    emit statusChanged();
    emit chestResultsChanged();
}

void LoginBridge::onChestManyFinished(bool ok, const QString &message, const QVariantList &results)
{
    m_status = message;
    setBusy(false);
    emit statusChanged();
    appendLogEntry(ok, message);
    bool coinsUpdated = false;
    // detalle por cuenta + sincronizar coins reales (la respuesta de openchest
    // trae el balance actual de cada cuenta)
    for (const QVariant &rv : results) {
        QVariantMap r = rv.toMap();
        QString who = r.value("name").toString() + " (" + r.value("deviceId").toString().left(8) + ")";
        if (r.value("ok").toBool()) {
            QStringList rewards;
            for (const QVariant &wv : r.value("rewards").toList()) {
                QVariantMap w = wv.toMap();
                int amount = w.value("amount").toInt(0);
                QString title = w.value("title").toString();
                rewards << (amount > 1 ? QString::number(amount) + "x " + title : title);
            }
            appendLogEntry(true, "Chest " + who + ": " + (rewards.isEmpty() ? "empty" : rewards.join(", ")));

            // coins de la cuenta tras abrir el chest -> m_accounts + persistir
            QString deviceId = r.value("deviceId").toString();
            qlonglong newCoins = r.value("coins").toLongLong();
            if (!deviceId.isEmpty() && newCoins >= 0) {
                for (QVariant &av : m_accounts) {
                    QVariantMap a = av.toMap();
                    if (a.value("deviceId").toString() == deviceId) {
                        if (a.value("coins").toLongLong() != newCoins) {
                            a.insert("coins", newCoins);
                            av = a;
                            coinsUpdated = true;
                        }
                        if (deviceId == m_loggedDeviceId && m_coins != newCoins) {
                            m_coins = newCoins;
                            emit coinsChanged();
                        }
                        break;
                    }
                }
            }
        } else {
            appendLogEntry(false, "Chest " + who + ": " + r.value("error").toString());
        }
    }
    if (coinsUpdated)
        saveAccounts();
    if (coinsUpdated)
        emit accountsChanged();
    m_chestResults = results;
    emit chestResultsChanged();
}

void LoginBridge::onChestFinished(bool ok, const QString &message, qlonglong coins,
                                  const QString &deviceId)
{
    m_status = message;
    setBusy(false);
    emit statusChanged();
    appendLogEntry(ok, message);
    if (ok && coins >= 0)
        m_coins = coins;
    emit coinsChanged();
    // refrescar el scan de la cuenta que abrio el chest (cambio de inventario)
    if (ok && !deviceId.isEmpty()) {
        for (const QVariant &v : m_accounts) {
            if (v.toMap().value("deviceId").toString() == deviceId) {
                setBusy(true);
                emit allLabsRequested(QVariantList{v});
                break;
            }
        }
    }
}

void LoginBridge::onScanFinished(bool ok, const QString &error, const QVariantList &accounts)
{
    if (ok && !accounts.isEmpty()) {
        // anade las cuentas nuevas a la lista existente (evita duplicados por deviceId)
        QVariantList merged = m_accounts;
        for (const QVariant &v : accounts) {
            const QString dev = v.toMap().value("deviceId").toString();
            bool found = false;
            for (QVariant &existing : merged) {
                if (existing.toMap().value("deviceId").toString() == dev) {
                    // la cuenta ya existe: actualizar coins/labSlots pero NUNCA
                    // perder la asignacion de plan ni el historial de crafting.
                    QVariantMap e = existing.toMap();
                    QVariantMap incoming = v.toMap();
                    if (incoming.contains("coins") && incoming.value("coins").toLongLong() >= 0)
                        e.insert("coins", incoming.value("coins"));
                    e.insert("labSlots", incoming.value("labSlots"));
                    e.insert("lockedSlots", incoming.value("lockedSlots"));
                    if (incoming.contains("ok"))
                        e.insert("ok", incoming.value("ok"));
                    if (incoming.contains("name") && !incoming.value("name").toString().isEmpty())
                        e.insert("name", incoming.value("name"));
                    existing = e;
                    found = true;
                    break;
                }
            }
            if (!found)
                merged.append(v);
        }
        m_accounts = merged;
        saveAccounts();
        m_status = QString("%1 QW accounts loaded").arg(m_accounts.size());
        emit accountsChanged();
        // Una cuenta recién añadida debe aparecer también en Account Labs sin
        // obligar al usuario a pulsar SCAN LABS manualmente.
        setBusy(false);
        scanAllLabs();
        return;
    } else {
        m_status = "QW add failed: " + error.left(80);
    }
    setBusy(false);
    emit statusChanged();
}

// ================================================================
// Persistencia de cuentas y planes
// ================================================================
static QString accountsFilePath()
{
    QString dir = qEnvironmentVariable("APPDATA") + "/Utopia Labs";
    QDir().mkpath(dir);
    return dir + "/accounts.json";
}

QVariantList LoginBridge::loadAccounts()
{
    QFile f(accountsFilePath());
    if (!f.open(QIODevice::ReadOnly))
        return m_accounts;
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (err.error != QJsonParseError::NoError || !doc.isArray())
        return m_accounts;
    m_accounts = doc.array().toVariantList();
    bool historyMigrated = false;
    for (QVariant &accountValue : m_accounts) {
        QVariantMap account = accountValue.toMap();
        QVariantList history = account.value("craftHistory").toList();
        if (history.isEmpty())
            continue;

        QVariantList normalized;
        int totalCrafted = 0;
        for (const QVariant &historyValue : history) {
            QVariantMap entry = historyValue.toMap();
            const QString name = entry.value("name").toString();
            const int baseQty = recipeQtyForName(name);

            // Solo normalizar recetas conocidas. Los posibles eventos de
            // versiones futuras se conservan tal como llegaron.
            if (labIdForName(name) < 0 || baseQty <= 0) {
                normalized.append(entry);
                totalCrafted += entry.value("count").toInt();
                continue;
            }

            const bool hasQty = entry.contains("qty");
            int crafts = entry.value("crafts").toInt();
            if (crafts < 1)
                crafts = hasQty ? 1 : qMax(1, entry.value("count").toInt());

            int perCraft = entry.value("qty").toInt();
            if (!hasQty || perCraft < 1) {
                perCraft = baseQty;
            } else {
                // Corregir cantidades imposibles como 8 Super Glue: una
                // receta solo puede producir base, base*2 o base*3.
                int multiplier = qBound(1, (perCraft + baseQty / 2) / baseQty, 3);
                perCraft = baseQty * multiplier;
            }

            const int correctedCount = perCraft * crafts;
            if (entry.value("count").toInt() != correctedCount
                || entry.value("qty").toInt() != perCraft
                || entry.value("crafts").toInt() != crafts) {
                historyMigrated = true;
            }
            entry.insert("count", correctedCount);
            entry.insert("qty", perCraft);
            entry.insert("crafts", crafts);
            normalized.append(entry);
            totalCrafted += correctedCount;
        }

        if (account.value("craftCount").toInt() != totalCrafted) {
            account.insert("craftCount", totalCrafted);
            historyMigrated = true;
        }
        account.insert("craftHistory", normalized);
        accountValue = account;
    }
    if (historyMigrated)
        saveAccounts();
    emit accountsChanged();
    return m_accounts;
}

bool LoginBridge::saveAccounts()
{
    QFile f(accountsFilePath());
    if (!f.open(QIODevice::WriteOnly))
        return false;
    QJsonDocument doc(QJsonArray::fromVariantList(m_accounts));
    f.write(doc.toJson(QJsonDocument::Indented));
    return true;
}

static QString plansFilePath()
{
    QString dir = qEnvironmentVariable("APPDATA") + "/Utopia Labs";
    QDir().mkpath(dir);
    return dir + "/plans.json";
}

void LoginBridge::savePlans(const QVariantList &plans)
{
    QFile f(plansFilePath());
    if (!f.open(QIODevice::WriteOnly))
        return;
    QJsonDocument doc(QJsonArray::fromVariantList(plans));
    f.write(doc.toJson(QJsonDocument::Indented));
}

QVariantList LoginBridge::loadPlans()
{
    QVariantList plans;
    QFile f(plansFilePath());
    if (!f.open(QIODevice::ReadOnly))
        return plans;
    QJsonParseError err;
    QJsonDocument doc = QJsonDocument::fromJson(f.readAll(), &err);
    if (err.error == QJsonParseError::NoError && doc.isArray())
        plans = doc.array().toVariantList();
    return plans;
}

void LoginBridge::removeAccount(const QString &deviceId)
{
    QVariantList merged;
    for (const QVariant &v : m_accounts) {
        if (v.toMap().value("deviceId").toString() != deviceId)
            merged.append(v);
    }
    m_accounts = merged;
    saveAccounts();
    m_status = QString("%1 QW accounts loaded").arg(m_accounts.size());
    emit accountsChanged();
    emit statusChanged();
}

void LoginBridge::removeAccountAt(int index)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    m_accounts.removeAt(index);
    saveAccounts();
    m_status = QString("%1 QW accounts loaded").arg(m_accounts.size());
    emit accountsChanged();
    emit statusChanged();
}

void LoginBridge::setAccountPlan(int index, const QString &planName)
{
    if (index < 0 || index >= m_accounts.size())
        return;
    QVariantMap acc = m_accounts.at(index).toMap();
    acc.insert("plan", planName);
    m_accounts[index] = acc;
    saveAccounts();
    emit accountsChanged();
}

// Debug: escribe al autobuy.log (para diagnosticar el loop desde QML)
void LoginBridge::logDebug(const QString &msg)
{
    appendLogEntry(true, msg);
}

// Debounce del refresh post-craft: agrupa los scans de 1 cuenta que se
// disparaban tras cada craft (ráfaga de logins que saturaba al server).
void LoginBridge::onCraftRefreshDebounce()
{
    m_craftRefreshTimer.stop();
    if (m_busy)
        return;
    QString target = m_craftRefreshTarget;
    m_craftRefreshTarget.clear();
    if (target.isEmpty())
        return;
    for (const QVariant &v : m_accounts) {
        if (v.toMap().value("deviceId").toString() == target) {
            setBusy(true);
            emit allLabsRequested(QVariantList{v});
            break;
        }
    }
}

void LoginBridge::setAccountLabMultiplier(int index, int multiplier)
{
    if (index < 0 || index >= m_accounts.size())
        return;

    multiplier = qBound(1, multiplier, 3);
    QVariantMap account = m_accounts.at(index).toMap();
    if (account.value("labMultiplier", 1).toInt() == multiplier)
        return;

    account.insert("labMultiplier", multiplier);
    m_accounts[index] = account;
    saveAccounts();
    emit accountsChanged();
    emit allLabsChanged();
}
