// login.h - LoginManager: KNOCK/LIM/EH + API del login Mitos.is
#pragma once

#include <QObject>
#include <QString>
#include <functional>

#include <QNetworkAccessManager>

#include "crypto.h"

struct GemInfo {
    int id = 0;
    QString name;
    QString sprite;
    int itemLevel = 0;
    long long exp = 0;
    long long cexp = 0;
    int durability = 0;
    int maxDurability = 0;
    int price = 0;
    int sellPrice = 0;
    int category = 0;
};

// Item de la tienda (do:"store"). El id es el id del CATALOGO (el que usa
// do:"buy","item":<id>), distinto del id del inventario. Verificado contra el
// server real 2026-08-08: store category=10 -> 5 gemas (Azul 1000, Cian 1500,
// Blanca 1000, Marron 1500, Negra 1220) y buy item=<id> -> ok buy.
struct StoreItem {
    int id = 0;
    QString name;
    QString sprite;
    int level = 0;
    int price = 0;
    long long exp = 0;
    bool owned = false;
    bool purchasable = true;
    int category = 0;
    QVariantList attrs; // [["speed",4],["split",5],...]
};

struct LoginResult {
    bool ok = false;
    QString error;
    QString sessionKey;
    QString magic;
    QString deviceId;
    QString accountName;
};

class LoginManager : public QObject
{
    Q_OBJECT
public:
    explicit LoginManager(QObject *parent = nullptr);
    ~LoginManager() override;

    // Bloqueante. deviceId vacio -> lee MitosisOG/qw.sol.
    LoginResult login(const QString &deviceId);

    // PEM de atestacion (fake TPM) para el EH de ESTA cuenta/device. Cada
    // account/device usa SIEMPRE su propia clave (setAttestPem); si esta vacia,
    // login() falla con error en vez de caer a la clave embebida compartida.
    void setAttestPem(const QString &pem);

    // Consulta el inventory de un slot. Devuelve las gemas.
    QVector<GemInfo> fetchInventory(int slot = 5);

    // Consulta la tienda (do:"store"). category=10 -> gemas del catalogo con
    // precio de compra. Devuelve los items de la tienda (StoreItem).
    QVector<StoreItem> fetchStore(int category = 10);

    // Envia un body arbitrario con la sesion actual y devuelve el JSON
    // decodificado (mismo cifrado que fetchInventory). Usado por el Shop
    // ({"do":"buy","item":N}) y el probe --probe-shop.
    QJsonObject apiCall(const QString &bodyJson);

    // updateexp (nivel + update)
    QJsonObject fetchUpdateExp();

    // Nombre real de la cuenta via loginifneeded (requiere login previo).
    // Cascada: data.username -> data.nickname -> data.userinfo.username ->
    // data.userinfo.nickname -> data.userinfo.display
    QString fetchAccountName();

    // Coins del ultimo fetchAccountName (data.userinfo.coins del loginifneeded)
    qlonglong lastCoins() const { return m_lastCoins; }

    // Id de la gema EQUIPADA del ultimo fetchInventory (data.current del server)
    int lastCurrentItem() const { return m_lastCurrentItem; }

    // Sesion del login (sk/magic) para que el refresh full TCP la reutilice sin
    // volver a loguear (FarmWorker::setSession -> refreshXp, rama sameSession).
    QString sessionKey() const { return m_sessionKey; }
    QString magic() const { return m_magic; }

    // Refresh completo: FFA spawn -> HvZ -> inventory slot=5 -> updateexp -> CTF.
    // Devuelve la XP de la gema (cexp, exp) y el nivel. Sin TCP: solo HTTP API.
    struct RefreshResult {
        bool ok = false;
        qlonglong cexp = 0;
        qlonglong exp = 0;
        int lvl = 0;
        QString error;
    };
    QJsonObject doFullRefresh();

private:
    QString m_sessionKey;
    QString m_magic;
    QString m_mainServer = "app.mitos.is";
    QString m_deviceId;
    QString m_accountName;
    QString m_attestPem; // PEM fake TPM para el EH (setAttestPem); vacio = login falla
    qlonglong m_lastCoins = 0;
    int m_lastCurrentItem = -1;
    QNetworkAccessManager m_net;
};
