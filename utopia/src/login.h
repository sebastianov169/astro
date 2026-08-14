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

    // Bloqueante. deviceId vacio -> lee MitosisOG/qw.sol.
    LoginResult login(const QString &deviceId);

    // PEM de atestacion (fake TPM) para el EH de ESTA cuenta/device. Si esta
    // vacia, login() usa el archivo embebido embedded_rsa_private_14.pem.
    void setAttestPem(const QString &pem);

    // Consulta el inventory de un slot. Devuelve las gemas.
    QVector<GemInfo> fetchInventory(int slot = 5);

    // updateexp (nivel + update)
    QJsonObject fetchUpdateExp();

    // Nombre real de la cuenta via loginifneeded (requiere login previo).
    // Cascada: data.username -> data.nickname -> data.userinfo.username ->
    // data.userinfo.nickname -> data.userinfo.display
    QString fetchAccountName();

    // Coins del ultimo fetchAccountName (data.userinfo.coins del loginifneeded)
    qlonglong lastCoins() const { return m_lastCoins; }

    // POST cifrado generico (do=craft, etc). Devuelve el payload descifrado.
    QByteArray postEncrypted(const QJsonObject &body);
    // POST cifrado a un host concreto (engine.php vs engine_beta.php).
    QByteArray postEncryptedHost(const QJsonObject &body, const QString &host);
    // Variante v5oh2 (AES-CBC + deriveAesKey(magic)).
    QByteArray postEncryptedV5oh2(const QJsonObject &body);
    // v5oh2 con clave explicita (deriveCustomAesKey(magic,100), etc).
    QByteArray postEncryptedV5oh2Key(const QJsonObject &body, const Bytes &key);

    // Id de la gema EQUIPADA del ultimo fetchInventory (data.current del server)
    int lastCurrentItem() const { return m_lastCurrentItem; }

private:
    QString m_sessionKey;
    QString m_magic;
    QString m_mainServer = "app.mitos.is";
    QString m_deviceId;
    QString m_accountName;
    QString m_attestPem; // PEM fake TPM para el EH (setAttestPem); vacio = embebida
    qlonglong m_lastCoins = 0;
    int m_lastCurrentItem = -1;
    QNetworkAccessManager m_net;
};
