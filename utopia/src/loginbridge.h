// loginbridge.h - Bridge QML para el login HTTP de Mitos.is (KNOCK/LIM/EH)
#pragma once

#include <QObject>
#include <QThread>
#include <QTimer>
#include <QJsonObject>
#include <QVariantList>
#include "login.h"

struct LabRecipe {
    int id = 0;
    QString name;       // nombre real devuelto por el server (lab)
    QString display;    // nombre amigable para la UI (QML)
    int seconds = 0;    // duracion del craft
};

// Worker que ejecuta las operaciones bloqueantes en un hilo aparte
class LoginWorker : public QObject
{
    Q_OBJECT
public:
    explicit LoginWorker(QObject *parent = nullptr) : QObject(parent) {}

public slots:
    void doLogin(const QString &deviceId, const QString &pemPath);
    void doCraft(int slot, const QString &itemName);
    void doCraftPlan(const QString &deviceId, const QVariantList &potionNames);
    void doAutobuy(const QString &deviceId, const QVariantList &itemIds);
    void doBuyMany(const QVariantList &accountsInfo, int itemId, int packs);
    void doFetchInventory();
    void doFetchLaboratory();
    void doScanAllLabs(const QVariantList &accountsInfo);
    void doScanQW(const QString &qwPath);
    void doOpenChest(const QString &deviceId);
    void doOpenChestMany(const QVariantList &accountsInfo);

signals:
    void loginFinished(bool ok, const QString &error, const QString &name,
                       qlonglong coins, const QString &deviceId);
    void craftFinished(bool ok, const QString &message, qlonglong coins = -1,
                       const QVariantList &crafted = QVariantList());
    void chestFinished(bool ok, const QString &message, qlonglong coins = -1,
                       const QString &deviceId = QString());
    void chestManyProgress(const QVariantList &results);
    void chestManyFinished(bool ok, const QString &message, const QVariantList &results);
    void buyManyFinished(bool ok, const QString &message, const QVariantList &accountCoins);
    void inventoryFinished(const QVariantList &items);
    void laboratoryFinished(const QVariantList &slotList);
    void allLabsProgress(const QVariantList &accountsLab);
    void allLabsFinished(bool ok, const QString &error, const QVariantList &accountsLab);
    void scanFinished(bool ok, const QString &error, const QVariantList &accounts);

private:
    LoginManager m_mgr;
};

class LoginBridge : public QObject
{
    Q_OBJECT
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(bool loggedIn READ loggedIn NOTIFY loggedInChanged)
    Q_PROPERTY(QString status READ status NOTIFY statusChanged)
    Q_PROPERTY(QString accountName READ accountName NOTIFY accountNameChanged)
    Q_PROPERTY(qlonglong coins READ coins NOTIFY coinsChanged)
    Q_PROPERTY(QVariantList inventory READ inventory NOTIFY inventoryChanged)
    Q_PROPERTY(QVariantList labSlots READ labSlots NOTIFY labSlotsChanged)
    Q_PROPERTY(QVariantList recipes READ recipes CONSTANT)
    Q_PROPERTY(QVariantList accounts READ accounts NOTIFY accountsChanged)
    Q_PROPERTY(QVariantList allLabs READ allLabs NOTIFY allLabsChanged)
    Q_PROPERTY(QVariantList chestResults READ chestResults NOTIFY chestResultsChanged)
    Q_PROPERTY(QString logText READ logText NOTIFY logTextChanged)

public:
    explicit LoginBridge(QObject *parent = nullptr);
    ~LoginBridge() override;

    bool busy() const { return m_busy; }
    bool loggedIn() const { return m_loggedIn; }
    QString status() const { return m_status; }
    QString accountName() const { return m_accountName; }
    qlonglong coins() const { return m_coins; }
    QVariantList inventory() const { return m_inventory; }
    QVariantList labSlots() const { return m_labSlots; }
    QVariantList recipes() const { return m_recipes; }
    QString logText() const { return m_logText; }
    QVariantList accounts() const { return m_accounts; }
    QVariantList allLabs() const { return m_allLabs; }
    QVariantList chestResults() const { return m_chestResults; }

    // PEM fake: se genera con generateRsaPem2048 si no existe el archivo
    Q_INVOKABLE void login(const QString &deviceId = QString());
    Q_INVOKABLE void craft(int slot, const QString &itemName);
    Q_INVOKABLE void craftPlan(int accountIndex, const QVariantList &potionNames);
    Q_INVOKABLE void autobuy(int accountIndex, const QVariantList &itemIds);
    Q_INVOKABLE void buyOnAccounts(const QVariantList &accountIndexes, int itemId, int packs = 1);
    Q_INVOKABLE void refreshInventory();
    Q_INVOKABLE void refreshLaboratory();
    Q_INVOKABLE void scanAllLabs();
    Q_INVOKABLE void scanQW(const QString &qwPath);
    Q_INVOKABLE void chooseQwFile();
    Q_INVOKABLE void openChest(int accountIndex);
    Q_INVOKABLE void openChestOnAccounts(const QVariantList &accountIndexes);
    Q_INVOKABLE void removeAccount(const QString &deviceId);
    Q_INVOKABLE void removeAccountAt(int index);
    Q_INVOKABLE void setAccountPlan(int index, const QString &planName);
    Q_INVOKABLE void logDebug(const QString &msg);
    Q_INVOKABLE void setAccountLabMultiplier(int index, int multiplier);
    Q_INVOKABLE QVariantList loadAccounts();
    Q_INVOKABLE bool saveAccounts();
    Q_INVOKABLE void savePlans(const QVariantList &plans);
    Q_INVOKABLE QVariantList loadPlans();

signals:
    void busyChanged();
    void loggedInChanged();
    void statusChanged();
    void accountNameChanged();
    void coinsChanged();
    void inventoryChanged();
    void labSlotsChanged();
    void allLabsChanged();
    void accountsChanged();
    void logTextChanged();
    void chestResultsChanged();

    void loginRequested(const QString &deviceId, const QString &pemPath);
    void craftRequested(int slot, const QString &itemName);
    void craftPlanRequested(const QString &deviceId, const QVariantList &potionNames);
    void autobuyRequested(const QString &deviceId, const QVariantList &itemIds);
    void buyManyRequested(const QVariantList &accountsInfo, int itemId, int packs);
    void inventoryRequested();
    void laboratoryRequested();
    void allLabsRequested(const QVariantList &accountsInfo);
    void scanRequested(const QString &qwDir);
    void chestRequested(const QString &deviceId);
    void chestManyRequested(const QVariantList &accountsInfo);

private slots:
    void onLoginFinished(bool ok, const QString &error, const QString &name,
                         qlonglong coins, const QString &deviceId);
    void onCraftFinished(bool ok, const QString &message, qlonglong coins = -1,
                         const QVariantList &crafted = QVariantList());
    void onInventoryFinished(const QVariantList &items);
    void onLaboratoryFinished(const QVariantList &slotList);
    void onAllLabsFinished(bool ok, const QString &error, const QVariantList &accountsLab);
    void onAllLabsProgress(const QVariantList &accountsLab);
    void onBuyManyFinished(bool ok, const QString &message, const QVariantList &accountCoins);
    void onScanFinished(bool ok, const QString &error, const QVariantList &accounts);
    void onChestFinished(bool ok, const QString &message, qlonglong coins,
                         const QString &deviceId);
    void onChestManyFinished(bool ok, const QString &message, const QVariantList &results);
    void onChestManyProgress(const QVariantList &results);
    void onCraftRefreshDebounce();

private:
    void setBusy(bool b) { if (m_busy != b) { m_busy = b; emit busyChanged(); } }
    QVariantList buildRecipes();
    void appendCraftHistory(const QVariantList &crafted);

    QThread m_thread;
    LoginWorker *m_worker = nullptr;
    bool m_busy = false;
    bool m_loggedIn = false;
    QString m_status = "Idle";
    QString m_accountName;
    QString m_loggedDeviceId;
    qlonglong m_coins = 0;
    QVariantList m_inventory;
    QVariantList m_labSlots;
    QVariantList m_allLabs;
    QVariantList m_chestResults;
    QTimer m_craftRefreshTimer;
    QString m_craftRefreshTarget;
    QVariantList m_recipes;
    QVariantList m_accounts;
    QString m_logText;
    QString m_lastActionDeviceId;
    void appendLogEntry(bool ok, const QString &message);
};
