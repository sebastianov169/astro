#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QTimer>
#include <QTextStream>
#include "loginbridge.h"
int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    QTextStream out(stdout);
    QString path = "D:/Users/andre/Downloads/MITOSIS FARMS/LABS/PG2/qw.sol";
    LoginBridge bridge;
    QObject::connect(&bridge, &LoginBridge::accountsChanged, [&]() {
        out << "ACCOUNTS count=" << bridge.accounts().size() << Qt::endl;
        for (const QVariant &v : bridge.accounts())
            out << "  " << v.toMap().value("name").toString()
                << " ok=" << v.toMap().value("ok").toBool()
                << Qt::endl;
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    });
    QQmlApplicationEngine engine;
    engine.loadFromModule("Utopia", "Main");
    out << "QML loaded" << Qt::endl;
    QTimer::singleShot(2000, &bridge, [&]() { bridge.scanQW(path); });
    QTimer::singleShot(60000, &app, &QCoreApplication::quit);
    return app.exec();
}
