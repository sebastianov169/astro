#include <QCoreApplication>
#include <QTimer>
#include <QTextStream>
#include "loginbridge.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);

    if (argc < 2) {
        out << "uso: bridgetest <qw.sol path>" << Qt::endl;
        return 1;
    }
    QString path = QString::fromUtf8(argv[1]);

    LoginBridge bridge;
    QObject::connect(&bridge, &LoginBridge::accountsChanged, [&]() {
        out << "ACCOUNTS CHANGED, count=" << bridge.accounts().size() << Qt::endl;
        for (const QVariant &v : bridge.accounts()) {
            QVariantMap m = v.toMap();
            out << "  name=" << m.value("name").toString()
                << " ok=" << m.value("ok").toBool()
                << " coins=" << m.value("coins").toLongLong()
                << " labSlots=" << m.value("labSlots").toInt()
                << " locked=" << m.value("lockedSlots").toInt()
                << " error=[" << m.value("error").toString() << "]"
                << Qt::endl;
        }
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    });
    QObject::connect(&bridge, &LoginBridge::statusChanged, [&]() {
        out << "STATUS: " << bridge.status() << Qt::endl;
    });

    out << "scanQW: " << path << Qt::endl;
    bridge.scanQW(path);

    QTimer::singleShot(60000, &app, &QCoreApplication::quit);
    return app.exec();
}