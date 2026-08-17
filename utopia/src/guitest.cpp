#include <QGuiApplication>
#include <QTimer>
#include <QTextStream>
#include "loginbridge.h"
int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    QTextStream out(stdout);
    QString path = "D:/Users/andre/Downloads/MITOSIS FARMS/LABS/PG2/qw.sol";
    LoginBridge bridge;
    QObject::connect(&bridge, &LoginBridge::accountsChanged, [&]() {
        out << "ACCOUNTS CHANGED count=" << bridge.accounts().size() << Qt::endl;
        for (const QVariant &v : bridge.accounts())
            out << "  " << v.toMap().value("name").toString()
                << " ok=" << v.toMap().value("ok").toBool()
                << " error=[" << v.toMap().value("error").toString() << "]"
                << Qt::endl;
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    });
    out << "scanQW..." << Qt::endl;
    bridge.scanQW(path);
    QTimer::singleShot(60000, &app, &QCoreApplication::quit);
    return app.exec();
}
