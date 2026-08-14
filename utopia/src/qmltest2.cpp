#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QWindow>
#include <QQuickStyle>
#include <QTimer>
#include <QTextStream>
#include <QUrl>
#include "loginbridge.h"
int main(int argc, char *argv[]) {
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Utopia"));
    app.setOrganizationName(QStringLiteral("Utopia Labs"));
    QTextStream out(stdout);
    QString path = "D:/Users/andre/Downloads/MITOSIS FARMS/LABS/PG2/qw.sol";
    LoginBridge bridge;
    QObject::connect(&bridge, &LoginBridge::accountsChanged, [&]() {
        out << "ACCOUNTS count=" << bridge.accounts().size() << Qt::endl;
        for (const QVariant &v : bridge.accounts())
            out << "  " << v.toMap().value("name").toString()
                << " ok=" << v.toMap().value("ok").toBool()
                << " error=[" << v.toMap().value("error").toString() << "]"
                << Qt::endl;
        QTimer::singleShot(0, &app, &QCoreApplication::quit);
    });
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("loginBridge", &bridge);
    engine.load(QUrl("qrc:/Utopia/qml/Main.qml"));
    const auto roots = engine.rootObjects();
    if (!roots.isEmpty()) {
        if (auto *window = qobject_cast<QWindow *>(roots.constFirst())) {
            window->show();
            window->raise();
            window->requestActivate();
        }
    }
    out << "QML cargado: " << (engine.rootObjects().isEmpty() ? "FALLO" : "OK") << Qt::endl;
    QTimer::singleShot(2500, &bridge, [&]() { bridge.scanQW(path); });
    QTimer::singleShot(60000, &app, &QCoreApplication::quit);
    return app.exec();
}