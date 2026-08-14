#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QUrl>

#include "loginbridge.h"

int main(int argc, char *argv[])
{
    QGuiApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("Utopia"));
    app.setOrganizationName(QStringLiteral("Utopia Labs"));

    QQuickStyle::setStyle(QStringLiteral("Basic"));

    LoginBridge loginBridge;

    QQmlApplicationEngine engine;
    engine.rootContext()->setContextProperty("loginBridge", &loginBridge);
    const QUrl url(QStringLiteral("qrc:/Utopia/qml/Main.qml"));
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed,
                     &app, [](const QUrl &) { QCoreApplication::exit(-1); },
                     Qt::QueuedConnection);
    engine.load(url);

    return app.exec();
}
