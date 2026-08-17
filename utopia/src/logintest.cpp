#include <QCoreApplication>
#include <QTextStream>
#include "login.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);

    if (argc < 2) {
        out << "uso: logintest <deviceId>" << Qt::endl;
        return 1;
    }
    QString dev = QString::fromUtf8(argv[1]);

    LoginManager lm;
    LoginResult r = lm.login(dev);
    if (!r.ok) {
        out << "LOGIN FAILED: [" << r.error << "]" << Qt::endl;
        return 1;
    }
    out << "LOGIN OK" << Qt::endl;
    QString name = lm.fetchAccountName();
    out << "NAME: " << name << " COINS: " << lm.lastCoins() << Qt::endl;
    return 0;
}