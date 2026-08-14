#include <QCoreApplication>
#include <QTextStream>
#include <QUrl>
#include <QFile>
#include "login.h"

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout);

    if (argc < 2) {
        out << "uso: logintest2 <qw.sol path>" << Qt::endl;
        return 1;
    }

    QFile f(QString::fromUtf8(argv[1]));
    if (!f.open(QIODevice::ReadOnly)) {
        out << "no puedo abrir el archivo" << Qt::endl;
        return 1;
    }
    QByteArray txt = f.readAll();
    int di = txt.indexOf("deviceIdy");
    if (di < 0) { out << "no deviceId" << Qt::endl; return 1; }
    QByteArray after = txt.mid(di + int(strlen("deviceIdy")));
    int c = after.indexOf(':');
    int n = after.left(c).toInt();
    QString dev = QUrl::fromPercentEncoding(after.mid(c + 1, n));
    out << "deviceId decodificado: " << dev << Qt::endl;

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