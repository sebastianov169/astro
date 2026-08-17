// test_astro_parser.cpp - reproduce el parser de Astro con el qw.sol de PG2
#include <QCoreApplication>
#include <QFile>
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QUrl>
#include <cstdio>

// Copia exacta de extractAllDeviceIds de farm_controller.cpp (con el fix URL-decode)
QStringList extractAllDeviceIds(const QByteArray &data)
{
    QStringList out;
    int pos = 0;
    while ((pos = data.indexOf("deviceId", pos)) >= 0) {
        if (pos > 0 && data.at(pos - 1) == ':') {
            int pre = pos - 2;
            while (pre >= 0 && data.at(pre) >= '0' && data.at(pre) <= '9')
                --pre;
            if (pre >= 0 && data.at(pre) == 'y') {
                bool ok = false;
                const int keyLen = data.mid(pre + 1, pos - pre - 2).toInt(&ok);
                if (ok && keyLen >= 8) {
                    const int v = pos + keyLen;
                    if (v < data.size() && data.at(v) == 'y') {
                        int q = v + 1;
                        while (q < data.size() && data.at(q) >= '0' && data.at(q) <= '9')
                            ++q;
                        if (q < data.size() && data.at(q) == ':') {
                            const int len = data.mid(v + 1, q - v - 1).toInt(&ok);
                            if (ok && len > 0 && q + 1 + len <= data.size()) {
                                const QByteArray rawDev = data.mid(q + 1, len);
                                QString dev = QString::fromUtf8(rawDev);
                                if (dev.contains(QStringLiteral("%")))
                                    dev = QUrl::fromPercentEncoding(rawDev);
                                if (!dev.isEmpty() && !out.contains(dev))
                                    out.append(dev);
                                pos = q + 1 + len;
                                continue;
                            }
                        }
                    }
                }
            }
        }
        pos += 8;
    }
    return out;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    if (argc < 2) { printf("uso: test_astro_parser <qw.sol>\n"); return 1; }
    QFile f(QString::fromLocal8Bit(argv[1]));
    if (!f.open(QIODevice::ReadOnly)) { printf("no abre\n"); return 1; }
    const QByteArray data = f.readAll();
    f.close();
    printf("archivo: %d bytes\n", data.size());
    const QStringList devs = extractAllDeviceIds(data);
    printf("deviceIds encontrados: %d\n", devs.size());
    for (const QString &d : devs)
        printf("  -> %s\n", qPrintable(d.left(40)));
    return 0;
}
