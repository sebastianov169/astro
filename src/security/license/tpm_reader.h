#pragma once

#include "license_structure.h"

#include <QObject>
#include <QString>
#include <QByteArray>
#include <windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <iphlpapi.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wbemuuid.lib")

namespace astro {
namespace license {

class TpmReader : public QObject {
    Q_OBJECT

public:
    explicit TpmReader(QObject* parent = nullptr);
    ~TpmReader() override;

    HardwareFingerprint readFingerprint();

    static bool isDebuggerAttached();

private:
    bool readTpmInfo(QString& manufacturer, QString& serial);
    bool readMotherboardSerial(QString& serial);
    bool readMacAddressHash(QString& hash);
    bool computeHwidHash(const QString& rawComponents, QString& outHash);
    bool sha256(const QByteArray& input, QByteArray& output);
    bool readMachineGuid(QString& guid);
    bool readCpuId(QString& cpuId);
    bool readDiskSerial(QString& serial);

    QString xorObfuscate(const QString& input, uint8_t key) const;
};

} // namespace license
} // namespace astro
