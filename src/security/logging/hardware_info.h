#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <Windows.h>
#include <QString>
#include <QJsonObject>
#include <QByteArray>
#include <QList>
#include <winternl.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace astro {
namespace security {

struct HardwareComponent {
    QString wmiClass;
    QString property;
    QString value;
};

struct SystemFingerprint {
    QString baseboardManufacturer;
    QString baseboardSerial;
    QString processorName;
    quint32 processorCores;
    quint32 processorSpeedMHz;
    QString systemManufacturer;
    QString systemModel;
    quint64 totalRAMBytes;
    QString diskSerial;
    quint64 diskSizeBytes;
    QString gpuName;
    quint64 gpuVRAMBytes;
    QString networkMAC;
    QString networkAdapterName;
    QString biosSerial;
    QString biosVersion;
    QString osVersion;
    quint32 osBuildNumber;
    QString compositeHash;
};

class HardwareInfo {
public:
    HardwareInfo();
    ~HardwareInfo();

    HardwareInfo(const HardwareInfo&) = delete;
    HardwareInfo& operator=(const HardwareInfo&) = delete;

    SystemFingerprint collect();
    QString deviceFingerprint() const { return m_fingerprint.compositeHash; }
    QJsonObject toJson() const;
    QByteArray toEncryptedPayload(const QByteArray& key) const;

    static QList<HardwareComponent> enumerateAllWmiClasses();

private:
    bool initializeWmi();
    void shutdownWmi();

    bool queryWmiString(const QString& wmiClass, const QString& property, QString& out);
    bool queryWmiUint32(const QString& wmiClass, const QString& property, quint32& out);
    bool queryWmiUint64(const QString& wmiClass, const QString& property, quint64& out);

    bool readBaseboardInfo();
    bool readProcessorInfo();
    bool readSystemInfo();
    bool readDiskInfo();
    bool readGpuInfo();
    bool readNetworkInfo();
    bool readBiosInfo();
    bool readOsInfo();
    bool computeCompositeHash();

    QByteArray sha256(const QByteArray& input);

    void* m_wbemLocator = nullptr;
    void* m_wbemServices = nullptr;
    bool m_wmiInitialized = false;
    SystemFingerprint m_fingerprint{};
};

void initializeHardwareInfo();
void shutdownHardwareInfo();
const SystemFingerprint& currentHardwareFingerprint();

} // namespace security
} // namespace astro
