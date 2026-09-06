#include "hardware_info.h"

#include <comdef.h>
#include <WbemCli.h>
#include <iphlpapi.h>
#include <bcrypt.h>
#include <QCryptographicHash>
#include <QJsonArray>
#include <QJsonObject>
#include <QMutex>
#include <QMutexLocker>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "bcrypt.lib")

namespace astro {
namespace security {

namespace {
    HardwareInfo* g_instance = nullptr;
    QMutex g_mutex;
}

HardwareInfo::HardwareInfo() {
    initializeWmi();
}

HardwareInfo::~HardwareInfo() {
    shutdownWmi();
}

bool HardwareInfo::initializeWmi() {
    if (m_wmiInitialized) return true;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return false;

    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr) && hr != RPC_E_TOO_LATE) return false;

    IWbemLocator* pLocator = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&pLocator));
    if (FAILED(hr)) return false;

    IWbemServices* pServices = nullptr;
    hr = pLocator->ConnectServer(
        _bstr_t(ENC("ROOT\\CIMV2").decrypt()), nullptr, nullptr, nullptr,
        0, nullptr, nullptr, &pServices);
    if (FAILED(hr)) {
        pLocator->Release();
        return false;
    }

    hr = CoSetProxyBlanket(pServices,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE);
    if (FAILED(hr)) {
        pServices->Release();
        pLocator->Release();
        return false;
    }

    m_wbemLocator = pLocator;
    m_wbemServices = pServices;
    m_wmiInitialized = true;
    return true;
}

void HardwareInfo::shutdownWmi() {
    if (m_wbemServices) {
        static_cast<IWbemServices*>(m_wbemServices)->Release();
        m_wbemServices = nullptr;
    }
    if (m_wbemLocator) {
        static_cast<IWbemLocator*>(m_wbemLocator)->Release();
        m_wbemLocator = nullptr;
    }
    m_wmiInitialized = false;
}

bool HardwareInfo::queryWmiString(const QString& wmiClass, const QString& property, QString& out) {
    if (!m_wmiInitialized) return false;

    auto* pServices = static_cast<IWbemServices*>(m_wbemServices);
    IEnumWbemClassObject* pEnumerator = nullptr;

    QString query = QString(QString::fromStdString(ENC("SELECT %1 FROM %2").decrypt())).arg(property, wmiClass);
    HRESULT hr = pServices->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.toStdWString().c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hr) || !pEnumerator) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);

    bool success = false;
    if (SUCCEEDED(hr) && returned > 0 && pObj) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pObj->Get(_bstr_t(property.toStdWString().c_str()), 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
            out = QString::fromWCharArray(vtProp.bstrVal);
            success = true;
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    return success;
}

bool HardwareInfo::queryWmiUint32(const QString& wmiClass, const QString& property, quint32& out) {
    if (!m_wmiInitialized) return false;

    auto* pServices = static_cast<IWbemServices*>(m_wbemServices);
    IEnumWbemClassObject* pEnumerator = nullptr;

    QString query = QString(QString::fromStdString(ENC("SELECT %1 FROM %2").decrypt())).arg(property, wmiClass);
    HRESULT hr = pServices->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.toStdWString().c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hr) || !pEnumerator) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);

    bool success = false;
    if (SUCCEEDED(hr) && returned > 0 && pObj) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pObj->Get(_bstr_t(property.toStdWString().c_str()), 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtProp.vt == VT_I4) {
            out = static_cast<quint32>(vtProp.intVal);
            success = true;
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    return success;
}

bool HardwareInfo::queryWmiUint64(const QString& wmiClass, const QString& property, quint64& out) {
    if (!m_wmiInitialized) return false;

    auto* pServices = static_cast<IWbemServices*>(m_wbemServices);
    IEnumWbemClassObject* pEnumerator = nullptr;

    QString query = QString(QString::fromStdString(ENC("SELECT %1 FROM %2").decrypt())).arg(property, wmiClass);
    HRESULT hr = pServices->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(query.toStdWString().c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator);

    if (FAILED(hr) || !pEnumerator) return false;

    IWbemClassObject* pObj = nullptr;
    ULONG returned = 0;
    hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);

    bool success = false;
    if (SUCCEEDED(hr) && returned > 0 && pObj) {
        VARIANT vtProp;
        VariantInit(&vtProp);
        hr = pObj->Get(_bstr_t(property.toStdWString().c_str()), 0, &vtProp, nullptr, nullptr);
        if (SUCCEEDED(hr) && vtProp.vt == VT_UI8) {
            out = static_cast<quint64>(vtProp.ullVal);
            success = true;
        }
        VariantClear(&vtProp);
        pObj->Release();
    }

    pEnumerator->Release();
    return success;
}

bool HardwareInfo::readBaseboardInfo() {
    queryWmiString(ENC("Win32_BaseBoard").decrypt(), ENC("Manufacturer").decrypt(), m_fingerprint.baseboardManufacturer);
    queryWmiString(ENC("Win32_BaseBoard").decrypt(), ENC("SerialNumber").decrypt(), m_fingerprint.baseboardSerial);
    return !m_fingerprint.baseboardSerial.isEmpty();
}

bool HardwareInfo::readProcessorInfo() {
    queryWmiString(ENC("Win32_Processor").decrypt(), ENC("Name").decrypt(), m_fingerprint.processorName);
    queryWmiUint32(ENC("Win32_Processor").decrypt(), ENC("NumberOfCores").decrypt(), m_fingerprint.processorCores);
    quint32 speed = 0;
    if (queryWmiUint32(ENC("Win32_Processor").decrypt(), ENC("MaxClockSpeed").decrypt(), speed)) {
        m_fingerprint.processorSpeedMHz = speed;
    }
    return !m_fingerprint.processorName.isEmpty();
}

bool HardwareInfo::readSystemInfo() {
    queryWmiString(ENC("Win32_ComputerSystem").decrypt(), ENC("Manufacturer").decrypt(), m_fingerprint.systemManufacturer);
    queryWmiString(ENC("Win32_ComputerSystem").decrypt(), ENC("Model").decrypt(), m_fingerprint.systemModel);
    quint64 ram = 0;
    if (queryWmiUint64(ENC("Win32_ComputerSystem").decrypt(), ENC("TotalPhysicalMemory").decrypt(), ram)) {
        m_fingerprint.totalRAMBytes = ram;
    }
    return !m_fingerprint.systemModel.isEmpty();
}

bool HardwareInfo::readDiskInfo() {
    queryWmiString(ENC("Win32_DiskDrive").decrypt(), ENC("SerialNumber").decrypt(), m_fingerprint.diskSerial);
    quint64 size = 0;
    if (queryWmiUint64(ENC("Win32_DiskDrive").decrypt(), ENC("Size").decrypt(), size)) {
        m_fingerprint.diskSizeBytes = size;
    }
    return !m_fingerprint.diskSerial.isEmpty();
}

bool HardwareInfo::readGpuInfo() {
    queryWmiString(ENC("Win32_VideoController").decrypt(), ENC("Name").decrypt(), m_fingerprint.gpuName);
    quint64 vram = 0;
    if (queryWmiUint64(ENC("Win32_VideoController").decrypt(), ENC("AdapterRAM").decrypt(), vram)) {
        m_fingerprint.gpuVRAMBytes = vram;
    }
    return !m_fingerprint.gpuName.isEmpty();
}

bool HardwareInfo::readNetworkInfo() {
    IP_ADAPTER_INFO adapterInfo[16];
    DWORD bufLen = sizeof(adapterInfo);
    DWORD status = GetAdaptersInfo(adapterInfo, &bufLen);

    if (status == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = adapterInfo;
        while (pAdapter) {
            if (pAdapter->AddressLength == 6) {
                QString mac;
                for (UINT i = 0; i < pAdapter->AddressLength; i++) {
                    mac += QString("%1").arg(pAdapter->Address[i], 2, 16, QChar('0')).toUpper();
                    if (i < pAdapter->AddressLength - 1) mac += ":";
                }
                m_fingerprint.networkMAC = mac;
                m_fingerprint.networkAdapterName = QString::fromLocal8Bit(pAdapter->Description);
                break;
            }
            pAdapter = pAdapter->Next;
        }
    }
    return !m_fingerprint.networkMAC.isEmpty();
}

bool HardwareInfo::readBiosInfo() {
    queryWmiString(ENC("Win32_BIOS").decrypt(), ENC("SerialNumber").decrypt(), m_fingerprint.biosSerial);
    queryWmiString(ENC("Win32_BIOS").decrypt(), ENC("SMBIOSBIOSVersion").decrypt(), m_fingerprint.biosVersion);
    return !m_fingerprint.biosSerial.isEmpty();
}

bool HardwareInfo::readOsInfo() {
    queryWmiString(ENC("Win32_OperatingSystem").decrypt(), ENC("Version").decrypt(), m_fingerprint.osVersion);
    queryWmiUint32(ENC("Win32_OperatingSystem").decrypt(), ENC("BuildNumber").decrypt(), m_fingerprint.osBuildNumber);
    return !m_fingerprint.osVersion.isEmpty();
}

QByteArray HardwareInfo::sha256(const QByteArray& input) {
    QByteArray hash = QCryptographicHash::hash(input, QCryptographicHash::Sha256);
    return hash.toHex();
}

bool HardwareInfo::computeCompositeHash() {
    QString raw = QString("%1|%2|%3|%4|%5|%6|%7|%8")
        .arg(m_fingerprint.baseboardSerial)
        .arg(m_fingerprint.processorName)
        .arg(m_fingerprint.diskSerial)
        .arg(m_fingerprint.biosSerial)
        .arg(m_fingerprint.networkMAC)
        .arg(m_fingerprint.systemModel)
        .arg(m_fingerprint.gpuName)
        .arg(m_fingerprint.osVersion);

    m_fingerprint.compositeHash = QString::fromUtf8(sha256(raw.toUtf8()));
    return !m_fingerprint.compositeHash.isEmpty();
}

SystemFingerprint HardwareInfo::collect() {
    if (!m_wmiInitialized) {
        initializeWmi();
    }

    readBaseboardInfo();
    readProcessorInfo();
    readSystemInfo();
    readDiskInfo();
    readGpuInfo();
    readNetworkInfo();
    readBiosInfo();
    readOsInfo();
    computeCompositeHash();

    return m_fingerprint;
}

QJsonObject HardwareInfo::toJson() const {
    QJsonObject obj;
    obj[ENC("baseboard_manufacturer").decrypt()] = m_fingerprint.baseboardManufacturer;
    obj[ENC("baseboard_serial").decrypt()] = m_fingerprint.baseboardSerial;
    obj[ENC("processor_name").decrypt()] = m_fingerprint.processorName;
    obj[ENC("processor_cores").decrypt()] = static_cast<qint64>(m_fingerprint.processorCores);
    obj[ENC("processor_speed_mhz").decrypt()] = static_cast<qint64>(m_fingerprint.processorSpeedMHz);
    obj[ENC("system_manufacturer").decrypt()] = m_fingerprint.systemManufacturer;
    obj[ENC("system_model").decrypt()] = m_fingerprint.systemModel;
    obj[ENC("total_ram_bytes").decrypt()] = static_cast<qint64>(m_fingerprint.totalRAMBytes);
    obj[ENC("disk_serial").decrypt()] = m_fingerprint.diskSerial;
    obj[ENC("disk_size_bytes").decrypt()] = static_cast<qint64>(m_fingerprint.diskSizeBytes);
    obj[ENC("gpu_name").decrypt()] = m_fingerprint.gpuName;
    obj[ENC("gpu_vram_bytes").decrypt()] = static_cast<qint64>(m_fingerprint.gpuVRAMBytes);
    obj[ENC("network_mac").decrypt()] = m_fingerprint.networkMAC;
    obj[ENC("network_adapter").decrypt()] = m_fingerprint.networkAdapterName;
    obj[ENC("bios_serial").decrypt()] = m_fingerprint.biosSerial;
    obj[ENC("bios_version").decrypt()] = m_fingerprint.biosVersion;
    obj[ENC("os_version").decrypt()] = m_fingerprint.osVersion;
    obj[ENC("os_build").decrypt()] = static_cast<qint64>(m_fingerprint.osBuildNumber);
    obj[ENC("composite_hash").decrypt()] = m_fingerprint.compositeHash;
    return obj;
}

QByteArray HardwareInfo::toEncryptedPayload(const QByteArray& key) const {
    QJsonObject json = toJson();
    QJsonDocument doc(json);
    QByteArray plaintext = doc.toJson(QJsonDocument::Compact);

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
    if (!BCRYPT_SUCCESS(status)) return QByteArray();

    status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PVOID)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    BCRYPT_AUTH_TAG_INFO authTagInfo{};
    authTagInfo.pbNonce = nullptr;
    authTagInfo.cbNonce = 0;
    authTagInfo.pbAuthenticatedData = nullptr;
    authTagInfo.cbAuthenticatedData = 0;
    authTagInfo.cbTag = 16;

    status = BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
        (PUCHAR)key.data(), static_cast<ULONG>(key.size()), 0);
    if (!BCRYPT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    DWORD cbPlainText = static_cast<DWORD>(plaintext.size());
    DWORD cbCipherText = cbPlainText;
    DWORD cbResult = 0;

    BYTE iv[12]{};
    BCryptGenRandom(hAlg, iv, sizeof(iv), 0);

    BYTE tag[16]{};

    BYTE* pCipherText = new (std::nothrow) BYTE[cbCipherText + sizeof(tag)];
    if (!pCipherText) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return QByteArray();
    }

    status = BCryptEncrypt(hKey,
        (PUCHAR)plaintext.data(), cbPlainText,
        &authTagInfo, iv, sizeof(iv),
        pCipherText, cbCipherText,
        &cbResult, 0, iv, sizeof(iv), sizeof(tag));

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!BCRYPT_SUCCESS(status)) {
        delete[] pCipherText;
        return QByteArray();
    }

    memcpy(pCipherText + cbCipherText, tag, sizeof(tag));

    QByteArray result;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<const char*>(pCipherText), cbCipherText + sizeof(tag));

    delete[] pCipherText;
    return result;
}

QList<HardwareComponent> HardwareInfo::enumerateAllWmiClasses() {
    QList<HardwareComponent> components;

    HardwareInfo info;
    if (!info.m_wmiInitialized) return components;

    QStringList wmiClasses = {
        ENC("Win32_BaseBoard").decrypt(), ENC("Win32_Processor").decrypt(), ENC("Win32_ComputerSystem").decrypt(),
        ENC("Win32_DiskDrive").decrypt(), ENC("Win32_VideoController").decrypt(), ENC("Win32_NetworkAdapter").decrypt(),
        ENC("Win32_BIOS").decrypt(), ENC("Win32_OperatingSystem").decrypt()
    };

    QStringList properties = {
        ENC("Manufacturer").decrypt(), ENC("SerialNumber").decrypt(), ENC("Name").decrypt(), ENC("Model").decrypt(),
        ENC("NumberOfCores").decrypt(), ENC("MaxClockSpeed").decrypt(), ENC("TotalPhysicalMemory").decrypt(),
        ENC("Size").decrypt(), ENC("AdapterRAM").decrypt(), ENC("Description").decrypt(), ENC("SMBIOSBIOSVersion").decrypt(),
        ENC("Version").decrypt(), ENC("BuildNumber").decrypt()
    };

    auto* pServices = static_cast<IWbemServices*>(info.m_wbemServices);

    for (const auto& cls : wmiClasses) {
        for (const auto& prop : properties) {
            IEnumWbemClassObject* pEnumerator = nullptr;
            QString query = QString(QString::fromStdString(ENC("SELECT %1 FROM %2").decrypt())).arg(prop, cls);

            HRESULT hr = pServices->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(query.toStdWString().c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                nullptr, &pEnumerator);

            if (FAILED(hr) || !pEnumerator) continue;

            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);

            if (SUCCEEDED(hr) && returned > 0 && pObj) {
                VARIANT vtProp;
                VariantInit(&vtProp);
                hr = pObj->Get(_bstr_t(prop.toStdWString().c_str()), 0, &vtProp, nullptr, nullptr);
                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
                    HardwareComponent comp;
                    comp.wmiClass = cls;
                    comp.property = prop;
                    comp.value = QString::fromWCharArray(vtProp.bstrVal);
                    components.append(comp);
                }
                VariantClear(&vtProp);
                pObj->Release();
            }
            pEnumerator->Release();
        }
    }

    return components;
}

void initializeHardwareInfo() {
    QMutexLocker lock(&g_mutex);
    if (!g_instance) {
        g_instance = new HardwareInfo();
        g_instance->collect();
    }
}

void shutdownHardwareInfo() {
    QMutexLocker lock(&g_mutex);
    delete g_instance;
    g_instance = nullptr;
}

const SystemFingerprint& currentHardwareFingerprint() {
    QMutexLocker lock(&g_mutex);
    static SystemFingerprint empty{};
    if (g_instance) {
        return g_instance->collect();
    }
    return empty;
}

} // namespace security
} // namespace astro
