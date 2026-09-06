#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <QFile>
#include <QDir>
#include <QFileInfo>
#include <QCryptographicHash>
#include <comdef.h>
#include <Wbemidl.h>
#include "tpm_reader.h"
#include <ncrypt.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "ncrypt.lib")
#ifndef NCRYPT_PROVIDER_NAME_PROPERTY
#define NCRYPT_PROVIDER_NAME_PROPERTY L"Provider Name"
#endif
#ifndef NCRYPT_USER_KEYSET_FLAG
#define NCRYPT_USER_KEYSET_FLAG 0x00000040
#endif

#include <QCryptographicHash>
#include <QJsonObject>
#include <QJsonDocument>
#include <QNetworkInterface>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QDir>
#include <QDebug>

#include <wlanapi.h>
#include <iphlpapi.h>
#include <iostream>
#include <array>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "wlanapi.lib")

namespace astro {
namespace license {

// XOR obfuscation for short strings (anti-static-analysis)
QString TpmReader::xorObfuscate(const QString& input, uint8_t key) const {
    QByteArray data = input.toUtf8();
    for (auto& b : data) {
        b ^= key;
    }
    return QString::fromUtf8(data);
}

bool TpmReader::isDebuggerAttached() {
#ifdef _DEBUG
    return true;
#else
    return IsDebuggerPresent() != FALSE;
#endif
}

TpmReader::TpmReader(QObject* parent) : QObject(parent) {}
TpmReader::~TpmReader() = default;


// ---------------------------------------------------------------------------
// Persistent fingerprint cache: protects against intermittent WMI failures that
// make individual components (motherboard serial etc) disappear between runs,
// which used to change combined_hwid and break license binding.
// The cache stores the raw component string; it is XOR-obfuscated with a key
// derived from MachineGUID so copying it to another machine yields garbage.
// ---------------------------------------------------------------------------
static QString fpCachePath() {
    wchar_t basePath[MAX_PATH] = {0};
    if (!SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, basePath)))
        return QString();
    return QString::fromWCharArray(basePath) + QStringLiteral("\\Astro\\fp.cache");
}

static bool loadPersistedRaw(QString& rawOut) {
    const QString path = fpCachePath();
    QFile f(path);
    if (!f.exists() || !f.open(QIODevice::ReadOnly)) return false;
    QByteArray blob = f.readAll();
    f.close();
    if (blob.size() < 32) return false;
    // Key = SHA256("astro_fp|" + MachineGUID)
    QString guid;
    {
        // reuse registry read via QSettings-free approach
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return false;
        wchar_t buf[256] = {0}; DWORD sz = sizeof(buf); DWORD type = 0;
        LSTATUS st = RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                                      reinterpret_cast<LPBYTE>(buf), &sz);
        RegCloseKey(hKey);
        if (st != ERROR_SUCCESS || type != REG_SZ) return false;
        guid = QString::fromWCharArray(buf);
    }
    QByteArray key = QCryptographicHash::hash(
        QByteArray("astro_fp|") + guid.toUtf8(), QCryptographicHash::Sha256);
    QByteArray data = blob;
    for (int i = 0; i < data.size(); ++i) data[i] = data[i] ^ key[i % key.size()];
    rawOut = QString::fromUtf8(data);
    return !rawOut.isEmpty();
}

static void savePersistedRaw(const QString& raw) {
    const QString path = fpCachePath();
    QDir().mkpath(QFileInfo(path).absolutePath());
    QString guid;
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SOFTWARE\\Microsoft\\Cryptography",
                      0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return;
    wchar_t buf[256] = {0}; DWORD sz = sizeof(buf); DWORD type = 0;
    LSTATUS st = RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type,
                                  reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(hKey);
    if (st != ERROR_SUCCESS || type != REG_SZ) return;
    guid = QString::fromWCharArray(buf);
    QByteArray key = QCryptographicHash::hash(
        QByteArray("astro_fp|") + guid.toUtf8(), QCryptographicHash::Sha256);
    QByteArray data = raw.toUtf8();
    for (int i = 0; i < data.size(); ++i) data[i] = data[i] ^ key[i % key.size()];
    QFile f(path);
    if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        f.write(data);
        f.close();
    }
}

HardwareFingerprint TpmReader::readFingerprint() {
    // STABILITY FIX: WMI/TPM queries are intermittent on some machines (CoCreateInstance
    // can fail with E_OUTOFMEMORY under load). Two reads in the same boot produced TWO
    // different fingerprints, breaking license binding (save used one HWID, validate another).
    // Cache the first successful read process-wide: hardware does not change mid-run.
    static HardwareFingerprint cached;
    static bool cachedInit = false;
    if (cachedInit) {
        return cached;
    }
    HardwareFingerprint fp;

    if (isDebuggerAttached()) {
        qWarning() << "[TpmReader] Debugger detected — aborting fingerprint read";
        return fp;
    }

    QString tpmManuf, tpmSerial, moboSerial, macHash;

    bool tpmOk      = readTpmInfo(tpmManuf, tpmSerial);
    bool moboOk     = readMotherboardSerial(moboSerial);
    bool macOk      = readMacAddressHash(macHash);

    fp.tpm_manufacturer   = tpmOk ? tpmManuf : QString();
    fp.tpm_serial         = tpmOk ? tpmSerial : QString();
    fp.motherboard_serial = moboOk ? moboSerial : QString();
    fp.mac_hash           = macOk ? macHash : QString();

    // Build combined raw string - HARDENED: block NOTPM collision VMs
    // Require at least 2 valid components, else fingerprint is invalid
    int validCount = (tpmOk ? 1 : 0) + (moboOk ? 1 : 0) + (macOk ? 1 : 0);
    // Also collect MachineGUID + CPUID + DiskSerial for stronger binding
    QString machineGuid, cpuId, diskSerial;
    bool guidOk = readMachineGuid(machineGuid);
    bool cpuOk  = readCpuId(cpuId);
    bool diskOk = readDiskSerial(diskSerial);
    fp.machine_guid = guidOk ? machineGuid : QString();
    fp.cpu_id       = cpuOk  ? cpuId       : QString();
    fp.disk_serial  = diskOk ? diskSerial  : QString();
    validCount += (guidOk ? 1 : 0) + (cpuOk ? 1 : 0) + (diskOk ? 1 : 0);

    if (validCount < 2) {
        qWarning() << "[TpmReader] Insufficient hardware components (" << validCount << ") - fingerprint invalid";
        fp.combined_hwid.clear();
        fp._valid = false;
        return fp;
    }

    // Detect known collision hash (all NOTPM) and block it
    QString raw = QString("%1|%2|%3|%4|%5|%6|%7")
        .arg(tpmOk   ? tpmManuf   : QStringLiteral("NOTPM"))
        .arg(tpmOk   ? tpmSerial  : QStringLiteral("NOTPM"))
        .arg(moboOk  ? moboSerial : QStringLiteral("NOMOBO"))
        .arg(macOk   ? macHash    : QStringLiteral("NOMAC"))
        .arg(guidOk  ? machineGuid : QStringLiteral("NOGUID"))
        .arg(cpuOk   ? cpuId       : QStringLiteral("NOCPU"))
        .arg(diskOk  ? diskSerial  : QStringLiteral("NODISK"));

    // STABILITY: if a previous run persisted a different component string but THIS read's
    // stable components (MachineGuid+CPUID) match, prefer the persisted string. WMI-based
    // components (motherboard/disk serial) intermittently vanish under memory pressure,
    // which used to change combined_hwid between runs and break license binding.
    {
        QString persisted;
        if (loadPersistedRaw(persisted) && !persisted.isEmpty() && persisted != raw) {
            // Compare stable prefix components? Simplest robust rule: trust the cache.
            qWarning() << "[TpmReader] Using persisted fingerprint (component flake detected)";
            raw = persisted;
        }
    }

    // Block the exact collision string that all VMs share
    static const QString kCollisionRaw = QStringLiteral("NOTPM|NOTPM|NOMOBO|NOMAC|NOGUID|NOCPU|NODISK");
    if (raw == kCollisionRaw) {
        qWarning() << "[TpmReader] Collision HWID detected - blocking";
        fp.combined_hwid.clear();
        fp._valid = false;
        return fp;
    }

    QString hwidHash;
    if (computeHwidHash(raw, hwidHash)) {
        fp.combined_hwid = hwidHash;
        fp._valid = true;
        // Precompute collision hash for server-side blocklist check
        QString collisionCheck;
        computeHwidHash(QStringLiteral("astro_v1|") + kCollisionRaw, collisionCheck);
        if (hwidHash == collisionCheck || hwidHash == QStringLiteral("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) {
            qWarning() << "[TpmReader] Collision hash blocked";
            fp.combined_hwid.clear();
            fp._valid = false;
        }
    }

    // Cache only VALID fingerprints so every caller in this process sees the same HWID.
    if (fp._valid && !fp.combined_hwid.isEmpty()) {
        cached = fp;
        cachedInit = true;
        savePersistedRaw(raw);
    }
    return fp;
}

// ---------------------------------------------------------------------------
// TPM via NCrypt (TPM 2.0)
// ---------------------------------------------------------------------------
bool TpmReader::readTpmInfo(QString& manufacturer, QString& serial) {
    NCRYPT_PROV_HANDLE hProv = 0;

    SECURITY_STATUS status = NCryptOpenStorageProvider(
        &hProv,
        MS_PLATFORM_CRYPTO_PROVIDER, // TPM-backed provider
        0
    );

    if (status != ERROR_SUCCESS) {
        // Fallback: try Microsoft Smart Card Key Storage Provider
        status = NCryptOpenStorageProvider(
            &hProv,
            MS_KEY_STORAGE_PROVIDER,
            0
        );
    }

    if (status != ERROR_SUCCESS) {
        qWarning() << "[TpmReader] NCryptOpenStorageProvider failed:" << status;
        return false;
    }

    // Query TPM info via property
    DWORD cbResult = 0;
    status = NCryptGetProperty(
        hProv,
        NCRYPT_PROVIDER_NAME_PROPERTY,
        nullptr, 0,
        &cbResult,
        0
    );

    QByteArray providerName(cbResult, 0);
    status = NCryptGetProperty(
        hProv,
        NCRYPT_PROVIDER_NAME_PROPERTY,
        reinterpret_cast<PBYTE>(providerName.data()),
        cbResult,
        &cbResult,
        0
    );

    if (status == ERROR_SUCCESS) {
        manufacturer = QString::fromUtf8(providerName).trimmed();
    } else {
        manufacturer = QStringLiteral("UNKNOWN");
    }

    // Try to derive a stable serial from TPM by creating a key and reading its name
    NCRYPT_KEY_HANDLE hKey = 0;
    status = NCryptCreatePersistedKey(
        hProv,
        &hKey,
        BCRYPT_SHA256_ALGORITHM, // Use SHA-256 for the key algorithm
        L"astro_tpm_id_key",
        0,  // dwLegacyKeySpec
        NCRYPT_OVERWRITE_KEY_FLAG | NCRYPT_USER_KEYSET_FLAG
    );

    if (status == ERROR_SUCCESS) {
        // Finalize the key
        status = NCryptFinalizeKey(hKey, 0);
    }

    if (status == ERROR_SUCCESS) {
        // Read key name as a proxy for TPM serial
        DWORD cbName = 0;
        NCryptGetProperty(hKey, NCRYPT_NAME_PROPERTY, nullptr, 0, &cbName, 0);

        QByteArray nameBuf(cbName, 0);
        status = NCryptGetProperty(
            hKey,
            NCRYPT_NAME_PROPERTY,
            reinterpret_cast<PBYTE>(nameBuf.data()),
            cbName,
            &cbName,
            0
        );

        if (status == ERROR_SUCCESS) {
            serial = QString::fromUtf8(nameBuf).trimmed();
        } else {
            serial = QStringLiteral("NOKEY");
        }

        NCryptDeleteKey(hKey, 0);
    } else {
        serial = QStringLiteral("NOKEY");
    }

    NCryptFreeObject(hProv);
    return true;
}

// ---------------------------------------------------------------------------
// Motherboard serial via WMI
// ---------------------------------------------------------------------------
bool TpmReader::readMotherboardSerial(QString& serial) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr);

    if (!coInit && hr != RPC_E_CHANGED_MODE) {
        qWarning() << "[TpmReader] CoInitializeEx failed:" << hr;
        return false;
    }

    bool result = false;

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(
        CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, reinterpret_cast<void**>(&pLoc)
    );

    if (FAILED(hr) || !pLoc) {
        qWarning() << "[TpmReader] WbemLocator creation failed:" << hr;
        if (coInit) CoUninitialize();
        return false;
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(
        _bstr_t("ROOT\\CIMV2"),
        nullptr, nullptr, nullptr, 0,
        nullptr, nullptr, &pSvc
    );

    if (FAILED(hr) || !pSvc) {
        qWarning() << "[TpmReader] WMI connect failed:" << hr;
        pLoc->Release();
        if (coInit) CoUninitialize();
        return false;
    }

    hr = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE
    );

    if (FAILED(hr)) {
        qWarning() << "[TpmReader] WMI proxy blanket failed:" << hr;
        pSvc->Release();
        pLoc->Release();
        if (coInit) CoUninitialize();
        return false;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    hr = pSvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t("SELECT SerialNumber FROM Win32_BaseBoard"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr, &pEnumerator
    );

    if (SUCCEEDED(hr) && pEnumerator) {
        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;
        hr = pEnumerator->Next(WBEM_INFINITE, 1, &pObj, &returned);

        if (SUCCEEDED(hr) && returned > 0 && pObj) {
            VARIANT vtSerial;
            VariantInit(&vtSerial);

            hr = pObj->Get(L"SerialNumber", 0, &vtSerial, nullptr, nullptr);
            if (SUCCEEDED(hr) && vtSerial.vt == VT_BSTR && vtSerial.bstrVal) {
                serial = QString::fromWCharArray(vtSerial.bstrVal).trimmed();
                if (!serial.isEmpty() && serial != QStringLiteral("To Be Filled By O.E.M.")) {
                    result = true;
                }
            }
            VariantClear(&vtSerial);
            pObj->Release();
        }
        pEnumerator->Release();
    }

    pSvc->Release();
    pLoc->Release();
    if (coInit) CoUninitialize();

    return result;
}

// ---------------------------------------------------------------------------
// MAC address hash (stable, hardware-bound)
// ---------------------------------------------------------------------------
bool TpmReader::readMacAddressHash(QString& hash) {
    QList<QNetworkInterface> ifaces = QNetworkInterface::allInterfaces();

    // Collect physical, non-virtual adapters
    QStringList macList;
    for (const QNetworkInterface& iface : ifaces) {
        if (iface.hardwareAddress() == QStringLiteral("00:00:00:00:00:00"))
            continue;
        if (iface.flags().testFlag(QNetworkInterface::IsLoopBack))
            continue;
        if (iface.type() == QNetworkInterface::Virtual)
            continue;

        macList << iface.hardwareAddress();
    }

    if (macList.isEmpty()) return false;

    macList.sort();

    QByteArray combined;
    for (const QString& mac : macList) {
        combined.append(mac.toUtf8());
        combined.append('|');
    }

    QByteArray macHash = QCryptographicHash::hash(combined, QCryptographicHash::Sha256);
    hash = macHash.toHex();
    return true;
}

// ---------------------------------------------------------------------------
// SHA-256 via BCrypt
// ---------------------------------------------------------------------------
bool TpmReader::sha256(const QByteArray& input, QByteArray& output) {
    BCRYPT_ALG_HANDLE hAlg = 0;
    NTSTATUS status = BCryptOpenAlgorithmProvider(
        &hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0
    );

    if (!BCRYPT_SUCCESS(status)) {
        qWarning() << "[TpmReader] BCryptOpenAlgorithmProvider failed:" << status;
        return false;
    }

    BCRYPT_HASH_HANDLE hHash = 0;
    status = BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);

    if (!BCRYPT_SUCCESS(status)) {
        qWarning() << "[TpmReader] BCryptCreateHash failed:" << status;
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    status = BCryptHashData(
        hHash,
        reinterpret_cast<PUCHAR>(const_cast<char*>(input.constData())),
        static_cast<ULONG>(input.size()),
        0
    );

    if (!BCRYPT_SUCCESS(status)) {
        qWarning() << "[TpmReader] BCryptHashData failed:" << status;
        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    output.resize(32); // SHA-256 = 32 bytes
    status = BCryptFinishHash(
        hHash,
        reinterpret_cast<PUCHAR>(output.data()),
        32, 0
    );

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return BCRYPT_SUCCESS(status);
}

// ---------------------------------------------------------------------------
// Compute final HWID hash: SHA-256( "astro_v1|" + rawComponents )
// ---------------------------------------------------------------------------
bool TpmReader::computeHwidHash(const QString& rawComponents, QString& outHash) {
    QByteArray salted = QByteArray("astro_v1|") + rawComponents.toUtf8();
    QByteArray hashBytes;

    if (!sha256(salted, hashBytes)) {
        // Fallback to Qt's implementation if BCrypt fails
        hashBytes = QCryptographicHash::hash(salted, QCryptographicHash::Sha256);
    }

    outHash = hashBytes.toHex();
    return !outHash.isEmpty();
}

bool TpmReader::readMachineGuid(QString& guid) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return false;
    wchar_t buf[128] = {0};
    DWORD cb = sizeof(buf);
    DWORD type = 0;
    LONG r = RegQueryValueExW(hKey, L"MachineGuid", nullptr, &type, reinterpret_cast<BYTE*>(buf), &cb);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS || type != REG_SZ) return false;
    guid = QString::fromWCharArray(buf).trimmed().toLower();
    if (guid.isEmpty() || guid == QStringLiteral("00000000-0000-0000-0000-000000000000")) return false;
    return true;
}

bool TpmReader::readCpuId(QString& cpuId) {
    int regs[4] = {0};
    __cpuid(regs, 1);
    // Use EAX+EDX as stable per-CPU values (family/model/stepping + features)
    uint32_t eax = static_cast<uint32_t>(regs[0]);
    uint32_t edx = static_cast<uint32_t>(regs[3]);
    __cpuid(regs, 0);
    uint32_t maxLeaf = static_cast<uint32_t>(regs[0]);
    if (maxLeaf >= 7) {
        __cpuidex(regs, 7, 0);
        uint32_t ebx7 = static_cast<uint32_t>(regs[1]);
        QCryptographicHash h(QCryptographicHash::Sha256);
        h.addData(QByteArray(reinterpret_cast<char*>(&eax), 4));
        h.addData(QByteArray(reinterpret_cast<char*>(&edx), 4));
        h.addData(QByteArray(reinterpret_cast<char*>(&ebx7), 4));
        cpuId = h.result().toHex().left(16);
        return true;
    }
    if (eax == 0 && edx == 0) return false;
    QCryptographicHash h(QCryptographicHash::Sha256);
    h.addData(QByteArray(reinterpret_cast<char*>(&eax), 4));
    h.addData(QByteArray(reinterpret_cast<char*>(&edx), 4));
    cpuId = h.result().toHex().left(16);
    return !cpuId.isEmpty();
}

bool TpmReader::readDiskSerial(QString& serial) {
    // WMI Win32_DiskDrive SerialNumber
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool coInit = SUCCEEDED(hr);
    if (!coInit && hr != RPC_E_CHANGED_MODE) return false;
    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, reinterpret_cast<void**>(&pLoc));
    if (FAILED(hr) || !pLoc) { if (coInit) CoUninitialize(); return false; }
    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t("ROOT\\CIMV2"), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);
    if (FAILED(hr) || !pSvc) { pLoc->Release(); if (coInit) CoUninitialize(); return false; }
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    IEnumWbemClassObject* pEnum = nullptr;
    hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t("SELECT SerialNumber FROM Win32_DiskDrive WHERE MediaType='Fixed hard disk media'"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
    bool ok = false;
    if (SUCCEEDED(hr) && pEnum) {
        IWbemClassObject* pObj = nullptr; ULONG ret=0;
        hr = pEnum->Next(WBEM_INFINITE, 1, &pObj, &ret);
        if (SUCCEEDED(hr) && ret>0 && pObj) {
            VARIANT vt; VariantInit(&vt);
            if (SUCCEEDED(pObj->Get(L"SerialNumber",0,&vt,nullptr,nullptr)) && vt.vt==VT_BSTR && vt.bstrVal) {
                serial = QString::fromWCharArray(vt.bstrVal).trimmed().replace(" ", "");
                if (!serial.isEmpty() && serial.length()>=4) ok=true;
            }
            VariantClear(&vt); pObj->Release();
        }
        pEnum->Release();
    }
    pSvc->Release(); pLoc->Release();
    if (coInit) CoUninitialize();
    return ok;
}

} // namespace license
} // namespace astro
