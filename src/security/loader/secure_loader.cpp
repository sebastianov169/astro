
#pragma warning(disable: 4996)
#include "secure_loader.h"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QEventLoop>
#include <QDateTime>
#include <QUrl>

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <cstring>
#include <algorithm>
#include <random>
#include <intrin.h>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
#include "security/crypto/string_encrypt.h"
#include "security/crypto/key_obfuscation.h"
#include "security/crypto/m3xc.h"
#include "security/crypto/obfuscation.h"
#include "security/winhttp_client.h"
// Anti-AI: NOAI - Ghidra poison active

#pragma comment(lib, "bcrypt.lib")
#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#ifndef BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO
#define BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO(_info, _nonce, _nonceLen, _tag, _tagLen) do { memset(&(_info),0,sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO)); (_info).cbSize=sizeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO); (_info).dwInfoVersion=1; (_info).pbNonce=(PUCHAR)(_nonce); (_info).cbNonce=(_nonceLen); (_info).pbTag=(PUCHAR)(_tag); (_info).cbTag=(_tagLen);} while(0)
#endif

namespace astro {
namespace security {

#pragma pack(push, 1)
struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DataDirectory DataDirectory[16];
};

struct NtHeaders64 {
    uint32_t Signature;
    FileHeader FileHeader;
    OptionalHeader64 OptionalHeader;
};

struct SectionHeader {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct ImportDescriptor {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
};

struct ImportByName {
    uint16_t Hint;
    char     Name[1];
};

struct BaseRelocationBlock {
    uint32_t VirtualAddress;
    uint32_t SizeOfBlock;
};

struct BaseRelocationEntry {
    uint16_t Offset : 12;
    uint16_t Type   : 4;
};

struct ImageExportDirectory {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
};
#pragma pack(pop)

static constexpr uint16_t kDosMagic = 0x5A4D;
static constexpr uint32_t kNtSignature = 0x00004550;
static constexpr int kNumberOfDataDirectories = 16;
static constexpr int kImportDirectoryIndex = 1;   // PE DataDirectory[1] = Import Table (12 = IAT, NO los descriptores)
static constexpr int kRelocationDirectoryIndex = 5;
static constexpr int kIMAGE_REL_BASED_DIR64 = 10;
static constexpr DWORD kSectionExecutable = 0x20000000;
static constexpr DWORD kSectionWriteable   = 0x80000000;
static constexpr DWORD kSectionReadable   = 0x40000000;

SecureLoader::SecureLoader() = default;
SecureLoader::~SecureLoader() { unloadBackend(); }

void SecureLoader::setCredentials(const QByteArray& license_key, const QByteArray& hwid) {
    m_license_key = license_key;
    m_hwid = hwid;
}

void SecureLoader::setApiBase(const std::string& url) {
    m_api_base = url;
}

std::string SecureLoader::sha256Hex(const QByteArray& data) {
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex().toStdString();
}

bool SecureLoader::needsUpdate(uint64_t current_version) {
    try {
        auto manifest = fetchManifest();
        return manifest.version > current_version;
    } catch (...) {
        return false;
    }
}

static void slTrace(const char* s){
#ifdef ASTRO_DEBUG_TRACE
    char _tp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _tp);
    std::string _lp = std::string(_tp) + "sl_trace.log";
    FILE* _f=fopen(_lp.c_str(),"a"); if(_f){fprintf(_f,"%s\n",s);fclose(_f);}
#else
    (void)s;
#endif
}
DllManifest SecureLoader::fetchManifest() {
    slTrace("FM-ENTER");
    JUNK_CODE;
    slTrace("FM-JUNK-OK");
    if (OPAQUE_PRED_TRUE((uint64_t)m_license_key.size() ^ 0xFEEDBEEFULL)) { JUNK_CODE; }
    QJsonObject resp;
    FLATTEN_BEGIN(0xC001)
        FLATTEN_CASE(0) {
            QJsonObject inner;
            inner[QString::fromStdString(ENC("license_key").decrypt())] = QString::fromUtf8(m_license_key);
            inner[QString::fromStdString(ENC("hwid").decrypt())] = QString::fromUtf8(m_hwid);
            inner[QString::fromStdString(ENC("action").decrypt())] = QString::fromStdString(ENC("manifest").decrypt());
            inner[QString::fromStdString(ENC("ts").decrypt())] = static_cast<qint64>(QDateTime::currentSecsSinceEpoch());
            inner[QString::fromStdString(ENC("nonce").decrypt())] = QString::number(QDateTime::currentMSecsSinceEpoch());
            QByteArray innerBytes = QJsonDocument(inner).toJson(QJsonDocument::Compact);
            QString encKey = astro::security::crypto::deobfuscateEncryptionKey();
            QString encrypted = astro::security::crypto::lm_m3xcEncrypt(QString::fromUtf8(innerBytes), encKey);
            // SERVER CONTRACT: worker's m3xcDecrypt REQUIRES "b64.tag" (HMAC-SHA256 of
            // the b64 with the derived key) - same format session_guard sends. Without
            // the tag the server answers 401 "Encrypted payload required".
            encrypted = encrypted + QStringLiteral(".") + QString::fromLatin1(
                astro::security::crypto::lm_hmacSha256HexDerived(encrypted.toUtf8(), encKey.toUtf8()));
            QJsonObject wrapper; wrapper[QString::fromStdString(ENC("encrypted").decrypt())] = encrypted;
            QByteArray body = QJsonDocument(wrapper).toJson(QJsonDocument::Compact);
            QString ts = QString::number(QDateTime::currentSecsSinceEpoch());
            QUrl url(QString::fromStdString(m_api_base) + QString::fromStdString(ENC("/api/download").decrypt()));
            // fallback if m_api_base already contains /api
            if (m_api_base.find("/api") != std::string::npos) {
                url = QUrl(QString::fromStdString(m_api_base) + QString::fromStdString(ENC("/download").decrypt()));
            }
            // Ensure path for HMAC is url.path()
            QString path = url.path();
            if (path.isEmpty()) path = QString::fromStdString(ENC("/api/download").decrypt());
            QByteArray payloadHmac = (QString::fromStdString(ENC("POST:").decrypt()) + path + QStringLiteral(":") + ts + QStringLiteral(":") + QString::fromUtf8(body)).toUtf8();
            QByteArray sig = astro::security::crypto::lm_hmacSha256HexDerived(payloadHmac, encKey.toUtf8());
            ASTRO_AI_TRAP();
            // DEADLOCK FIX: QNAM+QEventLoop hangs under LSP/proxy injection; WinHTTP direct.
            std::string respStd;
            slTrace("FM-PRE-HTTP");
            const int httpStatus = astro::security::winhttpPostJson(
                QString::fromStdString(m_api_base).toStdString(), path.toStdString(),
                body.toStdString(), ts.toStdString(), sig.toStdString(), respStd, 15000);
            #ifdef ASTRO_DEBUG_TRACE
    char _mtp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _mtp); std::string _mlp = std::string(_mtp) + "astro_manifest.log";
    { FILE* _d = fopen(_mlp.c_str(), "a");
              if (_d) { fprintf(_d, "manifest httpStatus=%d respLen=%zu head=%.60s\n", httpStatus, respStd.size(), respStd.c_str()); fclose(_d); } }
#endif
            slTrace("FM-POST-HTTP");
            {
                static char _sb2[64]; sprintf_s(_sb2, "FM-STATUS=%d len=%zu", httpStatus, respStd.size());
                slTrace(_sb2);
            }
            if (httpStatus != 200) {
                m_last_error = ENC("Manifest fetch failed: HTTP ").decrypt() + std::to_string(httpStatus);
                throw std::runtime_error(m_last_error);
            }
            {
                static char _sb[64]; sprintf_s(_sb, "FM-HTTP=%d respLen=%zu", httpStatus, respStd.size());
                slTrace(_sb);
            }
            QByteArray rawResp = QByteArray::fromStdString(respStd);
            QJsonDocument doc = QJsonDocument::fromJson(rawResp);
            slTrace("FM-JSON");
            QJsonObject obj = doc.object();
            if (obj.contains(QString::fromStdString(ENC("encrypted").decrypt()))) {
                QString encResp = obj[QString::fromStdString(ENC("encrypted").decrypt())].toString();
                QString decStr;
                if (!encResp.isEmpty()) {
                    slTrace("FM-M3XC-START");
                    decStr = astro::security::crypto::lm_m3xcDecrypt(encResp, encKey);
                    slTrace("FM-M3XC-DONE");
                    #ifdef ASTRO_DEBUG_TRACE
    { FILE* _d = fopen(_mlp.c_str(), "a");
                      if (_d) { fprintf(_d, "decrypt ok=%d len=%d\n", (int)!decStr.isEmpty(), decStr.size()); fclose(_d); } }
#endif
                    if (!decStr.isEmpty()) {
                        QJsonDocument decDoc = QJsonDocument::fromJson(decStr.toUtf8());
                        if (decDoc.isObject()) obj = decDoc.object();
                    }
                }
            }
            resp = obj;
            JUNK_CODE;
            FLATTEN_GOTO(1)
        }
        FLATTEN_CASE(1) {
        }
    FLATTEN_END


    DllManifest m;
    m.download_url = resp[QString::fromStdString(ENC("url").decrypt())].toString().toStdString();
    m.sha256_hex = resp[QString::fromStdString(ENC("sha256").decrypt())].toString().toStdString();
    m.version = resp[QString::fromStdString(ENC("version").decrypt())].toVariant().toULongLong();
    m.size = resp[QString::fromStdString(ENC("size").decrypt())].toVariant().toULongLong();
    return m;
}

QByteArray SecureLoader::downloadDll(const std::string& url) {
    slTrace("DL-ENTER");
    // DEADLOCK FIX: QNAM+QEventLoop hangs under LSP/proxy injection; WinHTTP direct.
    // Hooks LSP (HTTP Debugger) pueden colgar WinHttpReceiveResponse ignorando
    // el timeout: usar timeout corto + reintentos.
    std::string dataStd;
    int httpStatus = 0;
    for (int attempt = 0; attempt < 3 && httpStatus != 200; ++attempt) {
        dataStd.clear();
        httpStatus = astro::security::winHttpGetBin(url, dataStd, 15000);
        {
            static char _db[64]; sprintf_s(_db, "DL-TRY=%d http=%d len=%zu", attempt, httpStatus, dataStd.size());
            slTrace(_db);
        }
    }
    if (httpStatus != 200) {
        m_last_error = ENC("DLL download failed: HTTP ").decrypt() + std::to_string(httpStatus);
        throw std::runtime_error(m_last_error);
    }
    return QByteArray::fromStdString(dataStd);
}

bool SecureLoader::verifySha256(const QByteArray& data, const std::string& expected_hex) {
    std::string actual = sha256Hex(data);
    return actual == expected_hex;
}

void* SecureLoader::mapDllMemory(const QByteArray& raw_dll) {
    const uint8_t* data = reinterpret_cast<const uint8_t*>(raw_dll.constData());

    auto* dos = reinterpret_cast<const DosHeader*>(data);
    if (dos->e_magic != kDosMagic) {
        m_last_error = ENC("Invalid DOS magic").decrypt();
        return nullptr;
    }

    auto* nt = reinterpret_cast<const NtHeaders64*>(data + dos->e_lfanew);
    if (nt->Signature != kNtSignature) {
        m_last_error = ENC("Invalid NT signature").decrypt();
        return nullptr;
    }

    if (nt->OptionalHeader.Magic != 0x20B) {
        m_last_error = ENC("Not a PE32+ binary").decrypt();
        return nullptr;
    }

    uint32_t image_size = nt->OptionalHeader.SizeOfImage;
    uint32_t headers_size = nt->OptionalHeader.SizeOfHeaders;

    uint8_t* base = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!base) {
        m_last_error = ENC("VirtualAlloc failed for image: ").decrypt() + std::to_string(image_size);
        return nullptr;
    }

    std::memcpy(base, data, headers_size);

    auto* section = reinterpret_cast<const SectionHeader*>(
        data + dos->e_lfanew + sizeof(NtHeaders64));

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (section[i].SizeOfRawData == 0) continue;
        if (section[i].PointerToRawData + section[i].SizeOfRawData >
            static_cast<uint32_t>(raw_dll.size())) {
            VirtualFree(base, 0, MEM_RELEASE);
            m_last_error = ENC("Section extends past end of file").decrypt();
            return nullptr;
        }
        std::memcpy(base + section[i].VirtualAddress,
                    data + section[i].PointerToRawData,
                    section[i].SizeOfRawData);
    }

    ptrdiff_t delta = reinterpret_cast<intptr_t>(base) -
                      static_cast<intptr_t>(nt->OptionalHeader.ImageBase);

    if (delta != 0) {
        if (!relocateImage(base, delta)) {
            VirtualFree(base, 0, MEM_RELEASE);
            m_last_error = ENC("Relocation failed").decrypt();
            return nullptr;
        }
    }

    if (!resolveImports(base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        m_last_error = ENC("Import resolution failed").decrypt();
        return nullptr;
    }

    if (!protectSections(base)) {
        VirtualFree(base, 0, MEM_RELEASE);
        m_last_error = ENC("Section protection failed").decrypt();
        return nullptr;
    }

    m_mapped_base = base;
    m_mapped_size = image_size;
    return base;
}

bool SecureLoader::relocateImage(uint8_t* base, ptrdiff_t delta) {
    auto* dos = reinterpret_cast<DosHeader*>(base);
    auto* nt = reinterpret_cast<NtHeaders64*>(base + dos->e_lfanew);

    if (nt->OptionalHeader.NumberOfRvaAndSizes <= kRelocationDirectoryIndex) return true;

    auto& reloc_dir = nt->OptionalHeader.DataDirectory[kRelocationDirectoryIndex];
    if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) return true;

    auto* block = reinterpret_cast<BaseRelocationBlock*>(
        base + reloc_dir.VirtualAddress);
    auto* end = reinterpret_cast<uint8_t*>(
        base + reloc_dir.VirtualAddress + reloc_dir.Size);

    while (reinterpret_cast<uint8_t*>(block) < end && block->SizeOfBlock >= 8) {
        auto* entries = reinterpret_cast<BaseRelocationEntry*>(
            reinterpret_cast<uint8_t*>(block) + 8);
        uint32_t count = (block->SizeOfBlock - 8) / sizeof(BaseRelocationEntry);

        for (uint32_t i = 0; i < count; ++i) {
            if (entries[i].Type == kIMAGE_REL_BASED_DIR64) {
                auto* patch = reinterpret_cast<uint64_t*>(
                    base + block->VirtualAddress + entries[i].Offset);
                *patch += static_cast<uint64_t>(delta);
            }
        }

        block = reinterpret_cast<BaseRelocationBlock*>(
            reinterpret_cast<uint8_t*>(block) + block->SizeOfBlock);
    }
    return true;
}

bool SecureLoader::resolveImports(uint8_t* base) {
    #ifdef ASTRO_DEBUG_TRACE
    char _itp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _itp); std::string _ilp = std::string(_itp) + "astro_imports.log";
    { FILE* _d = fopen(_ilp.c_str(), "a");
      if (_d) { fprintf(_d, "resolveImports enter base=%p\n", (void*)base); fclose(_d); } }
#endif
    auto* dos = reinterpret_cast<DosHeader*>(base);
    auto* nt = reinterpret_cast<NtHeaders64*>(base + dos->e_lfanew);

    if (nt->OptionalHeader.NumberOfRvaAndSizes <= kImportDirectoryIndex) return true;

    auto& import_dir = nt->OptionalHeader.DataDirectory[kImportDirectoryIndex];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) return true;

    auto* desc = reinterpret_cast<ImportDescriptor*>(base + import_dir.VirtualAddress);

    while (desc->FirstThunk) {
        HMODULE hmod = LoadLibraryA(
            reinterpret_cast<const char*>(base + desc->Name));
        if (!hmod) {
            m_last_error = ENC("Failed to load library: ").decrypt() +
                std::string(reinterpret_cast<const char*>(base + desc->Name));
            #ifdef ASTRO_DEBUG_TRACE
    { FILE* _d = fopen(_ilp.c_str(), "a");
              if (_d) { fprintf(_d, "LoadLibrary fail: %s\n", reinterpret_cast<const char*>(base + desc->Name)); fclose(_d); } }
#endif
            return false;
        }
        #ifdef ASTRO_DEBUG_TRACE
    { FILE* _d = fopen(_ilp.c_str(), "a");
          if (_d) { fprintf(_d, "lib ok: %s\n", reinterpret_cast<const char*>(base + desc->Name)); fclose(_d); } }
#endif

        auto* thunk_ref = reinterpret_cast<uint64_t*>(
            base + desc->OriginalFirstThunk);
        auto* func_ref = reinterpret_cast<uint64_t*>(
            base + desc->FirstThunk);

        if (desc->OriginalFirstThunk == 0) {
            thunk_ref = func_ref;
        }

        for (; *thunk_ref; ++thunk_ref, ++func_ref) {
            FARPROC proc = nullptr;

            if (*thunk_ref & (1ULL << 63)) {
                uint16_t ordinal = static_cast<uint16_t>(*thunk_ref & 0xFFFF);
                proc = GetProcAddress(hmod, MAKEINTRESOURCEA(ordinal));
            } else {
                auto* ibn = reinterpret_cast<ImportByName*>(
                    base + (*thunk_ref & 0x7FFFFFFF));
                proc = GetProcAddress(hmod, ibn->Name);
                if (!proc) {
                    #ifdef ASTRO_DEBUG_TRACE
    { FILE* _d = fopen(_ilp.c_str(), "a");
                      if (_d) { fprintf(_d, "func fail: %s!%s (thunk=0x%llX)\n",
                          reinterpret_cast<const char*>(base + desc->Name), ibn->Name,
                          (unsigned long long)*thunk_ref); fclose(_d); } }
#endif
                }
            }

            if (!proc) {
                m_last_error = ENC("Failed to resolve import").decrypt();
                return false;
            }
            *func_ref = reinterpret_cast<uint64_t>(proc);
        }

        ++desc;
    }
    return true;
}

bool SecureLoader::protectSections(uint8_t* base) {
    auto* dos = reinterpret_cast<DosHeader*>(base);
    auto* nt = reinterpret_cast<NtHeaders64*>(base + dos->e_lfanew);
    auto* section = reinterpret_cast<SectionHeader*>(
        base + dos->e_lfanew + sizeof(NtHeaders64));

    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        DWORD prot = PAGE_READONLY;
        DWORD chars = section[i].Characteristics;

        if (chars & kSectionWriteable) {
            if (chars & kSectionExecutable)
                prot = PAGE_EXECUTE_READWRITE;
            else
                prot = PAGE_READWRITE;
        } else if (chars & kSectionExecutable) {
            prot = PAGE_EXECUTE_READ;
        }

        DWORD old_prot = 0;
        VirtualProtect(base + section[i].VirtualAddress,
                       section[i].VirtualSize, prot, &old_prot);
    }
    return true;
}

void SecureLoader::callEntryPoint(uint8_t* base) {
    auto* dos = reinterpret_cast<DosHeader*>(base);
    auto* nt = reinterpret_cast<NtHeaders64*>(base + dos->e_lfanew);

    if (nt->OptionalHeader.AddressOfEntryPoint == 0) return;

    using DllMainFunc = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    auto* entry = reinterpret_cast<DllMainFunc>(
        base + nt->OptionalHeader.AddressOfEntryPoint);

    HINSTANCE hinst = reinterpret_cast<HINSTANCE>(base);
    entry(hinst, DLL_PROCESS_ATTACH, nullptr);
}

BackendApi SecureLoader::loadBackend(uint64_t current_version) {
    slTrace("LB-ENTER");
    unloadBackend();
    slTrace("LB-UNLOAD-OK");

    try {
        auto manifest = fetchManifest();

        if (manifest.version <= current_version && current_version > 0) {
            m_last_error = ENC("Backend is up to date").decrypt();
            return {};
        }

        QByteArray encrypted_dll = downloadDll(manifest.download_url);
        #ifdef ASTRO_DEBUG_TRACE
    char _iltp[MAX_PATH]{}; GetTempPathA(MAX_PATH, _iltp); std::string _ilp = std::string(_iltp) + "astro_imports.log";
    { FILE* _d = fopen(_ilp.c_str(), "a");
          if (_d) { fprintf(_d, "dll descargada: %lld bytes\n", (long long)encrypted_dll.size()); fclose(_d); } }
#endif

        QByteArray decrypted_dll;
        {
            const uint8_t* raw = reinterpret_cast<const uint8_t*>(
                encrypted_dll.constData());
            size_t raw_size = encrypted_dll.size();

            if (raw_size < 32) {
                m_last_error = ENC("DLL too small to contain header").decrypt();
                return {};
            }

            QByteArray enc_key_input = m_license_key + m_hwid;
            QByteArray enc_key = QCryptographicHash::hash(
                enc_key_input, QCryptographicHash::Sha256);

            uint8_t iv[16]{};
            uint8_t tag[16]{};
            std::memcpy(iv, raw, 16);
            std::memcpy(tag, raw + raw_size - 16, 16);

            const uint8_t* ciphertext = raw + 16;
            size_t ct_len = raw_size - 32;

            BCRYPT_ALG_HANDLE hAlg = nullptr;
            BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0);
            BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);

            BCRYPT_KEY_HANDLE hKey = nullptr;
            BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                reinterpret_cast<PUCHAR>(enc_key.data()), 32, 0);

            BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO aead{};
            BCRYPT_INIT_AUTHENTICATED_CIPHER_MODE_INFO(aead,
                iv, 16, tag, 16);

            decrypted_dll.resize(static_cast<int>(ct_len));
            DWORD cbResult = 0;
            NTSTATUS status = BCryptDecrypt(hKey,
                const_cast<PUCHAR>(ciphertext), static_cast<ULONG>(ct_len),
                &aead, nullptr, 0,
                reinterpret_cast<PUCHAR>(decrypted_dll.data()),
                static_cast<ULONG>(ct_len), &cbResult, 0);

            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);

            if (!BCRYPT_SUCCESS(status)) {
                m_last_error = ENC("AES-GCM decryption failed").decrypt();
                return {};
            }
        }

        slTrace("DL-DEC-DONE");
        slTrace("DL-SHA-START");
        const bool _shaOk = verifySha256(decrypted_dll, manifest.sha256_hex);
        slTrace(_shaOk ? "DL-SHA-OK" : "DL-SHA-BAD");
        if (!_shaOk) {
            m_last_error = ENC("SHA-256 integrity check failed").decrypt();
            return {};
        }

        slTrace("LB-MAP-START");
        void* base = mapDllMemory(decrypted_dll);
        slTrace(base ? "LB-MAP-OK" : "LB-MAP-FAIL");
        if (!base) {
            return {};
        }

        slTrace("LB-EP-START");
        callEntryPoint(static_cast<uint8_t*>(base));
        slTrace("LB-EP-DONE");

        m_dll_module = base;
        m_loaded = true;
        slTrace("LB-LOADED");

        m_api.get_proc = [base](const char* name) -> void* {
            auto* dos = reinterpret_cast<DosHeader*>(base);
            auto* nt = reinterpret_cast<NtHeaders64*>(reinterpret_cast<uint8_t*>(base) + dos->e_lfanew);

            if (nt->OptionalHeader.NumberOfRvaAndSizes == 0) return nullptr;
            auto& exports_dir = nt->OptionalHeader.DataDirectory[0];
            if (exports_dir.VirtualAddress == 0) return nullptr;

            auto* exp = reinterpret_cast<ImageExportDirectory*>(
                reinterpret_cast<uint8_t*>(base) + exports_dir.VirtualAddress);

            DWORD* names = reinterpret_cast<DWORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfNames);
            WORD* ordinals = reinterpret_cast<WORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfNameOrdinals);
            DWORD* functions = reinterpret_cast<DWORD*>(
                reinterpret_cast<uint8_t*>(base) + exp->AddressOfFunctions);

            for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
                const char* n = reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(base) + names[i]);
                if (strcmp(n, name) == 0) {
                    return reinterpret_cast<uint8_t*>(base) + functions[ordinals[i]];
                }
            }
            return nullptr;
        };

        m_api.shutdown = [this]() { unloadBackend(); };

        return m_api;

    } catch (const std::exception& e) {
        m_last_error = e.what();
        return {};
    }
}

void SecureLoader::unloadBackend() {
    if (!m_loaded) return;

    if (m_dll_module) {
        auto* dos = reinterpret_cast<DosHeader*>(m_dll_module);
        auto* nt = reinterpret_cast<NtHeaders64*>(
            static_cast<uint8_t*>(m_dll_module) + dos->e_lfanew);

        using DllMainFunc = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
        auto* entry = reinterpret_cast<DllMainFunc>(
            static_cast<uint8_t*>(m_dll_module) +
            nt->OptionalHeader.AddressOfEntryPoint);

        HINSTANCE hinst = reinterpret_cast<HINSTANCE>(m_dll_module);
        entry(hinst, DLL_PROCESS_DETACH, nullptr);

        VirtualFree(m_dll_module, 0, MEM_RELEASE);
        m_dll_module = nullptr;
    }

    m_loaded = false;
    m_api = {};
}

} // namespace security
} // namespace astro
