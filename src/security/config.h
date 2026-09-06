#pragma once
#include <QString>
#include <QFile>
#include <QStandardPaths>
#include "security/crypto/string_encrypt.h"
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

namespace astro_config {
    // Domain is now encrypted at compile time - never appears in .rdata
    inline const QString& apiDomain() {
        static const QString domain = [] {
            // SECURITY FIX: config.ini domain override was an unauthenticated MITM vector -
            // any local file write redirected all license traffic (with HWID + keys) elsewhere.
            // Override removed in Release; keep compiled-out hook for local debugging only.
#ifndef ASTRO_ALLOW_DOMAIN_OVERRIDE
            Q_UNUSED(false);
#else
            QFile f(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QString::fromStdString(ENC("/Astro/config.ini").decrypt()));
            if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
                QByteArray line;
                while (!(line = f.readLine()).isEmpty()) {
                    QString s = QString::fromUtf8(line).trimmed();
                    if (s.startsWith(QString::fromStdString(ENC("domain=").decrypt()))) {
                        const QString candidate = s.mid(static_cast<int>(QString::fromStdString(ENC("domain=").decrypt()).size()));
                        if (candidate.endsWith(QStringLiteral(".astro-bots.workers.dev"))) {
                            return candidate;  // allow only sibling workers.dev subdomains
                        }
                    }
                }
            }
#endif
            // Default domain - encrypted, not visible in Ghidra strings window
            return QString::fromStdString(ENC("astro-license.astro-bots.workers.dev").decrypt());
        }();
        return domain;
    }

    inline QString apiBase() {
        static const std::string https = ENC("https://").decrypt();
        return QString::fromStdString(https) + apiDomain();
    }

    inline QString validateUrl() { static const std::string s = ENC("/api/validate").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString activateUrl() { static const std::string s = ENC("/api/activate").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString heartbeatUrl() { static const std::string s = ENC("/api/heartbeat").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString killUrl() { static const std::string s = ENC("/api/kill").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString downloadUrl() { static const std::string s = ENC("/api/download").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString telemetryUrl() { static const std::string s = ENC("/api/telemetry").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString updateUrl() { static const std::string s = ENC("/api/update").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString sessionUrl() { static const std::string s = ENC("/api/session").decrypt(); return apiBase() + QString::fromStdString(s); }
    inline QString sessionValidateUrl() { static const std::string s = ENC("/api/session/validate").decrypt(); return apiBase() + QString::fromStdString(s); }
}
