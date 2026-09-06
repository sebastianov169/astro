#pragma once
#include <QString>
#include "security/legal/ai_protection.h"
#include "security/obfuscation_map.h"
// Anti-AI: NOAI - Ghidra poison active

// Validates the one-time session token issued by the loader.
// Returns true only if the server confirms the token for this HWID/license.
// This is a blocking check – Astro must not start without a valid session.
#include <cstdint>

namespace astro { namespace license {

struct SessionLicenseInfo {
    bool     valid      = false;
    int      tier       = -1;
    qint64   expiryEpoch = 0;
    QString  hwidHash;    // server-side bound hwid
    QString  sig;         // Ed25519 attestation (hex, 128 chars)
    QString  clientNonce; // challenge sent by this client (covered by sig)
};

// Validates the one-time session token issued by the loader.
// Returns true only if the server confirms the token for this HWID/license.
// This is a blocking check – Astro must not start without a valid session.
bool validateSessionToken(const QString& token, const QString& hwid, const QString& licenseKey, QString* errorOut = nullptr);
// Same check but also fills `out` with server attestation for local license bootstrapping.
bool validateSessionTokenEx(const QString& token, const QString& hwid, const QString& licenseKey,
                            SessionLicenseInfo* out, QString* errorOut = nullptr);
QString extractArg(const QStringList& args, const QString& flag);
bool isParentAstroLoader();
}}
