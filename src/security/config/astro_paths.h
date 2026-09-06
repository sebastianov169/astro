#pragma once
// astro_paths.h - FUENTE UNICA de nombres del producto.
// Cambiar las macros KEY de abajo propaga el rename a todo el autokill.
// Los literales viajan cifrados (ENC) para no dejar strings en claro.

#include <QString>
#include <string>
#include "security/crypto/string_encrypt.h"

namespace astro {
namespace security {
namespace paths {

// --- Nombres base (editar SOLO aqui) ---
#define ASTRO_APP_DIR_KEY     "astro_app"        // %TEMP%\<appdir>
#define ASTRO_EXE_KEY         "Astro.exe"
#define ASTRO_LOADER_EXE_KEY  "AstroLoader.exe"
#define ASTRO_PACKAGE_ZIP_KEY "astro_package.zip"

#define ASTRO_LICENSE_DAT_KEY "license.dat"
#define ASTRO_SESSION_TOK_KEY "session.token"
#define ASTRO_DATA_SUBDIR_KEY "Astro"   // %LOCALAPPDATA%\<data_subdir> (license.dat)

inline QString appDirName()        { return QString::fromStdString(ENC(ASTRO_APP_DIR_KEY).decrypt()); }
inline QString exeName()           { return QString::fromStdString(ENC(ASTRO_EXE_KEY).decrypt()); }
inline QString loaderExe()         { return QString::fromStdString(ENC(ASTRO_LOADER_EXE_KEY).decrypt()); }
inline QString packageZip()        { return QString::fromStdString(ENC(ASTRO_PACKAGE_ZIP_KEY).decrypt()); }
inline QString licenseDatNameSafe(){ return QString::fromStdString(ENC(ASTRO_LICENSE_DAT_KEY).decrypt()); }
inline QString sessionTokenNameSafe(){ return QString::fromStdString(ENC(ASTRO_SESSION_TOK_KEY).decrypt()); }
inline QString dataSubdir()        { return QString::fromStdString(ENC(ASTRO_DATA_SUBDIR_KEY).decrypt()); }

// Patrones heuristicos (case-insensitive contains) para barridos forenses.
inline QString patternRoot()  { return QString::fromStdString(ENC("astro").decrypt()); }
inline QString patternSess()  { return QString::fromStdString(ENC("session").decrypt()); }
inline QString patternLic()   { return QString::fromStdString(ENC("license").decrypt()); }
inline QString patternTok()   { return QString::fromStdString(ENC("token").decrypt()); }

} // namespace paths
} // namespace security
} // namespace astro
