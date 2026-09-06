#pragma once
#include <string>

namespace astro { namespace security {

// Blocking HTTPS POST (JSON) with hard timeout. Returns HTTP status (200=OK), 0 on failure.
int winhttpPostJson(const std::string& apiBase,
                    const std::string& path,
                    const std::string& body,
                    const std::string& tsHeader,
                    const std::string& sigHeader,
                    std::string& responseOut,
                    int timeoutMs);

// Blocking HTTPS GET (binary). Returns HTTP status (200=OK), 0 on failure.
int winHttpGetBin(const std::string& url,
                  std::string& responseOut,
                  int timeoutMs);

}} // namespace
