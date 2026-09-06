#pragma once
#include <string>
namespace vercheck { std::string parseAstroSha256(const std::string& resp); std::string sha256FileHex(const std::wstring& path); bool isCacheStale(const std::wstring& exePath, const std::string& serverSha); }
