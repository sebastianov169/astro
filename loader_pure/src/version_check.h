#pragma once
#include <cstdint>
#include <string>
#include <vector>
namespace vercheck {
std::string parseShaField(const std::string& resp, const std::string& field);
std::string parseAstroSha256(const std::string& resp);
std::string parseLoaderSha256(const std::string& resp);
std::string parsePackageSha256(const std::string& resp);
std::string sha256FileHex(const std::wstring& path);
std::string sha256BytesHex(const std::vector<uint8_t>& data);
bool isCacheStale(const std::wstring& exePath, const std::string& serverSha);
}
