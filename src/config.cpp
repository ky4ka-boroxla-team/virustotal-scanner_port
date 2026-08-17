#include "config.h"
#include "http_client.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include <nlohmann/json.hpp>

#pragma comment(lib, "shell32.lib")

using json = nlohmann::json;

std::wstring GetConfigDir() {
    PWSTR path = nullptr;
    std::wstring dir;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &path))) {
        dir = path;
        CoTaskMemFree(path);
        dir += L"\\VirusTotalScanner";
    } else {
        dir = L".";
    }
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

std::wstring GetConfigFilePath() {
    return GetConfigDir() + L"\\vt_config.json";
}

static std::string TodayString() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    char buf[16];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
    return buf;
}

AppConfig LoadConfig() {
    AppConfig cfg;
    cfg.requestsResetDate = "";

    std::wstring path = GetConfigFilePath();
    std::ifstream f(path, std::ios::binary);
    if (f.is_open()) {
        try {
            json j;
            f >> j;
            cfg.apiKey = j.value("api_key", cfg.apiKey);
            cfg.topmost = j.value("topmost", cfg.topmost);
            cfg.thanksShown = j.value("thanks_shown", cfg.thanksShown);
            cfg.apiType = j.value("api_type", cfg.apiType);
            cfg.requestsUsed = j.value("requests_used", cfg.requestsUsed);
            cfg.requestsResetDate = j.value("requests_reset_date", cfg.requestsResetDate);
            cfg.lang = j.value("lang", cfg.lang);
            cfg.theme = j.value("theme", cfg.theme);
            cfg.soundOnComplete = j.value("sound_on_complete", cfg.soundOnComplete);
        } catch (...) {
            // Ignore malformed config, fall back to defaults.
        }
    }

    std::string today = TodayString();
    if (cfg.requestsResetDate != today) {
        cfg.requestsUsed = 0;
        cfg.requestsResetDate = today;
        SaveConfig(cfg);
    }
    return cfg;
}

bool SaveConfig(const AppConfig& cfg) {
    json j;
    j["api_key"] = cfg.apiKey;
    j["topmost"] = cfg.topmost;
    j["thanks_shown"] = cfg.thanksShown;
    j["api_type"] = cfg.apiType;
    j["requests_used"] = cfg.requestsUsed;
    j["requests_reset_date"] = cfg.requestsResetDate;
    j["lang"] = cfg.lang;
    j["theme"] = cfg.theme;
    j["sound_on_complete"] = cfg.soundOnComplete;

    std::wstring path = GetConfigFilePath();
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) return false;
    f << j.dump(2);
    return true;
}
