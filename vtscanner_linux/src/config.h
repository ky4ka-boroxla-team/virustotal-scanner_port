#pragma once
#include <string>

struct AppConfig {
    std::string apiKey;
    bool topmost = false;
    bool thanksShown = false;
    std::string apiType = "free";
    int  requestsUsed = 0;
    std::string requestsResetDate;
    std::string lang = "ru";
    std::string theme = "dark";
    bool soundOnComplete = true;
};

std::string GetConfigDir();
std::string GetConfigFilePath();
AppConfig LoadConfig();
bool SaveConfig(const AppConfig& cfg);