#pragma once
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <vector>
#include <chrono>
#include "config.h"
#include "lang.h"

struct ScanState {
    bool scanning = false;
    bool hasFile = false;
    bool rescanEnabled = false;
    std::string fileName;
    std::string fileHashHex;
    unsigned long long fileSize = 0;
    std::string statusText;
    std::string outputLog;
    float progress = 0.0f;
    bool showCheckNowButton = false;
    int requestsUsed = 0;
};

struct BrowserEntry {
    std::string name;
    bool isDir = false;
};

class App {
public:
    App();
    ~App();
    void Init(void* hwnd);
    void DrawUI();
    void OnFileDropped(const std::string& utf8Path);
    bool WantsTopmost() const { return m_config.topmost; }
    bool WantsExit() const { return m_wantsExit; }
    std::string ThemeName() const { return m_config.theme; }

private:
    void DrawMainWindow();
    void DrawSettingsPopup();
    void DrawApiKeyPopup();
    void DrawAboutPopup();
    void DrawFileBrowserPopup();
    void OpenFileDialogAndScan();
    void OpenBuiltinFileBrowser();
    void RefreshBrowserEntries();
    void StartScan(const std::wstring& path, const std::string& fileNameUtf8);
    void ScanWorker(std::wstring path, std::string fileNameUtf8);
    void CheckNow();
    void ClearOutput();
    void CopyHash();
    void OpenInBrowser();
    void PlayCompleteSound();
    void BumpRequestsUsed();
    bool IsRateLimited(int& secondsLeft);
    ScanState Snapshot();
    void MutateState(const std::function<void(ScanState&)>& fn);
    Lang L() const { return LangFromString(m_config.lang); }

    AppConfig m_config;
    ScanState m_state;
    std::mutex m_mutex;
    std::thread m_worker;
    std::atomic<bool> m_checkNowRequested{false};
    std::atomic<bool> m_shuttingDown{false};
    std::wstring m_currentFilePath;
    bool m_showSettings = false;
    bool m_showApiKeyPopup = false;
    bool m_showAbout = false;
    char m_apiKeyBuf[256] = {};
    void* m_hwnd = nullptr;
    bool m_wantsExit = false;

    bool m_showFileBrowser = false;
    std::string m_browserCurrentDir;
    std::string m_browserSelected;
    std::vector<BrowserEntry> m_browserEntries;

    std::vector<std::chrono::steady_clock::time_point> m_requestTimes;
};