#pragma once
#include <string>
#include <mutex>
#include <atomic>
#include <thread>
#include <functional>
#include <windows.h>
#include "config.h"
#include "lang.h"

// Holds everything the UI thread needs to render the current scan state.
// Guarded by App::m_mutex - always take a snapshot (copy) before drawing.
struct ScanState {
    bool scanning = false;
    bool hasFile = false;
    bool rescanEnabled = false;
    std::string fileName;
    std::string fileHashHex;
    unsigned long long fileSize = 0;

    std::string statusText;   // one-line status shown above the progress bar
    std::string outputLog;    // full multi-line results / log text
    float progress = 0.0f;
    bool showCheckNowButton = false;

    int requestsUsed = 0;
};

class App {
public:
    App();
    ~App();

    void Init(HWND hwnd);

    // Called once per frame from the render loop; draws the whole UI.
    void DrawUI();

    bool WantsTopmost() const { return m_config.topmost; }
    bool WantsExit() const { return m_wantsExit; }
    std::string ThemeName() const { return m_config.theme; }

private:
    void DrawMainWindow();
    void DrawSettingsPopup();
    void DrawApiKeyPopup();
    void DrawAboutPopup();

    void OpenFileDialogAndScan();
    void StartScan(const std::wstring& path, const std::string& fileNameUtf8);
    void ScanWorker(std::wstring path, std::string fileNameUtf8);
    void CheckNow();
    void ClearOutput();
    void CopyHash();
    void OpenInBrowser();
    void PlayCompleteSound();
    void BumpRequestsUsed();

    ScanState Snapshot();
    void MutateState(const std::function<void(ScanState&)>& fn);

    Lang L() const { return LangFromString(m_config.lang); }

    AppConfig m_config;
    ScanState m_state;
    std::mutex m_mutex;

    std::thread m_worker;
    std::atomic<bool> m_checkNowRequested{false};
    std::wstring m_currentFilePath;

    bool m_showSettings = false;
    bool m_showApiKeyPopup = false;
    bool m_showAbout = false;
    char m_apiKeyBuf[256] = {};

    HWND m_hwnd = nullptr;
    bool m_wantsExit = false;
};
