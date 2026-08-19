#include "app.h"
#include "http_client_linux.h"
#include "sha256.h"
#include "imgui.h"
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <iomanip>
#include <chrono>
#include <cstring>

using json = nlohmann::json;

namespace {
std::string NowString() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&t, &tmv);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

std::string Repeat(char c, int n) {
    return std::string(size_t(n), c);
}

struct CommentInfo {
    std::string authorName;
    int authorReputation = 0;
    std::string text;
};
}

App::App() {}
App::~App() { if (m_worker.joinable()) m_worker.detach(); }

void App::Init(void* hwnd) {
    m_hwnd = hwnd;
    m_config = LoadConfig();
    strncpy(m_apiKeyBuf, m_config.apiKey.c_str(), sizeof(m_apiKeyBuf) - 1);
    MutateState([&](ScanState& s) {
        s.statusText = T(L(), "ready");
        s.requestsUsed = m_config.requestsUsed;
    });
    if (m_config.apiKey.empty()) m_showApiKeyPopup = true;
}

ScanState App::Snapshot() {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

void App::MutateState(const std::function<void(ScanState&)>& fn) {
    std::lock_guard<std::mutex> lock(m_mutex);
    fn(m_state);
}

void App::DrawUI() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::Begin("##main", nullptr,
                  ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
                  ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_MenuBar);
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu(T(L(), "actions").c_str())) {
            if (ImGui::MenuItem(T(L(), "change_api_key").c_str())) m_showApiKeyPopup = true;
            if (ImGui::MenuItem(T(L(), "settings").c_str())) m_showSettings = true;
            if (ImGui::MenuItem(T(L(), "about").c_str())) m_showAbout = true;
            ImGui::EndMenu();
        }
        ScanState snap = Snapshot();
        ImGui::SameLine(ImGui::GetWindowWidth() - 220);
        ImGui::TextDisabled("%s: %d", T(L(), "requests_used").c_str(), snap.requestsUsed);
        ImGui::EndMenuBar();
    }
    DrawMainWindow();
    ImGui::End();
    if (m_showSettings) DrawSettingsPopup();
    if (m_showApiKeyPopup) DrawApiKeyPopup();
    if (m_showAbout) DrawAboutPopup();
}

void App::DrawMainWindow() {
    ScanState snap = Snapshot();
    float leftWidth = 300.0f;
    ImGui::BeginChild("left_panel", ImVec2(leftWidth, 0), true);
    {
        ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", T(L(), "file_info").c_str());
        ImGui::Separator();
        ImGui::Spacing();
        if (snap.hasFile) {
            ImGui::TextWrapped("%s", snap.fileName.c_str());
            ImGui::Text("%s: %.2f %s", T(L(), "size").c_str(), snap.fileSize / 1024.0, T(L(), "kb").c_str());
            ImGui::TextWrapped("%s: %s", T(L(), "sha256").c_str(), snap.fileHashHex.c_str());
        } else {
            ImGui::TextDisabled("%s", T(L(), "no_file").c_str());
        }
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", T(L(), "actions").c_str());
        ImGui::Separator();
        ImGui::Spacing();
        ImGui::BeginDisabled(snap.scanning);
        if (ImGui::Button(T(L(), "select_file").c_str(), ImVec2(-1, 36))) {
            OpenFileDialogAndScan();
        }
        ImGui::EndDisabled();
        ImGui::BeginDisabled(snap.scanning || !snap.rescanEnabled);
        if (ImGui::Button(T(L(), "rescan").c_str(), ImVec2(-1, 32))) {
            if (!m_currentFilePath.empty()) StartScan(m_currentFilePath, snap.fileName);
        }
        ImGui::EndDisabled();
        ImGui::Spacing();
        if (ImGui::Button(T(L(), "copy_hash").c_str(), ImVec2(-1, 30))) CopyHash();
        if (ImGui::Button(T(L(), "open_in_browser").c_str(), ImVec2(-1, 30))) OpenInBrowser();
        if (ImGui::Button(T(L(), "clear").c_str(), ImVec2(-1, 30))) ClearOutput();
        if (snap.showCheckNowButton) {
            ImGui::Spacing();
            if (ImGui::Button(T(L(), "check_now").c_str(), ImVec2(-1, 32))) CheckNow();
        }
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", T(L(), "status").c_str());
        ImGui::Separator();
        ImGui::TextWrapped("%s", snap.statusText.c_str());
        ImGui::ProgressBar(snap.progress, ImVec2(-1, 20));
    }
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("right_panel", ImVec2(0, 0), true);
    {
        ImGui::TextColored(ImVec4(0.6f, 0.8f, 1.0f, 1.0f), "%s", T(L(), "results").c_str());
        ImGui::Separator();
        ImGui::InputTextMultiline("##output", snap.outputLog.data(), snap.outputLog.size() + 1,
                                   ImVec2(-1, -1),
                                   ImGuiInputTextFlags_ReadOnly);
    }
    ImGui::EndChild();
}

void App::DrawSettingsPopup() {
    ImGui::OpenPopup(T(L(), "settings").c_str());
    ImGui::SetNextWindowSize(ImVec2(420, 380), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal(T(L(), "settings").c_str(), &m_showSettings)) {
        ImGui::Checkbox(T(L(), "topmost").c_str(), &m_config.topmost);
        ImGui::Spacing();
        ImGui::Text("%s", T(L(), "theme").c_str());
        bool isDark = m_config.theme == "dark";
        if (ImGui::RadioButton(T(L(), "dark").c_str(), isDark)) m_config.theme = "dark";
        ImGui::SameLine();
        if (ImGui::RadioButton(T(L(), "light").c_str(), !isDark)) m_config.theme = "light";
        ImGui::Spacing();
        ImGui::Checkbox(T(L(), "sound").c_str(), &m_config.soundOnComplete);
        ImGui::Spacing();
        ImGui::Text("%s", T(L(), "api_type").c_str());
        bool isFree = m_config.apiType == "free";
        if (ImGui::RadioButton(T(L(), "free").c_str(), isFree)) m_config.apiType = "free";
        ImGui::SameLine();
        if (ImGui::RadioButton(T(L(), "paid").c_str(), !isFree)) m_config.apiType = "paid";
        ImGui::Spacing();
        ImGui::Text("%s", T(L(), "language").c_str());
        bool isRu = m_config.lang == "ru";
        if (ImGui::RadioButton(T(L(), "lang_ru").c_str(), isRu)) m_config.lang = "ru";
        ImGui::SameLine();
        if (ImGui::RadioButton(T(L(), "lang_en").c_str(), !isRu)) m_config.lang = "en";
        ImGui::Spacing();
        ImGui::Separator();
        if (ImGui::Button(T(L(), "save").c_str(), ImVec2(120, 32))) {
            SaveConfig(m_config);
            MutateState([&](ScanState& s) { s.statusText = T(L(), "ready"); });
            m_showSettings = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button(T(L(), "cancel").c_str(), ImVec2(120, 32))) {
            m_config = LoadConfig();
            m_showSettings = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void App::DrawApiKeyPopup() {
    ImGui::OpenPopup(T(L(), "api_key_dialog_title").c_str());
    ImGui::SetNextWindowSize(ImVec2(460, 160), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal(T(L(), "api_key_dialog_title").c_str(), &m_showApiKeyPopup)) {
        ImGui::TextWrapped("%s", T(L(), "api_key_dialog_text").c_str());
        ImGui::SetNextItemWidth(-1);
        ImGui::InputText("##apikey", m_apiKeyBuf, sizeof(m_apiKeyBuf), ImGuiInputTextFlags_Password);
        if (ImGui::Button(T(L(), "ok").c_str(), ImVec2(120, 32))) {
            m_config.apiKey = m_apiKeyBuf;
            SaveConfig(m_config);
            MutateState([&](ScanState& s) { s.statusText = T(L(), "api_key_updated"); });
            m_showApiKeyPopup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button(T(L(), "cancel").c_str(), ImVec2(120, 32))) {
            strncpy(m_apiKeyBuf, m_config.apiKey.c_str(), sizeof(m_apiKeyBuf) - 1);
            m_showApiKeyPopup = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void App::DrawAboutPopup() {
    ImGui::OpenPopup(T(L(), "about_program").c_str());
    ImGui::SetNextWindowSize(ImVec2(500, 320), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal(T(L(), "about_program").c_str(), &m_showAbout)) {
        ImGui::TextWrapped("%s", T(L(), "about_text").c_str());
        ImGui::Spacing();
        if (ImGui::Button(T(L(), "ok").c_str(), ImVec2(120, 32))) {
            m_showAbout = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

void App::OpenFileDialogAndScan() {
    if (Snapshot().scanning) return;
    std::string cmd = "zenity --file-selection 2>/dev/null";
    FILE* fp = popen(cmd.c_str(), "r");
    if (!fp) return;
    char buf[4096];
    std::string path;
    if (fgets(buf, sizeof(buf), fp)) {
        path = buf;
        if (!path.empty() && path.back() == '\n') path.pop_back();
    }
    pclose(fp);
    if (path.empty()) return;
    std::wstring wpath(path.begin(), path.end());
    std::string base = path.substr(path.find_last_of("/") + 1);
    StartScan(wpath, base);
}

void App::StartScan(const std::wstring& path, const std::string& fileNameUtf8) {
    if (m_worker.joinable()) m_worker.detach();
    m_currentFilePath = path;
    struct stat st;
    unsigned long long size = 0;
    std::string spath(path.begin(), path.end());
    if (stat(spath.c_str(), &st) == 0) size = st.st_size;
    MutateState([&](ScanState& s) {
        s.hasFile = true;
        s.rescanEnabled = true;
        s.fileName = fileNameUtf8;
        s.fileSize = size;
        s.fileHashHex.clear();
        s.scanning = true;
        s.progress = 0.0f;
        s.showCheckNowButton = false;
        std::ostringstream oss;
        oss << T(L(), "scan_start_header") << "\n" << Repeat('=', 70) << "\n\n"
            << T(L(), "scan_start_note1") << "\n" << T(L(), "scan_start_note2") << "\n\n"
            << T(L(), "hash_calc") << "\n";
        s.outputLog = oss.str();
        s.statusText = T(L(), "hash_calc");
    });
    m_checkNowRequested = false;
    m_worker = std::thread(&App::ScanWorker, this, path, fileNameUtf8);
}

void App::CheckNow() { m_checkNowRequested = true; }

void App::ClearOutput() {
    MutateState([&](ScanState& s) {
        s.outputLog = T(L(), "output_cleared") + "\n";
        s.statusText = T(L(), "ready");
        s.progress = 0.0f;
    });
}

void App::CopyHash() {
    std::string hash = Snapshot().fileHashHex;
    if (!hash.empty()) ImGui::SetClipboardText(hash.c_str());
}

void App::OpenInBrowser() {
    std::string hash = Snapshot().fileHashHex;
    if (hash.empty()) return;
    std::string url = "https://www.virustotal.com/gui/file/" + hash;
    std::string cmd = "xdg-open " + url + " 2>/dev/null &";
    system(cmd.c_str());
}

void App::PlayCompleteSound() {
    if (m_config.soundOnComplete) system("echo -e '\a' 2>/dev/null");
}

void App::BumpRequestsUsed() {
    m_config.requestsUsed++;
    SaveConfig(m_config);
    MutateState([&](ScanState& s) { s.requestsUsed = m_config.requestsUsed; });
}

std::vector<CommentInfo> FetchComments(const std::string& hash, const std::map<std::string, std::string>& headers) {
    std::vector<CommentInfo> out;
    std::string url = "https://www.virustotal.com/api/v3/files/" + hash + "/comments";
    HttpResponse resp = HttpClient::Get(url, headers, 15000);
    if (resp.status != 200) return out;
    try {
        json j = json::parse(resp.body);
        auto arr = j.value("data", json::array());
        int count = 0;
        for (auto& c : arr) {
            if (count++ >= 10) break;
            CommentInfo info;
            info.text = c["attributes"].value("text", "");
            std::string id = c.value("id", "");
            info.authorName = "anonymous";
            if (!id.empty()) {
                std::string authorUrl = "https://www.virustotal.com/api/v3/comments/" + id + "/author";
                HttpResponse ar = HttpClient::Get(authorUrl, headers, 10000);
                if (ar.status == 200) {
                    try {
                        json aj = json::parse(ar.body);
                        auto data = aj.value("data", json::object());
                        info.authorName = data.value("id", info.authorName);
                        info.authorReputation = data.value("attributes", json::object()).value("reputation", 0);
                    } catch (...) {}
                }
            }
            out.push_back(std::move(info));
        }
    } catch (...) {}
    return out;
}

void FetchReputation(const std::string& hash, const std::map<std::string, std::string>& headers,
                      int& reputation, json& totalVotes) {
    reputation = 0;
    totalVotes = json::object();
    std::string url = "https://www.virustotal.com/api/v3/files/" + hash;
    HttpResponse resp = HttpClient::Get(url, headers, 15000);
    if (resp.status != 200) return;
    try {
        json j = json::parse(resp.body);
        auto attrs = j["data"].value("attributes", json::object());
        reputation = attrs.value("reputation", 0);
        totalVotes = attrs.value("total_votes", json::object());
    } catch (...) {}
}

std::string ExtractAnalysisIdFrom409(const std::string& body) {
    try {
        json j = json::parse(body);
        if (j.contains("error") && j["error"].contains("message")) {
            std::string msg = j["error"]["message"].get<std::string>();
            std::smatch m;
            std::regex re1(R"(analysis[=/]([a-zA-Z0-9-]+))");
            if (std::regex_search(msg, m, re1)) return m[1].str();
            std::regex re2(R"(([a-f0-9-]{36}))");
            if (std::regex_search(msg, m, re2)) return m[1].str();
        }
    } catch (...) {}
    return "";
}

std::string BuildResultsText(Lang lang, const std::string& fileName, unsigned long long fileSize,
                              const std::string& fileHash, const json& stats, const json& results,
                              const std::vector<CommentInfo>& comments, int reputation, const json& totalVotes) {
    auto stat = [&](const char* key) -> long long {
        return stats.contains(key) ? stats[key].get<long long>() : 0;
    };
    long long malicious = stat("malicious");
    long long suspicious = stat("suspicious");
    long long undetected = stat("undetected");
    long long harmless = stat("harmless");
    long long timeoutN = stat("timeout");
    long long votesHarmless = totalVotes.contains("harmless") ? totalVotes["harmless"].get<long long>() : 0;
    long long votesMalicious = totalVotes.contains("malicious") ? totalVotes["malicious"].get<long long>() : 0;
    const char* repMark = reputation > 0 ? "(+)" : (reputation < 0 ? "(-)" : "(0)");
    std::ostringstream o;
    o << Repeat('=', 70) << "\n"
      << T(lang, "scan_results_header") << "\n" << Repeat('=', 70) << "\n\n"
      << T(lang, "file_label") << ": " << fileName << "\n"
      << T(lang, "size") << ": " << std::fixed << std::setprecision(2) << (fileSize / 1024.0)
      << " " << T(lang, "kb") << " (" << fileSize << " " << T(lang, "bytes_unit") << ")\n"
      << T(lang, "sha256") << ": " << fileHash << "\n"
      << T(lang, "date_label") << ": " << NowString() << "\n\n"
      << Repeat('=', 70) << "\n"
      << T(lang, "stats") << ":\n"
      << "  " << T(lang, "harmless") << ": " << harmless << "\n"
      << "  " << T(lang, "undetected") << ": " << undetected << "\n"
      << "  " << T(lang, "suspicious") << ": " << suspicious << "\n"
      << "  " << T(lang, "malicious") << ": " << malicious << "\n"
      << "  " << T(lang, "timeout_stats") << ": " << timeoutN << "\n\n"
      << Repeat('=', 70) << "\n"
      << repMark << " " << T(lang, "reputation") << ": " << reputation << "\n"
      << "  " << T(lang, "votes_for") << ": " << votesHarmless << "   "
      << T(lang, "votes_against") << ": " << votesMalicious << "\n"
      << Repeat('=', 70) << "\n\n";
    if (malicious > 0 || suspicious > 0) {
        o << "!! " << T(lang, "threats_detected") << ":\n" << Repeat('-', 70) << "\n";
        long long detected = 0;
        for (auto it = results.begin(); it != results.end(); ++it) {
            const json& res = it.value();
            std::string category = res.value("category", "");
            if (category == "malicious" || category == "suspicious") {
                detected++;
                std::string resultText = res.value("result", T(lang, "unknown_object"));
                std::string method = res.value("method", "unknown");
                std::string engineName = res.value("engine_name", it.key());
                o << "[" << (category == "malicious" ? "M" : "S") << "] " << engineName << " -> " << resultText
                  << "\n    " << T(lang, "method_label") << ": " << method << "\n";
            }
        }
        o << Repeat('-', 70) << "\n" << T(lang, "total_detections") << ": " << detected << "\n";
    } else {
        o << T(lang, "no_detections") << "\n";
    }
    o << "\n" << T(lang, "full_report") << ": https://www.virustotal.com/gui/file/" << fileHash << "\n";
    if (!comments.empty()) {
        o << "\n" << Repeat('=', 70) << "\n" << T(lang, "comments") << " (" << comments.size() << "):\n"
          << Repeat('=', 70) << "\n";
        for (auto& c : comments) {
            o << c.authorName << " (" << (c.authorReputation >= 0 ? "+" : "") << c.authorReputation << "): "
              << c.text << "\n";
        }
    } else {
        o << "\n" << T(lang, "no_comments") << "\n";
    }
    return o.str();
}

void App::ScanWorker(std::wstring path, std::string fileNameUtf8) {
    Lang lang = L();
    std::string apiKey = m_config.apiKey;
    std::map<std::string, std::string> headers = {
        {"x-apikey", apiKey},
        {"accept", "application/json"},
    };
    auto setStatus = [&](const std::string& s) {
        MutateState([&](ScanState& st) { st.statusText = s; });
    };
    auto appendLog = [&](const std::string& s) {
        MutateState([&](ScanState& st) { st.outputLog += s; });
    };
    auto setProgress = [&](float p) {
        MutateState([&](ScanState& st) { st.progress = p; });
    };
    auto finishScanning = [&]() {
        MutateState([&](ScanState& st) { st.scanning = false; st.showCheckNowButton = false; });
    };
    std::string spath(path.begin(), path.end());
    std::string hash = SHA256::hashFile(spath);
    if (hash.empty()) {
        appendLog("\n" + T(lang, "error_fail") + "\n");
        setStatus(T(lang, "error_fail"));
        finishScanning();
        return;
    }
    MutateState([&](ScanState& st) { st.fileHashHex = hash; });
    setStatus(T(lang, "checking_db"));
    setProgress(0.1f);
    std::string reportUrl = "https://www.virustotal.com/api/v3/files/" + hash;
    HttpResponse reportResp = HttpClient::Get(reportUrl, headers, 30000);
    if (reportResp.networkError) {
        appendLog("\n" + T(lang, "error_network") + "\n");
        setStatus(T(lang, "error_network"));
        finishScanning();
        return;
    }
    if (reportResp.status == 200) {
        try {
            json j = json::parse(reportResp.body);
            auto attrs = j["data"].value("attributes", json::object());
            json stats = attrs.value("last_analysis_stats", json::object());
            json results = attrs.value("last_analysis_results", json::object());
            if (!stats.empty()) {
                appendLog(T(lang, "file_found_in_db") + "\n\n");
                auto comments = FetchComments(hash, headers);
                int reputation; json totalVotes;
                FetchReputation(hash, headers, reputation, totalVotes);
                std::string text = BuildResultsText(lang, fileNameUtf8, Snapshot().fileSize, hash,
                                                     stats, results, comments, reputation, totalVotes);
                MutateState([&](ScanState& st) { st.outputLog = text; st.progress = 1.0f;
                                                  st.statusText = T(lang, "ready_report_from_db"); });
                BumpRequestsUsed();
                PlayCompleteSound();
                finishScanning();
                return;
            }
        } catch (...) {}
    }
    setStatus(T(lang, "file_not_in_db"));
    appendLog(T(lang, "uploading") + "\n");
    setProgress(0.3f);
    std::string uploadUrl = "https://www.virustotal.com/api/v3/files";
    HttpResponse uploadResp = HttpClient::PostFile(uploadUrl, headers, spath, "file", fileNameUtf8, 120000);
    std::string analysisId;
    if (uploadResp.networkError) {
        appendLog("\n" + T(lang, "error_network") + "\n");
        setStatus(T(lang, "error_network"));
        finishScanning();
        return;
    } else if (uploadResp.status == 409) {
        analysisId = ExtractAnalysisIdFrom409(uploadResp.body);
        if (analysisId.empty()) {
            appendLog("\n" + T(lang, "error_fail") + "\n");
            setStatus(T(lang, "error_fail"));
            finishScanning();
            return;
        }
    } else if (uploadResp.status == 200) {
        try {
            json j = json::parse(uploadResp.body);
            analysisId = j["data"].value("id", "");
        } catch (...) {}
        if (analysisId.empty()) {
            appendLog("\n" + T(lang, "error_fail") + "\n");
            setStatus(T(lang, "error_fail"));
            finishScanning();
            return;
        }
        appendLog(T(lang, "file_uploaded") + "\n");
    } else {
        std::string msg = T(lang, "error_fail") + " (" + std::to_string(uploadResp.status) + ")";
        appendLog("\n" + msg + "\n");
        setStatus(msg);
        finishScanning();
        return;
    }
    std::string analysisUrl = "https://www.virustotal.com/api/v3/analyses/" + analysisId;
    setProgress(0.4f);
    setStatus(T(lang, "waiting_scan"));
    appendLog(T(lang, "waiting_scan_text") + "\n");
    MutateState([&](ScanState& st) { st.showCheckNowButton = true; });
    const int maxAttempts = 30;
    const int pollSeconds = 15;
    m_checkNowRequested = false;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        for (int waited = 0; waited < pollSeconds * 10; ++waited) {
            if (m_checkNowRequested.exchange(false)) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        float p = 0.4f + std::min(0.55f, attempt * 0.02f);
        setProgress(p);
        HttpResponse ar = HttpClient::Get(analysisUrl, headers, 30000);
        if (ar.status != 200) continue;
        try {
            json j = json::parse(ar.body);
            auto attrs = j["data"].value("attributes", json::object());
            std::string status = attrs.value("status", "unknown");
            if (status == "completed") {
                json stats = attrs.value("stats", json::object());
                json results = attrs.value("results", json::object());
                auto comments = FetchComments(hash, headers);
                int reputation; json totalVotes;
                FetchReputation(hash, headers, reputation, totalVotes);
                std::string text = BuildResultsText(lang, fileNameUtf8, Snapshot().fileSize, hash,
                                                     stats, results, comments, reputation, totalVotes);
                MutateState([&](ScanState& st) {
                    st.outputLog = text;
                    st.progress = 1.0f;
                    st.statusText = T(lang, "scan_complete");
                    st.showCheckNowButton = false;
                });
                BumpRequestsUsed();
                PlayCompleteSound();
                finishScanning();
                return;
            } else {
                std::ostringstream s;
                s << T(lang, "status") << ": [" << status << "] (" << attempt << "/" << maxAttempts << ")";
                setStatus(s.str());
            }
        } catch (...) { continue; }
    }
    appendLog("\n" + T(lang, "timeout_warning") + "\n" + T(lang, "check_later") + ": " + analysisUrl + "\n");
    setStatus(T(lang, "timeout_warning"));
    finishScanning();
}