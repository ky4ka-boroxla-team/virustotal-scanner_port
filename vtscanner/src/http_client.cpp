#include "http_client.h"
#include <windows.h>
#include <winhttp.h>
#include <fstream>
#include <sstream>
#include <random>

#pragma comment(lib, "winhttp.lib")

std::string HttpClient::WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int size = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), size, nullptr, nullptr);
    return out;
}

std::wstring HttpClient::Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int size = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), size);
    return out;
}

namespace {

struct UrlParts {
    std::wstring host;
    std::wstring path; // includes query
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
    bool secure = true;
};

bool CrackUrl(const std::wstring& url, UrlParts& out) {
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t hostBuf[512]{};
    wchar_t pathBuf[4096]{};
    uc.lpszHostName = hostBuf;
    uc.dwHostNameLength = 512;
    uc.lpszUrlPath = pathBuf;
    uc.dwUrlPathLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.size(), 0, &uc)) return false;
    out.host = hostBuf;
    out.path = pathBuf;
    out.port = uc.nPort;
    out.secure = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    return true;
}

// Reads the full response body from an already-sent, response-received request handle.
std::string ReadBody(HINTERNET hRequest) {
    std::string body;
    DWORD avail = 0;
    do {
        avail = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &avail)) break;
        if (avail == 0) break;
        std::vector<char> buf(avail);
        DWORD read = 0;
        if (!WinHttpReadData(hRequest, buf.data(), avail, &read)) break;
        body.append(buf.data(), read);
    } while (avail > 0);
    return body;
}

int QueryStatusCode(HINTERNET hRequest) {
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                         WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    return (int)statusCode;
}

std::wstring BuildHeaderBlock(const std::map<std::wstring, std::wstring>& headers) {
    std::wstring block;
    for (const auto& kv : headers) {
        block += kv.first + L": " + kv.second + L"\r\n";
    }
    return block;
}

} // namespace

HttpResponse HttpClient::Get(const std::wstring& url,
                              const std::map<std::wstring, std::wstring>& headers,
                              int timeoutMs) {
    HttpResponse result;
    UrlParts parts;
    if (!CrackUrl(url, parts)) { result.networkError = true; return result; }

    HINTERNET hSession = WinHttpOpen(L"VirusTotalScanner/3.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { result.networkError = true; return result; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parts.host.c_str(), parts.port, 0);
    if (!hConnect) { result.networkError = true; WinHttpCloseHandle(hSession); return result; }

    DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", parts.path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { result.networkError = true; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    std::wstring headerBlock = BuildHeaderBlock(headers);
    if (!headerBlock.empty()) {
        WinHttpAddRequestHeaders(hRequest, headerBlock.c_str(), (DWORD)headerBlock.size(),
                                  WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (sent) {
        BOOL received = WinHttpReceiveResponse(hRequest, nullptr);
        if (received) {
            result.status = QueryStatusCode(hRequest);
            result.body = ReadBody(hRequest);
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_WINHTTP_TIMEOUT) result.timedOut = true; else result.networkError = true;
        }
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_TIMEOUT) result.timedOut = true; else result.networkError = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}

HttpResponse HttpClient::PostFile(const std::wstring& url,
                                   const std::map<std::wstring, std::wstring>& headers,
                                   const std::wstring& filePath,
                                   const std::string& fieldName,
                                   const std::string& fileNameUtf8,
                                   int timeoutMs) {
    HttpResponse result;
    UrlParts parts;
    if (!CrackUrl(url, parts)) { result.networkError = true; return result; }

    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) { result.networkError = true; return result; }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    // Random multipart boundary.
    std::mt19937_64 rng(std::random_device{}());
    char boundary[48];
    snprintf(boundary, sizeof(boundary), "----VTScannerBoundary%016llx", (unsigned long long)rng());

    std::string preamble = "--" + std::string(boundary) + "\r\n" +
        "Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + fileNameUtf8 + "\"\r\n" +
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string epilogue = "\r\n--" + std::string(boundary) + "--\r\n";

    DWORD totalLen = (DWORD)(preamble.size() + fileSize + epilogue.size());

    HINTERNET hSession = WinHttpOpen(L"VirusTotalScanner/3.0",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { result.networkError = true; return result; }
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    HINTERNET hConnect = WinHttpConnect(hSession, parts.host.c_str(), parts.port, 0);
    if (!hConnect) { result.networkError = true; WinHttpCloseHandle(hSession); return result; }

    DWORD flags = parts.secure ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", parts.path.c_str(), nullptr,
                                             WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) { result.networkError = true; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return result; }

    std::map<std::wstring, std::wstring> allHeaders = headers;
    allHeaders[L"Content-Type"] = L"multipart/form-data; boundary=" + Utf8ToWide(boundary);
    std::wstring headerBlock = BuildHeaderBlock(allHeaders);
    WinHttpAddRequestHeaders(hRequest, headerBlock.c_str(), (DWORD)headerBlock.size(), WINHTTP_ADDREQ_FLAG_ADD);

    BOOL sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                    WINHTTP_NO_REQUEST_DATA, 0, totalLen, 0);
    if (!sent) {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_TIMEOUT) result.timedOut = true; else result.networkError = true;
        WinHttpCloseHandle(hRequest); WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession);
        return result;
    }

    DWORD written = 0;
    WinHttpWriteData(hRequest, preamble.data(), (DWORD)preamble.size(), &written);

    std::vector<char> buf(1 << 16);
    while (file.good() && fileSize > 0) {
        file.read(buf.data(), buf.size());
        std::streamsize got = file.gcount();
        if (got <= 0) break;
        WinHttpWriteData(hRequest, buf.data(), (DWORD)got, &written);
    }

    WinHttpWriteData(hRequest, epilogue.data(), (DWORD)epilogue.size(), &written);

    BOOL received = WinHttpReceiveResponse(hRequest, nullptr);
    if (received) {
        result.status = QueryStatusCode(hRequest);
        result.body = ReadBody(hRequest);
    } else {
        DWORD err = GetLastError();
        if (err == ERROR_WINHTTP_TIMEOUT) result.timedOut = true; else result.networkError = true;
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return result;
}
