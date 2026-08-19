// Minimal HTTPS client built on WinHTTP - no external dependencies.
#pragma once
#include <string>
#include <vector>
#include <map>

struct HttpResponse {
    int status = 0;
    std::string body;
    bool networkError = false; // true when the request could not reach the server at all
    bool timedOut = false;
};

class HttpClient {
public:
    // Simple GET with headers of the form "Name: Value".
    static HttpResponse Get(const std::wstring& url,
                             const std::map<std::wstring, std::wstring>& headers,
                             int timeoutMs = 30000);

    // multipart/form-data POST uploading a single file under the given field name.
    static HttpResponse PostFile(const std::wstring& url,
                                  const std::map<std::wstring, std::wstring>& headers,
                                  const std::wstring& filePath,
                                  const std::string& fieldName,
                                  const std::string& fileNameUtf8,
                                  int timeoutMs = 60000);

    static std::string WideToUtf8(const std::wstring& w);
    static std::wstring Utf8ToWide(const std::string& s);
};
