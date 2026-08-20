#pragma once
#include <string>
#include <map>

struct HttpResponse {
    int status = 0;
    std::string body;
    bool networkError = false;
    bool timedOut = false;
};

class HttpClient {
public:
    static HttpResponse Get(const std::string& url,
                             const std::map<std::string, std::string>& headers,
                             int timeoutMs = 30000);
    static HttpResponse PostFile(const std::string& url,
                                  const std::map<std::string, std::string>& headers,
                                  const std::string& filePath,
                                  const std::string& fieldName,
                                  const std::string& fileNameUtf8,
                                  int timeoutMs = 60000);
    static std::string WideToUtf8(const std::wstring& w);
    static std::wstring Utf8ToWide(const std::string& s);
};