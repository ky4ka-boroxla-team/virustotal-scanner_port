#include "http_client_linux.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <fstream>
#include <sstream>
#include <regex>
#include <vector>
#include <random>
#include <cstring>

std::string HttpClient::WideToUtf8(const std::wstring& w) {
    return std::string(w.begin(), w.end());
}

std::wstring HttpClient::Utf8ToWide(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

namespace {
struct UrlParts {
    std::string host;
    std::string path;
    int port = 443;
};

bool ParseUrl(const std::string& url, UrlParts& out) {
    std::regex re(R"(^https://([^:/]+)(?::(\d+))?(/.*)?$)");
    std::smatch m;
    if (!std::regex_match(url, m, re)) return false;
    out.host = m[1];
    out.path = m[3].matched ? m[3].str() : "/";
    out.port = m[2].matched ? std::stoi(m[2]) : 443;
    return true;
}

static bool s_sslInit = false;
static SSL_CTX* s_ctx = nullptr;

void InitSSL() {
    if (!s_sslInit) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        s_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(s_ctx, SSL_VERIFY_NONE, nullptr);
        s_sslInit = true;
    }
}

int ConnectTimeout(const std::string& host, int port, int timeoutMs) {
    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) return -1;
    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return -1; }
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        struct timeval tv = {timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        if (select(sock + 1, nullptr, &fdset, nullptr, &tv) <= 0) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err) {
            close(sock);
            freeaddrinfo(res);
            return -1;
        }
    }
    fcntl(sock, F_SETFL, flags);
    freeaddrinfo(res);
    return sock;
}

std::string ReadResponse(SSL* ssl) {
    std::string response;
    char buf[4096];
    int bytes;
    while ((bytes = SSL_read(ssl, buf, sizeof(buf))) > 0) {
        response.append(buf, bytes);
    }
    return response;
}

int GetStatusCode(const std::string& response) {
    std::regex re(R"(HTTP/\d\.\d (\d+))");
    std::smatch m;
    if (std::regex_search(response, m, re)) return std::stoi(m[1]);
    return 0;
}

std::string BuildRequest(const std::string& method, const std::string& path,
                          const std::map<std::string, std::string>& headers,
                          const std::string& body = "") {
    std::ostringstream req;
    req << method << " " << path << " HTTP/1.1\r\n";
    for (const auto& h : headers) {
        req << h.first << ": " << h.second << "\r\n";
    }
    req << "Connection: close\r\n";
    req << "Content-Length: " << body.size() << "\r\n";
    req << "\r\n";
    req << body;
    return req.str();
}
}

HttpResponse HttpClient::Get(const std::string& url,
                              const std::map<std::string, std::string>& headers,
                              int timeoutMs) {
    HttpResponse result;
    UrlParts parts;
    if (!ParseUrl(url, parts)) { result.networkError = true; return result; }
    InitSSL();
    int sock = ConnectTimeout(parts.host, parts.port, timeoutMs);
    if (sock < 0) { result.networkError = true; return result; }
    SSL* ssl = SSL_new(s_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        result.networkError = true;
        return result;
    }
    auto h = headers;
    h["Host"] = parts.host;
    std::string req = BuildRequest("GET", parts.path, h);
    SSL_write(ssl, req.c_str(), req.size());
    std::string response = ReadResponse(ssl);
    SSL_free(ssl);
    close(sock);
    size_t pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        result.status = GetStatusCode(response);
        result.body = response.substr(pos + 4);
    }
    return result;
}

HttpResponse HttpClient::PostFile(const std::string& url,
                                   const std::map<std::string, std::string>& headers,
                                   const std::string& filePath,
                                   const std::string& fieldName,
                                   const std::string& fileNameUtf8,
                                   int timeoutMs) {
    HttpResponse result;
    UrlParts parts;
    if (!ParseUrl(url, parts)) { result.networkError = true; return result; }
    std::ifstream file(filePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) { result.networkError = true; return result; }
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    std::random_device rd;
    std::mt19937_64 rng(rd());
    char boundary[64];
    snprintf(boundary, sizeof(boundary), "----VTScanner%016llx", (unsigned long long)rng());
    std::string preamble = "--" + std::string(boundary) + "\r\n" +
        "Content-Disposition: form-data; name=\"" + fieldName + "\"; filename=\"" + fileNameUtf8 + "\"\r\n" +
        "Content-Type: application/octet-stream\r\n\r\n";
    std::string epilogue = "\r\n--" + std::string(boundary) + "--\r\n";
    std::string body;
    body.reserve(preamble.size() + fileSize + epilogue.size());
    body += preamble;
    std::vector<char> buf(8192);
    while (file.good()) {
        file.read(buf.data(), buf.size());
        std::streamsize got = file.gcount();
        if (got > 0) body.append(buf.data(), got);
    }
    body += epilogue;
    InitSSL();
    int sock = ConnectTimeout(parts.host, parts.port, timeoutMs);
    if (sock < 0) { result.networkError = true; return result; }
    SSL* ssl = SSL_new(s_ctx);
    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        close(sock);
        result.networkError = true;
        return result;
    }
    auto h = headers;
    h["Host"] = parts.host;
    h["Content-Type"] = "multipart/form-data; boundary=" + std::string(boundary);
    std::string req = BuildRequest("POST", parts.path, h, body);
    SSL_write(ssl, req.c_str(), req.size());
    std::string response = ReadResponse(ssl);
    SSL_free(ssl);
    close(sock);
    size_t pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        result.status = GetStatusCode(response);
        result.body = response.substr(pos + 4);
    }
    return result;
}