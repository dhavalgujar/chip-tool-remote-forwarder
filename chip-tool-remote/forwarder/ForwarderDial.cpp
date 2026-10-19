// SPDX-License-Identifier: Apache-2.0

#include "ForwarderDial.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>

namespace ForwarderClient {

namespace {

using Clock = std::chrono::steady_clock;

constexpr size_t kMaxProxyResponse = 8192;

int MsLeft(Clock::time_point deadline)
{
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return ms < 0 ? 0 : static_cast<int>(ms);
}

std::string PercentDecode(const std::string & s)
{
    std::string o;
    for (size_t i = 0; i < s.size(); i++)
    {
        if (s[i] == '%' && i + 2 < s.size() && isxdigit(static_cast<unsigned char>(s[i + 1])) &&
            isxdigit(static_cast<unsigned char>(s[i + 2])))
        {
            char b[3] = { s[i + 1], s[i + 2], 0 };
            o.push_back(static_cast<char>(strtoul(b, nullptr, 16)));
            i += 2;
        }
        else
        {
            o.push_back(s[i]);
        }
    }
    return o;
}

std::string Base64(const std::string & in)
{
    static const char k[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string o;
    size_t i = 0;
    for (; i + 2 < in.size(); i += 3)
    {
        uint32_t v = (static_cast<uint8_t>(in[i]) << 16) | (static_cast<uint8_t>(in[i + 1]) << 8) | static_cast<uint8_t>(in[i + 2]);
        o += k[v >> 18];
        o += k[(v >> 12) & 63];
        o += k[(v >> 6) & 63];
        o += k[v & 63];
    }
    if (i < in.size())
    {
        uint32_t v = static_cast<uint8_t>(in[i]) << 16;
        if (i + 1 < in.size())
            v |= static_cast<uint8_t>(in[i + 1]) << 8;
        o += k[v >> 18];
        o += k[(v >> 12) & 63];
        o += i + 1 < in.size() ? k[(v >> 6) & 63] : '=';
        o += '=';
    }
    return o;
}

bool WriteAll(int fd, const uint8_t * p, size_t n)
{
    while (n > 0)
    {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

std::string ProxySetting()
{
    for (const char * k : { "CHIP_TOOL_REMOTE_PROXY", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy" })
    {
        const char * v = getenv(k);
        if (v != nullptr && *v != '\0')
            return v;
    }
    return "";
}

} // namespace

bool SplitHostPort(const std::string & s, std::string & host, uint16_t & port, uint16_t defaultPort)
{
    std::string h = s, p;
    if (!s.empty() && s[0] == '[')
    {
        size_t close = s.find(']');
        if (close == std::string::npos)
            return false;
        h = s.substr(1, close - 1);
        if (close + 1 < s.size())
        {
            if (s[close + 1] != ':')
                return false;
            p = s.substr(close + 2);
        }
    }
    else
    {
        size_t colon = s.rfind(':');
        if (colon != std::string::npos && s.find(':') == colon)
        {
            h = s.substr(0, colon);
            p = s.substr(colon + 1);
        }
    }
    if (h.empty())
        return false;
    unsigned long n = defaultPort;
    if (!p.empty())
    {
        char * end = nullptr;
        n          = strtoul(p.c_str(), &end, 10);
        if (*end != '\0' || n == 0 || n > 65535)
            return false;
    }
    if (n == 0)
        return false;
    host = h;
    port = static_cast<uint16_t>(n);
    return true;
}

std::string HostPort(const std::string & host, uint16_t port)
{
    bool v6 = host.find(':') != std::string::npos;
    return (v6 ? "[" + host + "]" : host) + ":" + std::to_string(port);
}

int DialTcp(const std::string & host, uint16_t port, int timeoutMs)
{
    addrinfo hints = {};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo * res    = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
        return -1;
    int fd             = -1;
    auto deadline      = Clock::now() + std::chrono::milliseconds(timeoutMs);
    for (addrinfo * a = res; a != nullptr && fd < 0; a = a->ai_next)
    {
        fd = socket(a->ai_family, a->ai_socktype | SOCK_CLOEXEC, a->ai_protocol);
        if (fd < 0)
            continue;
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int rc = connect(fd, a->ai_addr, a->ai_addrlen);
        if (rc != 0 && errno == EINPROGRESS)
        {
            pollfd p = { fd, POLLOUT, 0 };
            rc       = poll(&p, 1, MsLeft(deadline)) == 1 ? 0 : -1;
            int err  = 0;
            socklen_t l = sizeof(err);
            if (rc == 0 && (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &l) != 0 || err != 0))
                rc = -1;
        }
        if (rc != 0)
        {
            close(fd);
            fd = -1;
            continue;
        }
        fcntl(fd, F_SETFL, flags);
    }
    freeaddrinfo(res);
    return fd;
}

int DialProxy(const std::string & target, int timeoutMs, std::string & why, ForwarderStream::Failure & kind)
{
    kind            = ForwarderStream::Failure::kOther;
    std::string raw = ProxySetting();
    if (raw.empty())
    {
        why = "no CONNECT proxy configured (CHIP_TOOL_REMOTE_PROXY or HTTPS_PROXY)";
        return -1;
    }
    std::string rest = raw;
    size_t scheme    = rest.find("://");
    if (scheme != std::string::npos)
    {
        if (rest.compare(0, scheme, "http") != 0)
        {
            why = "the CONNECT proxy must be an http:// URL";
            return -1;
        }
        rest = rest.substr(scheme + 3);
    }
    rest = rest.substr(0, rest.find('/'));
    std::string auth;
    size_t at = rest.rfind('@');
    if (at != std::string::npos)
    {
        std::string userinfo = rest.substr(0, at);
        rest                 = rest.substr(at + 1);
        size_t colon         = userinfo.find(':');
        std::string user     = PercentDecode(userinfo.substr(0, colon));
        std::string pw       = colon == std::string::npos ? "" : PercentDecode(userinfo.substr(colon + 1));
        auth                 = Base64(user + ":" + pw);
    }
    std::string phost;
    uint16_t pport = 0;
    if (!SplitHostPort(rest, phost, pport, 80))
    {
        why = "the CONNECT proxy setting is not a URL";
        return -1;
    }
    int c = DialTcp(phost, pport, timeoutMs);
    if (c < 0)
    {
        why = "can't reach the CONNECT proxy";
        return -1;
    }
    std::string req = "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n";
    if (!auth.empty())
        req += "Proxy-Authorization: Basic " + auth + "\r\n";
    req += "\r\n";
    bool ok = WriteAll(c, reinterpret_cast<const uint8_t *>(req.data()), req.size());
    std::fill(req.begin(), req.end(), '\0');
    std::fill(auth.begin(), auth.end(), '\0');
    if (!ok)
    {
        close(c);
        why = "CONNECT request failed";
        return -1;
    }
    // The response headers, byte by byte: nothing past them may be consumed.
    std::string resp;
    auto deadline = Clock::now() + std::chrono::milliseconds(timeoutMs);
    while (resp.size() < kMaxProxyResponse && (resp.size() < 4 || resp.compare(resp.size() - 4, 4, "\r\n\r\n") != 0))
    {
        pollfd p = { c, POLLIN, 0 };
        char b;
        if (poll(&p, 1, MsLeft(deadline)) != 1 || recv(c, &b, 1, 0) != 1)
        {
            close(c);
            why  = "no answer from the CONNECT proxy";
            kind = ForwarderStream::Failure::kUnreachable;
            return -1;
        }
        resp.push_back(b);
    }
    int status = 0;
    if (sscanf(resp.c_str(), "HTTP/%*d.%*d %d", &status) != 1 || status != 200)
    {
        close(c);
        why  = "the CONNECT proxy refused " + target + ": " + std::to_string(status);
        kind = status == 407 ? ForwarderStream::Failure::kProxyAuth : ForwarderStream::Failure::kProxyRefused;
        return -1;
    }
    return c;
}

} // namespace ForwarderClient
