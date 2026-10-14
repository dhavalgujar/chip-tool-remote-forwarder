// SPDX-License-Identifier: Apache-2.0

#include "mgw_server.h"
#include "mgw_log.h"
#include "mgw_server_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#ifndef ESP_PLATFORM
#include <net/if.h> // struct ifreq (lwIP has it in sys/socket.h)
#endif

#include <atomic>

// The server's listening sockets: accepts TCP connections and hands each to
// StartConnection (mgw_server.cpp).

namespace mgw {

namespace {

constexpr size_t kListenStack = 4096;
constexpr int kListenBacklog  = 4;
constexpr int kMaxListeners   = 4;

struct Listener
{
    std::atomic<int> fd{ -1 };
    std::atomic<bool> stop{ false };
};
Listener sListenerSlots[kMaxListeners];

void ListenMain(void * arg)
{
    Listener * self    = static_cast<Listener *>(arg);
    const int listenFd = self->fd;
    while (!self->stop)
    {
        // a timeout, so RemoveListener can stop it without closing a socket
        // another task is blocked on
        fd_set rd;
        FD_ZERO(&rd);
        FD_SET(listenFd, &rd);
        timeval tv = { 1, 0 };
        int n      = select(listenFd + 1, &rd, nullptr, nullptr, &tv);
        if (n == 0 || (n < 0 && errno == EINTR))
        {
            continue;
        }
        sockaddr_in peer;
        socklen_t pl = sizeof(peer);
        int fd       = n > 0 ? accept(listenFd, reinterpret_cast<sockaddr *>(&peer), &pl) : -1;
        if (fd < 0)
        {
            if (errno == EBADF || errno == EINVAL || errno == ENOTSOCK)
            {
                MGW_ERR("accept failed (%d)", errno);
                break;
            }
            // Out of sockets or memory for now (ENFILE, ENOBUFS, ...): wait, don't stop listening.
            if (errno != EINTR && errno != ECONNABORTED)
            {
                MGW_ERR("accept failed (%d), retrying", errno);
                usleep(500 * 1000);
            }
            continue;
        }
        StartConnection(fd);
    }
    close(listenFd);
    self->fd   = -1;
    self->stop = false;
}

} // namespace

// Bound to ifname when given, so lwIP (and Linux) send every packet of its
// connections out of that interface.
int OpenListener(const char * ifname, uint32_t localIp)
{
    Listener * slot = nullptr;
    for (auto & l : sListenerSlots)
    {
        int expected = -1;
        if (l.fd.compare_exchange_strong(expected, -2)) // reserved
        {
            slot = &l;
            break;
        }
    }
    if (slot == nullptr)
    {
        return -1;
    }
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        slot->fd = -1;
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (ifname != nullptr)
    {
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name) - 1);
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) != 0)
        {
            MGW_ERR("can't bind to interface %s (%d)", ifname, errno);
            close(fd);
            slot->fd = -1;
            return -1;
        }
    }
    sockaddr_in a     = {};
    a.sin_family      = AF_INET;
    a.sin_addr.s_addr = localIp;
    a.sin_port        = htons(ServerSettings().port);
    char ip[INET_ADDRSTRLEN] = "";
    if (localIp != 0)
    {
        inet_ntop(AF_INET, &a.sin_addr, ip, sizeof(ip));
    }
    char where[48];
    snprintf(where, sizeof(where), "%s%s%s%s", ifname ? " on " : "", ifname ? ifname : "", localIp ? " at " : "", ip);
    if (bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) != 0 || listen(fd, kListenBacklog) != 0)
    {
        MGW_ERR("can't listen on TCP %u%s (%d)", ServerSettings().port, where, errno);
        close(fd);
        slot->fd = -1;
        return -1;
    }
    slot->stop = false;
    slot->fd   = fd;
    if (!ServerSettings().spawn(ListenMain, slot, "matter_gw_listen", kListenStack))
    {
        close(fd);
        slot->fd = -1;
        return -1;
    }
    MGW_LOG("listening on TCP %u%s", ServerSettings().port, where);
    return static_cast<int>(slot - sListenerSlots);
}

int AddListener(const char * ifname, uint32_t localIp)
{
    return ServerRunning() && ifname != nullptr ? OpenListener(ifname, localIp) : -1;
}

void RemoveListener(int handle)
{
    if (handle >= 0 && handle < kMaxListeners && sListenerSlots[handle].fd >= 0)
    {
        sListenerSlots[handle].stop = true;
    }
}

} // namespace mgw
