// SPDX-License-Identifier: Apache-2.0

/* CHIP posts every UDP datagram it receives as an event (queue of
 * CONFIG_MAX_EVENT_QUEUE_SIZE), and a full queue is fatal (ScheduleLambda ->
 * CriticalFailure). A controller on a LAN with many Matter devices gets bursts
 * of Matter mDNS (a commissionable-node browse draws an answer from every
 * device in commissioning mode; 25 virtual devices aborted the gateway).
 * ESP's own filter (ESP32EndpointQueueFilter) drops only non-Matter mDNS. This
 * one applies it, then caps queued multicast mDNS datagrams; mDNS retries cover
 * what is dropped. Only one filter can be installed and ESP re-installs its
 * own on every IPv6 address event, so this one is installed after it. (CHIP's
 * DropIfTooManyQueuedPacketsFilter dies if a packet queued before it was
 * installed is dequeued; this counter saturates instead.) */
#include "controller_priv.h"

#include <atomic>

#include "esp_wifi.h"

#include <inet/UDPEndPointImpl.h>
#include <platform/CHIPDeviceLayer.h>
#include <platform/ESP32/ESP32EndpointQueueFilter.h>

namespace {

constexpr uint16_t kMdnsPort = 5353;

class GatewayQueueFilter : public chip::Inet::EndpointQueueFilter
{
public:
    static constexpr int kMaxQueuedMdns = 12;
    /* All datagrams: bursts of Matter traffic too (27 subscriptions priming at
     * once, each relayed message crossing the loopback bridge) filled the
     * queue. Dropping is recoverable (MRP retransmits); a full queue is not. */
    static constexpr int kMaxQueued = CHIP_DEVICE_CONFIG_MAX_EVENT_QUEUE_SIZE * 2 / 3;

    bool SetHostName(const uint8_t mac[6])
    {
        char name[12];
        static const char hex[] = "0123456789ABCDEF";
        for (int i = 0; i < 6; i++) {
            name[2 * i]     = hex[mac[i] >> 4];
            name[2 * i + 1] = hex[mac[i] & 0xf];
        }
        mEspFilter = mEsp.SetMdnsHostName(chip::CharSpan(name, sizeof(name))) == CHIP_NO_ERROR;
        return mEspFilter;
    }

    FilterOutcome FilterBeforeEnqueue(const void *endpoint, const chip::Inet::IPPacketInfo &pktInfo,
                                      const chip::System::PacketBufferHandle &payload) override
    {
        const bool mdns = pktInfo.DestPort == kMdnsPort;
        if (mdns && mEspFilter && mEsp.FilterBeforeEnqueue(endpoint, pktInfo, payload) == FilterOutcome::kDropPacket) {
            return FilterOutcome::kDropPacket;
        }
        if ((mdns && mQueuedMdns.load() >= kMaxQueuedMdns) || mQueued.load() >= kMaxQueued) {
            return FilterOutcome::kDropPacket;
        }
        mQueued++;
        if (mdns) mQueuedMdns++;
        return FilterOutcome::kAllowPacket;
    }

    FilterOutcome FilterAfterDequeue(const void *, const chip::Inet::IPPacketInfo &pktInfo,
                                     const chip::System::PacketBufferHandle &) override
    {
        Decrement(mQueued);
        if (pktInfo.DestPort == kMdnsPort) Decrement(mQueuedMdns);
        return FilterOutcome::kAllowPacket;
    }

private:
    static void Decrement(std::atomic<int> &c)
    {
        int v = c.load();
        while (v > 0 && !c.compare_exchange_weak(v, v - 1)) {
        }
    }

    chip::Inet::ESP32EndpointQueueFilter mEsp;
    bool mEspFilter = false;
    std::atomic<int> mQueued{0};
    std::atomic<int> mQueuedMdns{0};
};

GatewayQueueFilter sFilter;

} // namespace

void mgw_ctl_install_queue_filter(void)
{
    static bool named;
    uint8_t mac[6];
    if (!named && esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK) named = sFilter.SetHostName(mac);
    chip::Inet::UDPEndPointImpl::SetQueueFilter(&sFilter);
}
