# esp32_matter_gateway

A Matter gateway for `chip-tool-gw` (CHIP's chip-tool with the gateway's
client, in this repository's `chip-tool-gw/`).

- `chip-tool-gw` reaches every Matter device through this device, over one TLS
  stream (TCP 7401).
- The device relays the messages onto its own secure sessions with the
  devices, over Wi-Fi or Thread.
- The fabric's CA is `chip-tool-gw`'s: the device enrolls once
  (`matter.enroll`), then has `chip-tool-gw` verify and sign every device it
  commissions.

## Use

```c
#include "esp32_matter_gateway.h"

// At boot, once Wi-Fi (the default station netif) is started:
const esp32_matter_gateway_config_t gateway = {
    .setup_complete = true, // Bluetooth is CHIP's from now on
    .listen_netif   = NULL, // chip-tool-gw connects from the local network
};
esp32_matter_gateway_init(&gateway);

// On a channel you trust (never the network): the endpoint and secret
// chip-tool-gw connects with, and its release (client, this component's
// version).
cJSON *r = esp32_matter_gateway_connect(NULL);
```

- **Wi-Fi:** the application connects the station (`WIFI_STA_DEF`); the
  gateway uses that connection and never configures Wi-Fi itself.
- **Bluetooth** is shared with the application, one at a time:
  - `setup_complete` false: the application still uses Bluetooth for its own
    setup (for example, pairing with its owner). Matter doesn't start, and the
    `matter` partition is erased, so a new owner starts clean.
  - When its setup finishes, the application calls
    `esp32_matter_gateway_setup_done()`; the device restarts shortly after.
  - `setup_complete` true: CHIP uses Bluetooth from `init` on, to commission
    new devices.
- **`listen_netif`** can be a tunnel's lwIP netif (two letters, for example
  `"tn"`). The port is then reachable only through that netif, at the
  station's address.
- **`esp32_matter_gateway_erase()`** is for the application's own reset: it
  forgets the fabric, its devices and the secret.
- **`chip-tool-gw` calls the rest over the stream** (`gateway call`):
  `matter.enroll`, `matter.commission`, `matter.nodes`, `matter.rename`,
  `matter.commissionables` (devices in pairing mode on the network),
  `matter.remove`, `matter.open_window`, `matter.icd`, `matter.icd_wait`,
  `thread.*` and `matter.gateway_status`.

## Requirements

- ESP-IDF v6.0, PSRAM, and a `matter` NVS partition (320 KB: see
  `examples/gateway/partitions.csv`).
- The settings in `examples/gateway/sdkconfig.defaults`:
  - esp-matter's controller, with `CUSTOM_OPERATIONAL_CREDS_ISSUER`;
  - ECDHE-PSK and the TLS exporter in mbedTLS;
  - CHIP's memory in PSRAM;
  - CHIP's and lwIP's pools, larger than their defaults for the relay's load.

  They're other components' options, so the application must set them in its
  own `sdkconfig`.
- esp-matter 1.6 comes from the component registry.
- Can't be used with `CONFIG_NVS_ENCRYPTION`: esp-matter 1.6 doesn't support
  its HMAC-based scheme.
