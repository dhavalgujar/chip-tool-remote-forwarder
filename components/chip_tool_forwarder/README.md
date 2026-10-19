# chip_tool_forwarder

A forwarder for `chip-tool-remote` (CHIP's chip-tool with the forwarder's
client, in this repository's `chip-tool-remote/`).

- `chip-tool-remote` reaches every Matter device through this device, over one TLS
  stream (TCP 7401).
- The device relays the messages onto its own secure sessions with the
  devices, over Wi-Fi or Thread.
- The fabric's CA is `chip-tool-remote`'s: the device enrolls once
  (`matter.enroll`), then has `chip-tool-remote` verify and sign every device it
  commissions.

## Use

```c
#include "chip_tool_forwarder.h"

// At boot, once Wi-Fi (the default station netif) is started:
const chip_tool_forwarder_config_t forwarder = {
    .setup_complete = true, // Bluetooth is CHIP's from now on
    .listen_netif   = NULL, // chip-tool-remote connects from the local network
};
chip_tool_forwarder_init(&forwarder);

// On a channel you trust (never the network): the endpoint and secret
// chip-tool-remote connects with, and its release (client, this component's
// version).
cJSON *r = chip_tool_forwarder_connect(NULL);
```

- **Wi-Fi:** the application connects the station (`WIFI_STA_DEF`); the
  forwarder uses that connection and never configures Wi-Fi itself.
- **Bluetooth** is shared with the application, one at a time:
  - `setup_complete` false: the application still uses Bluetooth for its own
    setup (for example, pairing with its owner). Matter doesn't start, and the
    `matter` partition is erased, so a new owner starts clean.
  - When its setup finishes, the application calls
    `chip_tool_forwarder_setup_done()`; the device restarts shortly after.
  - `setup_complete` true: CHIP uses Bluetooth from `init` on, to commission
    new devices.
- **`listen_netif`** can be a tunnel's lwIP netif (two letters, for example
  `"tn"`). The port is then reachable only through that netif, at the
  station's address.
- **`chip_tool_forwarder_erase()`** is for the application's own reset: it
  forgets the fabric, its devices and the secret.
- **`chip-tool-remote` calls the rest over the stream** (`forwarder call`):
  `matter.enroll`, `matter.commission`, `matter.nodes`, `matter.rename`,
  `matter.commissionables` (devices in pairing mode on the network),
  `matter.remove`, `matter.open_window`, `matter.icd`, `matter.icd_wait`,
  `thread.*` and `matter.gateway_status`.

## Requirements

- ESP-IDF v6.0, PSRAM, and a `matter` NVS partition (320 KB: see
  `examples/forwarder/partitions.csv`).
- The settings in `examples/forwarder/sdkconfig.defaults`:
  - esp-matter's controller, with `CUSTOM_OPERATIONAL_CREDS_ISSUER`;
  - ECDHE-PSK and the TLS exporter in mbedTLS;
  - CHIP's memory in PSRAM;
  - CHIP's and lwIP's pools, larger than their defaults for the relay's load.

  They're other components' options, so the application must set them in its
  own `sdkconfig`.
- esp-matter 1.6 comes from the component registry.
- Can't be used with `CONFIG_NVS_ENCRYPTION`: esp-matter 1.6 doesn't support
  its HMAC-based scheme.
