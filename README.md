# esp32-matter-gateway

A Matter gateway on an ESP32, for chip-tool.

- `chip-tool-gw` is CHIP's `chip-tool` with a client for the gateway: it
  reaches every Matter device through the ESP32, over one TLS stream.
- The ESP32 relays the messages onto secure sessions of its own with the
  devices, over Wi-Fi or Thread (through the home's border router).
- Only TCP to the ESP32 leaves the machine `chip-tool-gw` runs on, so it works
  where Matter's UDP, multicast and IPv6 can't go, such as a sandboxed VM.
- The fabric's CA stays with `chip-tool-gw`: the ESP32 enrolls once, then asks
  `chip-tool-gw` to verify the attestation of each device it commissions and
  to sign its certificate.
- An application uses the component as a dependency, and hands out the
  stream's endpoint and secret on a channel it trusts.

| Directory | Contents |
| --- | --- |
| `components/esp32_matter_gateway/` | The ESP-IDF component: the gateway, the relay, the controller |
| `components/esp32_matter_gateway/core/` | The stream protocol (`mgw_proto.h`), the relay and the server, shared with `chip-tool-gw` |
| `chip-tool-gw/` | `chip-tool-gw` and `mgw-host` (the relay on a host, for tests), built against a connectedhomeip checkout |
| `examples/gateway/` | The component on its own: Wi-Fi from menuconfig, `chip-tool-gw` on the local network |
| `tests/` | Host tests: the pure-C parts, the protocol, and `chip-tool-gw`'s stream client |

## Firmware

- A generic ESP-IDF (v6.0) component.
- It needs an ESP32 with PSRAM, and Bluetooth to commission new devices over
  it.
- CI builds it for the ESP32-C5; it's tested on the ESP32-C5 and ESP32-S3.
- esp-matter 1.6 comes from the component registry.

```bash
cd examples/gateway
idf.py set-target esp32c5
idf.py menuconfig        # Matter gateway example: Wi-Fi
idf.py build flash monitor
```

On the console, `connect --secret` prints what `chip-tool-gw` connects with.

## chip-tool-gw

Each release contains `chip-tool-gw-<version>-linux-x86_64.tgz` and its
`.sha256`. The tarball holds:

- `bin/chip-tool-gw`;
- the libevent libraries it needs;
- `mgw.sh`;
- the PAA roots for device attestation (`paa/`).

To build it, see [chip-tool-gw/README.md](chip-tool-gw/README.md).

```bash
# Save the gateway's endpoint and secret as connect.json next to mgw.sh, then:
export MGW_VIA_PROXY=0                    # straight to the gateway, not through a proxy
./mgw.sh gateway call matter.gateway_status
./mgw.sh gateway call matter.enroll       # once: chip-tool-gw's CA becomes the fabric's
./mgw.sh gateway call matter.commission --params '{"code":"MT:..."}'
./mgw.sh onoff toggle 1 1
```

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_host.py' -v
CHIP_TOOL_GW_OUT=<build.sh OUT_DIR> python3 -m unittest discover -s tests -p 'test_stream.py' -v
```

## License

Apache-2.0 (`LICENSE`). Files from
[connectedhomeip](https://github.com/project-chip/connectedhomeip) keep its
header.
