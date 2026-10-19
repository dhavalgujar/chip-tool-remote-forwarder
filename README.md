# chip-tool-remote-forwarder

chip-tool, wherever it runs, controls the home's Matter devices through an ESP32.

- `chip-tool-remote` is CHIP's `chip-tool` with a client for the forwarder
  (`chip_tool_forwarder`, the ESP-IDF component on the ESP32): it reaches
  every Matter device through the ESP32, over one TLS stream.
- The ESP32 relays the messages onto secure sessions of its own with the
  devices, over Wi-Fi or Thread (through the home's border router).
- Only TCP to the ESP32 leaves the machine `chip-tool-remote` runs on, so it works
  where Matter's UDP, multicast and IPv6 can't go, such as a sandboxed VM.
- The fabric's CA stays with `chip-tool-remote`: the ESP32 enrolls once, then asks
  `chip-tool-remote` to verify the attestation of each device it commissions and
  to sign its certificate.
- An application uses the component as a dependency, and hands out the
  stream's endpoint and secret on a channel it trusts.

| Directory | Contents |
| --- | --- |
| `components/chip_tool_forwarder/` | The ESP-IDF component: the forwarder, the relay, the controller |
| `components/chip_tool_forwarder/core/` | The stream protocol (`ctf_proto.h`), the relay and the server, shared with `chip-tool-remote` |
| `chip-tool-remote/` | `chip-tool-remote` and `forwarder-host` (the relay on a host, for tests), built against a connectedhomeip checkout |
| `examples/forwarder/` | The component on its own: Wi-Fi from menuconfig, `chip-tool-remote` on the local network |
| `tests/` | Host tests: the pure-C parts, the protocol, and `chip-tool-remote`'s stream client |

## Firmware

- A generic ESP-IDF (v6.0) component.
- It needs an ESP32 with PSRAM, and Bluetooth to commission new devices over
  it.
- CI builds it for the ESP32-C5; it's tested on the ESP32-C5 and ESP32-S3.
- esp-matter 1.6 comes from the component registry.

```bash
cd examples/forwarder
idf.py set-target esp32c5
idf.py menuconfig        # forwarder example: Wi-Fi
idf.py build flash monitor
```

On the console, `connect --secret` prints what `chip-tool-remote` connects with.

## chip-tool-remote

Each release contains `chip-tool-remote-<version>-linux-x86_64.tgz` and its
`.sha256`. The tarball holds:

- `bin/chip-tool-remote`;
- the libevent libraries it needs;
- `chip-tool-remote.sh`;
- the PAA roots for device attestation (`paa/`).

To build it, see [chip-tool-remote/README.md](chip-tool-remote/README.md).

```bash
# Save the forwarder's endpoint and secret as connect.json next to chip-tool-remote.sh, then:
export CHIP_TOOL_REMOTE_VIA_PROXY=0                    # straight to the forwarder, not through a proxy
./chip-tool-remote.sh forwarder call matter.gateway_status
./chip-tool-remote.sh forwarder call matter.enroll       # once: chip-tool-remote's CA becomes the fabric's
./chip-tool-remote.sh forwarder call matter.commission --params '{"code":"MT:..."}'
./chip-tool-remote.sh onoff toggle 1 1
```

## Tests

```bash
python3 -m unittest discover -s tests -p 'test_host.py' -v
CHIP_TOOL_REMOTE_OUT=<build.sh OUT_DIR> python3 -m unittest discover -s tests -p 'test_stream.py' -v
```

## License

Apache-2.0 (`LICENSE`). Files from
[connectedhomeip](https://github.com/project-chip/connectedhomeip) keep its
header.
