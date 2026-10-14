# chip-tool-gw

CHIP's `chip-tool` with a client for the ESP32's Matter gateway
(`../components/esp32_matter_gateway`).

- Every Matter device is reached through the gateway: `chip-tool-gw` sends its
  messages over one TLS stream (`core/mgw_proto.h` in the component).
- The gateway relays them onto its own secure sessions with the devices.
- Only TCP leaves the machine it runs on, so it works where UDP and IPv6 can't
  go, such as a sandboxed VM.

`chip-tool`'s own sources are unmodified. The client (`gateway/`) adds:

- `MATTER_GW_CONNECT_FILE`: the gateway's endpoint and secret, as
  `esp32_matter_gateway_connect()` gives them, saved as JSON (mode 600).
  - `MATTER_GW=proxy`: through an HTTP CONNECT proxy (`MATTER_GW_PROXY`, else
    `HTTPS_PROXY`).
  - `MATTER_GW=host:port` (or `proxy:host:port`): another address, with the
    file's secret.
- `gateway call NAME --params JSON`: the gateway's own commands
  (`matter.commission`, `matter.nodes`, `matter.enroll`, ...).
- The cloud CA: once the gateway enrolled with this controller's storage, this
  controller verifies every device's attestation and signs its certificate.
- Through a gateway, chip-tool's `pairing`, `discover`, `dcl` and
  `groupsettings` sets aren't available, since they can't work through it.
  - To commission a device: `gateway call matter.commission`.
  - To find devices in pairing mode: `gateway call matter.commissionables`.

## Build

```bash
./build.sh ~/connectedhomeip [OUT_DIR]
```

- On Linux, against a
  [connectedhomeip](https://github.com/project-chip/connectedhomeip) checkout
  with its submodules (tested at `7d3dfb6c06b3cc696186f86d527b2f387a5603df`).
- It needs CHIP's environment (`scripts/bootstrap.sh`, then
  `scripts/activate.sh`); with `gn` already on `PATH`, `build.sh` uses the
  environment it is in.
- It applies the one CHIP patch in `patches/` (a session lookup hook in
  `CASESessionManager`), and links `build_overrides`,
  `third_party/connectedhomeip` and `core` (the component's) into this
  directory.
- It builds `chip-tool-gw` and `mgw-host` (the gateway relay on a host, for
  tests) into `OUT_DIR` (default `CHIP_ROOT/out/chip-tool-gw`).

To test the client against a fake gateway and `mgw-host`, from the
repository's root, with Python 3.13 or later:

```bash
CHIP_TOOL_GW_OUT=OUT_DIR python3 -m unittest discover -s tests -p 'test_stream.py'
```

`package.sh CHIP_ROOT OUT_DIR NAME DEST` makes the release tarball described
below.

## Release tarball

`chip-tool-gw-<version>-linux-x86_64.tgz` (with its `.sha256`) holds:

- `bin/chip-tool-gw`, stripped;
- `lib/`: `libevent_core` and `libevent_pthreads`, which stock images lack;
- `mgw.sh`;
- `paa/`: the PAA roots device attestation trusts. The production ones come
  from the DCL when the release is built (connectedhomeip's copy if the DCL
  can't be reached), the development ones from connectedhomeip;
  `paa/SOURCE` says which. Without `paa/`, chip-tool trusts only the test
  PAAs and refuses certified devices.

`mgw.sh` runs `chip-tool-gw`:

- with the gateway's endpoint and secret from `connect.json` next to it;
- with the fabric's CA in `storage/`;
- through an HTTP CONNECT proxy by default (`MGW_VIA_PROXY=1`: port
  `MGW_PROXY_PORT`, 3129, on `$HTTPS_PROXY`'s host), or directly with
  `MGW_VIA_PROXY=0`.

## Tests

`mgw-host gateway serve SECRET-FILE` runs the relay on a host, against devices
on the same network, for testing the client without an ESP32.
