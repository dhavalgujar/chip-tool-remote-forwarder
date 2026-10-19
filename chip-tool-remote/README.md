# chip-tool-remote

CHIP's `chip-tool` with a client for the ESP32 forwarder
(`../components/chip_tool_forwarder`).

- Every Matter device is reached through the forwarder: `chip-tool-remote` sends its
  messages over one TLS stream (`core/ctf_proto.h` in the component).
- The forwarder relays them onto its own secure sessions with the devices.
- Only TCP leaves the machine it runs on, so it works where UDP and IPv6 can't
  go, such as a sandboxed VM.

`chip-tool`'s own sources are unmodified. The client (`forwarder/`) adds:

- `CHIP_TOOL_REMOTE_CONNECT_FILE`: the forwarder's endpoint and secret, as
  `chip_tool_forwarder_connect()` gives them, saved as JSON (mode 600).
  - `CHIP_TOOL_REMOTE_TARGET=proxy`: through an HTTP CONNECT proxy (`CHIP_TOOL_REMOTE_PROXY`, else
    `HTTPS_PROXY`).
  - `CHIP_TOOL_REMOTE_TARGET=host:port` (or `proxy:host:port`): another address, with the
    file's secret.
- `forwarder call NAME --params JSON`: the forwarder's own commands
  (`matter.commission`, `matter.nodes`, `matter.enroll`, ...).
- The cloud CA: once the forwarder enrolled with this controller's storage, this
  controller verifies every device's attestation and signs its certificate.
- Through a forwarder, chip-tool's `pairing`, `discover`, `dcl` and
  `groupsettings` sets aren't available, since they can't work through it.
  - To commission a device: `forwarder call matter.commission`.
  - To find devices in pairing mode: `forwarder call matter.commissionables`.

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
- It builds `chip-tool-remote` and `forwarder-host` (the forwarder relay on a host, for
  tests) into `OUT_DIR` (default `CHIP_ROOT/out/chip-tool-remote`).

To test the client against a fake forwarder and `forwarder-host`, from the
repository's root, with Python 3.13 or later:

```bash
CHIP_TOOL_REMOTE_OUT=OUT_DIR python3 -m unittest discover -s tests -p 'test_stream.py'
```

`package.sh CHIP_ROOT OUT_DIR NAME DEST` makes the release tarball described
below.

## Release tarball

`chip-tool-remote-<version>-linux-x86_64.tgz` (with its `.sha256`) holds:

- `bin/chip-tool-remote`, stripped;
- `lib/`: `libevent_core` and `libevent_pthreads`, which stock images lack;
- `chip-tool-remote.sh`;
- `paa/`: the PAA roots device attestation trusts. The production ones come
  from the DCL when the release is built (connectedhomeip's copy if the DCL
  can't be reached), the development ones from connectedhomeip;
  `paa/SOURCE` says which. Without `paa/`, chip-tool trusts only the test
  PAAs and refuses certified devices.

`chip-tool-remote.sh` runs `chip-tool-remote`:

- with the forwarder's endpoint and secret from `connect.json` next to it;
- with the fabric's CA in `storage/`;
- through an HTTP CONNECT proxy by default (`CHIP_TOOL_REMOTE_VIA_PROXY=1`: port
  `CHIP_TOOL_REMOTE_PROXY_PORT`, 3129, on `$HTTPS_PROXY`'s host), or directly with
  `CHIP_TOOL_REMOTE_VIA_PROXY=0`.

## Tests

`forwarder-host forwarder serve CONNECT-FILE` runs the relay on a host, against devices
on the same network, for testing the client without an ESP32. CONNECT-FILE is
a `connect.json` like the forwarder's: the secret, and the endpoint whose port it
listens on.
