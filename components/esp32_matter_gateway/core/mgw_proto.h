// SPDX-License-Identifier: Apache-2.0

/*
 * Matter gateway stream protocol. A cloud controller
 * (chip-tool-gw) connects over TCP (kDefaultPort) to the gateway and carries
 * Matter messages for sessions the gateway ends. The keys are in mgw_keys.h.
 *
 * Frame: [u16 length, big endian][u8 type][body], length = 1 + body length.
 *   type 0 control: body = [u8 op][fields, integers big endian]
 *   type 1 Matter:  body = one Matter message (as it would be sent over UDP)
 *
 * The stream is TLS 1.2 with ECDHE-PSK (mgw_tls.h: AES-128-CBC-SHA256,
 * encrypt-then-MAC, extended master secret, 4 KB records), ALPN kAlpn. From
 * the per-gateway secret K:
 *   PSK          = HMAC(K, "matter-gw tls psk")                 32 bytes
 *   PSK identity = "matter-gw:" + hex(HMAC(K, "matter-gw psk id")[0..8])
 *   conn_key     = TLS exporter, label "matter-gw conn", no context, 32 bytes
 * Every frame below travels inside TLS.
 * Sessions:
 *   C→G open      req u16, node u64, cloud_lsid u16, cloud_node u64
 *   G→C open_ok   req u16, gw_lsid u16      | open_err req u16, code u16
 *   session secret = HMAC(conn_key, "matter-gw session" | node u64 | cloud_lsid u16 | gw_lsid u16)
 *   (CASE-type session, empty salt, cloud = initiator; see
 *   mgw_session.h)
 *   C→G close     cloud_lsid u16, gw_lsid u16
 *   ping / pong   token u32
 *   G→C error     code u16 (then the gateway closes the stream)
 * Gateway commands (commissioning, the node list; the gateway decides which):
 *   C→G call      req u16, name_len u8, name, params JSON (rest of the body)
 *   G→C result    req u16, result JSON {ok, payload | error} (rest of the body)
 * Cloud signer (the fabric's CA is the cloud controller's), asked on the
 * connection whose call needs it (commissioning, matter.enroll):
 *   G→C sign      req u16, kind u8, node u64, fabric u64, then fields, each
 *                 u16 length + bytes: NOCSR elements, attestation signature,
 *                 attestation challenge, CSR nonce, DAC, PAI (empty for kind 2)
 *   C→G signed    req u16, status u16 (ErrCode), then fields: NOC, ICAC, RCAC
 *                 (X.509 DER), IPK (16 bytes), then admin subject u64 (0: none)
 *   Attestation (kind 3, during commissioning, before the CSR): the commissioner's
 *   attestation verifier is the cloud's.
 *   G→C sign      req u16, kind 3, VID u64, PID u64, then fields: attestation
 *                 elements, attestation challenge, attestation signature, PAI,
 *                 DAC, attestation nonce
 *   C→G signed    req u16, status u16 (kErrNone / kErrAttestation), result u16
 *                 (CHIP AttestationVerificationResult)
 * Events (G→C, to every authenticated connection; clients ignore kinds they
 * don't know):
 *   event         kind u8, node u64
 *     kind 1 icd_active: the node (an ICD the gateway is the client of) sent
 *     a Check-In and is in active mode now
 *
 * Versions: the ALPN alone says which version of this protocol a connection
 * speaks. There is no version field, and nothing else depends on it: the PSK,
 * its identity and the key labels stay the same from one version to the next,
 * so a client of another version fails on the ALPN ("another protocol
 * version"), not on the secret.
 *   No new version needed: new gateway commands, parameters and result fields
 *   (call and result carry JSON), and new event kinds (clients ignore kinds
 *   they don't know, and any op they don't know).
 *   A new version: a new op, or any change to the fields of a frame or a
 *   message. The gateway closes the stream on an op it doesn't know
 *   (bad_frame).
 *   Moving to a new version: the firmware and chip-tool-gw are updated
 *   separately (an OTA, the agent's bundle), so the gateway accepts the old
 *   and the new ALPN for at least one release, preferring the new one, and
 *   chip-tool-gw offers the new one first.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

namespace mgw {

constexpr uint16_t kDefaultPort   = 7401;
constexpr char kAlpn[]            = "matter-gw/1";
constexpr char kExportLabel[]     = "matter-gw conn";
constexpr char kIdentityName[]    = "matter-gw"; // the PSK identity's prefix, the same in every version
constexpr size_t kIdentityLen     = sizeof(kIdentityName) + 16 + 1; // kIdentityName + ":" + 16 hex digits + NUL
constexpr size_t kMacLen          = 32;
constexpr size_t kKeyLen          = 32;
constexpr size_t kMaxFrameBody    = 4096; // Matter messages are at most 1280 bytes; certificate chains need more
constexpr size_t kFrameHeaderLen  = 3;
constexpr size_t kMinSecretLen    = 16;
constexpr size_t kMaxSecretLen    = 64;
constexpr size_t kMaxCallName     = 63;

enum FrameType : uint8_t
{
    kFrameControl = 0,
    kFrameMatter  = 1,
};

enum Op : uint8_t
{
    // 1-4 are reserved.
    kOpOpen     = 5,
    kOpOpenOk   = 6,
    kOpOpenErr  = 7,
    kOpClose    = 8,
    kOpPing     = 9,
    kOpPong     = 10,
    kOpError    = 11,
    kOpCall     = 12,
    kOpResult   = 13,
    kOpSign     = 14,
    kOpSigned   = 15,
    kOpEvent    = 16,
};

enum EventKind : uint8_t
{
    kEventIcdActive = 1,
};

enum SignKind : uint8_t
{
    kSignDevice     = 1, // a node being commissioned: NOCSR elements + attestation
    kSignController = 2, // the gateway's own controller identity (enrollment)
    kSignAttest     = 3, // verify a node's attestation (the cloud's verifier decides)
};

enum ErrCode : uint16_t
{
    kErrNone        = 0,
    // 1-3 are reserved.
    kErrNoMemory    = 4,
    kErrBadNode     = 5,
    kErrInternal    = 6,
    kErrBadFrame    = 7,
    kErrPolicy      = 8,
    kErrAttestation = 9,  // the signer did not accept the device's attestation
    kErrSigner      = 10, // no signer on that connection, or it failed
    kErrBusy        = 11, // every connection slot is in use
};

const char * ErrName(uint16_t code);

// Big-endian helpers.
inline void Put16(uint8_t * p, uint16_t v)
{
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}
inline void Put32(uint8_t * p, uint32_t v)
{
    Put16(p, static_cast<uint16_t>(v >> 16));
    Put16(p + 2, static_cast<uint16_t>(v));
}
inline void Put64(uint8_t * p, uint64_t v)
{
    Put32(p, static_cast<uint32_t>(v >> 32));
    Put32(p + 4, static_cast<uint32_t>(v));
}
inline uint16_t Get16(const uint8_t * p)
{
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}
inline uint32_t Get32(const uint8_t * p)
{
    return (static_cast<uint32_t>(Get16(p)) << 16) | Get16(p + 2);
}
inline uint64_t Get64(const uint8_t * p)
{
    return (static_cast<uint64_t>(Get32(p)) << 32) | Get32(p + 4);
}

/*
 * Incremental frame reader: feed bytes, take complete frames. Holds at most
 * one frame (header + kMaxFrameBody).
 */
class FrameReader
{
public:
    // Appends up to len bytes; returns how many were taken (0 when a frame is
    // waiting to be taken).
    size_t Feed(const uint8_t * data, size_t len);
    // True when a whole frame is buffered; type/body valid until Consume().
    bool Ready() const;
    // A frame header announced a body larger than kMaxFrameBody or empty.
    bool Bad() const { return mBad; }
    uint8_t Type() const { return mBuf[2]; }
    const uint8_t * Body() const { return mBuf + kFrameHeaderLen; }
    size_t BodyLen() const { return Get16(mBuf) - 1u; }
    void Consume();

private:
    uint8_t mBuf[kFrameHeaderLen + kMaxFrameBody];
    size_t mLen = 0;
    bool mBad   = false;
};

// Writes a frame header for a body of bodyLen bytes into out[3].
bool FrameHeader(uint8_t * out, uint8_t type, size_t bodyLen);

/*
 * Control messages: Encode() writes the whole control body (op byte first);
 * Decode() takes one and returns false if it isn't this message or is too
 * short (longer bodies are accepted: fields may be added at the end).
 */
struct OpenMsg // C→G open
{
    static constexpr size_t kLen = 1 + 2 + 8 + 2 + 8;
    uint16_t req       = 0;
    uint64_t node      = 0;
    uint16_t cloudLsid = 0;
    uint64_t cloudNode = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

struct OpenReplyMsg // G→C open_ok (value: gw_lsid) or open_err (value: ErrCode)
{
    static constexpr size_t kLen = 1 + 2 + 2;
    bool ok        = false;
    uint16_t req   = 0;
    uint16_t value = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

struct CloseMsg // C→G close
{
    static constexpr size_t kLen = 1 + 2 + 2;
    uint16_t cloudLsid = 0;
    uint16_t gwLsid    = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

struct PingMsg // ping, or pong (its answer, with the same token)
{
    static constexpr size_t kLen = 1 + 4;
    bool pong      = false;
    uint32_t token = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

struct ErrorMsg // G→C error
{
    static constexpr size_t kLen = 1 + 2;
    uint16_t code = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

struct EventMsg // G→C event
{
    static constexpr size_t kLen = 1 + 1 + 8;
    uint8_t kind  = 0;
    uint64_t node = 0;
    void Encode(uint8_t out[kLen]) const;
    bool Decode(const uint8_t * body, size_t len);
};

// C→G call. Decode() points name and params into the body.
struct CallMsg
{
    static constexpr size_t kHeaderLen = 1 + 2 + 1;
    uint16_t req         = 0;
    const char * name    = nullptr;
    size_t nameLen       = 0; // 1-kMaxCallName
    const char * params  = nullptr;
    size_t paramsLen     = 0;
    size_t Len() const { return kHeaderLen + nameLen + paramsLen; }
    // Fails if the name's length is out of range or out has less than Len().
    bool Encode(uint8_t * out, size_t cap) const;
    bool Decode(const uint8_t * body, size_t len);
};

// G→C result. Decode() points json into the body.
struct ResultMsg
{
    static constexpr size_t kHeaderLen = 1 + 2;
    uint16_t req       = 0;
    const char * json  = nullptr;
    size_t jsonLen     = 0;
    size_t Len() const { return kHeaderLen + jsonLen; }
    bool Encode(uint8_t * out, size_t cap) const;
    bool Decode(const uint8_t * body, size_t len);
};

/* Length-prefixed fields (u16 big endian + bytes) inside a body. */
class FieldWriter
{
public:
    FieldWriter(uint8_t * buf, size_t cap) : mBuf(buf), mCap(cap) {}
    bool Raw(const void * p, size_t n);
    bool U8(uint8_t v) { return Raw(&v, 1); }
    bool U16(uint16_t v);
    bool U64(uint64_t v);
    bool Field(const uint8_t * p, size_t n); // u16 length + bytes
    size_t Len() const { return mLen; }
    bool Ok() const { return mOk; }

private:
    uint8_t * mBuf;
    size_t mCap;
    size_t mLen = 0;
    bool mOk    = true;
};

class FieldReader
{
public:
    FieldReader(const uint8_t * buf, size_t len) : mBuf(buf), mLen(len) {}
    bool U8(uint8_t & v);
    bool U16(uint16_t & v);
    bool U64(uint64_t & v);
    bool Field(const uint8_t *& p, size_t & n);

private:
    const uint8_t * mBuf;
    size_t mLen;
    size_t mAt = 0;
};

} // namespace mgw
