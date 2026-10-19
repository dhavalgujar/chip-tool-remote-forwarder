// SPDX-License-Identifier: Apache-2.0

// Host harness for the forwarder stream protocol (components/chip_tool_forwarder/
// core/ctf_proto.cpp, shared by the forwarder and chip-tool-remote): framing, the
// control messages and the length-prefixed fields. Run by tests/test_host.py.
#include <stdio.h>
#include <string.h>

#include "ctf_proto.h"

using namespace ctf;

static int failures;
#define CHECK(c)                                                                  \
    do                                                                            \
    {                                                                             \
        if (!(c))                                                                 \
        {                                                                         \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
            failures++;                                                           \
        }                                                                         \
    } while (0)

static void integers()
{
    uint8_t b[8];
    Put16(b, 0x1234);
    CHECK(b[0] == 0x12 && b[1] == 0x34 && Get16(b) == 0x1234);
    Put32(b, 0x89abcdefu);
    CHECK(b[0] == 0x89 && b[3] == 0xef && Get32(b) == 0x89abcdefu);
    Put64(b, 0x0102030405060708ull);
    CHECK(b[0] == 1 && b[7] == 8 && Get64(b) == 0x0102030405060708ull);
}

// Builds frame [len][type][body] into out; returns its size.
static size_t Frame(uint8_t * out, uint8_t type, const uint8_t * body, size_t n)
{
    CHECK(FrameHeader(out, type, n));
    memcpy(out + kFrameHeaderLen, body, n);
    return kFrameHeaderLen + n;
}

static void frames()
{
    uint8_t hdr[kFrameHeaderLen];
    CHECK(FrameHeader(hdr, kFrameMatter, kMaxFrameBody));
    CHECK(Get16(hdr) == kMaxFrameBody + 1 && hdr[2] == kFrameMatter);
    CHECK(!FrameHeader(hdr, kFrameMatter, kMaxFrameBody + 1));

    // Two frames in one read, then the same bytes one at a time.
    static uint8_t stream[64];
    const uint8_t a[] = { 1, 2, 3 }, b[] = { 9 };
    size_t n = Frame(stream, kFrameControl, a, sizeof(a));
    n += Frame(stream + n, kFrameMatter, b, sizeof(b));

    static FrameReader r; // 4 KB: not on the stack
    size_t used = r.Feed(stream, n);
    CHECK(used == kFrameHeaderLen + sizeof(a) && r.Ready() && !r.Bad());
    CHECK(r.Type() == kFrameControl && r.BodyLen() == sizeof(a) && memcmp(r.Body(), a, sizeof(a)) == 0);
    CHECK(r.Feed(stream + used, n - used) == 0); // a frame is waiting to be taken
    r.Consume();
    CHECK(r.Feed(stream + used, n - used) == n - used && r.Ready() && r.Type() == kFrameMatter && r.Body()[0] == 9);
    r.Consume();

    int ready = 0;
    for (size_t i = 0; i < n; i++)
    {
        CHECK(r.Feed(stream + i, 1) == 1);
        if (r.Ready())
        {
            ready++;
            r.Consume();
        }
    }
    CHECK(ready == 2 && !r.Bad());

    // A frame with no type byte, and one longer than kMaxFrameBody: bad.
    static FrameReader empty, big;
    const uint8_t zero[] = { 0, 0 };
    empty.Feed(zero, sizeof(zero));
    CHECK(empty.Bad() && !empty.Ready());
    uint8_t huge[2];
    Put16(huge, kMaxFrameBody + 2);
    big.Feed(huge, sizeof(huge));
    CHECK(big.Bad());
}

// Every fixed-size message: a round trip, too short, the wrong op, and a
// longer body (fields added later) still decoding.
template <typename M>
static void FixedRoundTrip(const M & m, M & back)
{
    uint8_t b[M::kLen + 4] = {};
    m.Encode(b);
    CHECK(back.Decode(b, M::kLen));
    CHECK(back.Decode(b, M::kLen + 4));
    M other;
    CHECK(!other.Decode(b, M::kLen - 1));
    b[0] ^= 0x80;
    CHECK(!other.Decode(b, M::kLen));
}

static void messages()
{
    OpenMsg open, o2;
    open.req       = 7;
    open.node      = 0x1122334455667788ull;
    open.cloudLsid = 0xabcd;
    open.cloudNode = 112233;
    FixedRoundTrip(open, o2);
    CHECK(o2.req == 7 && o2.node == open.node && o2.cloudLsid == 0xabcd && o2.cloudNode == 112233);
    uint8_t b[OpenMsg::kLen];
    open.Encode(b);
    CHECK(b[0] == kOpOpen && OpenMsg::kLen == 21);

    OpenReplyMsg ok, ok2, err;
    ok.ok    = true;
    ok.req   = 7;
    ok.value = 42;
    FixedRoundTrip(ok, ok2);
    CHECK(ok2.ok && ok2.req == 7 && ok2.value == 42);
    err.req   = 8;
    err.value = kErrPolicy;
    uint8_t e[OpenReplyMsg::kLen];
    err.Encode(e);
    CHECK(e[0] == kOpOpenErr && ok2.Decode(e, sizeof(e)) && !ok2.ok && ok2.value == kErrPolicy);

    CloseMsg close, c2;
    close.cloudLsid = 3;
    close.fwdLsid    = 4;
    FixedRoundTrip(close, c2);
    CHECK(c2.cloudLsid == 3 && c2.fwdLsid == 4);

    PingMsg ping, p2;
    ping.token = 0xdeadbeef;
    FixedRoundTrip(ping, p2);
    CHECK(!p2.pong && p2.token == 0xdeadbeef);
    ping.pong = true;
    uint8_t pb[PingMsg::kLen];
    ping.Encode(pb);
    CHECK(pb[0] == kOpPong && p2.Decode(pb, sizeof(pb)) && p2.pong);

    ErrorMsg error, e2;
    error.code = kErrBusy;
    FixedRoundTrip(error, e2);
    CHECK(e2.code == kErrBusy);

    EventMsg event, ev2;
    event.kind = kEventIcdActive;
    event.node = 249;
    FixedRoundTrip(event, ev2);
    CHECK(ev2.kind == kEventIcdActive && ev2.node == 249);

    // call: a name, then params as the rest of the body
    CallMsg call, call2;
    call.req       = 0x0102;
    call.name      = "matter.nodes";
    call.nameLen   = strlen(call.name);
    call.params    = "{}";
    call.paramsLen = 2;
    uint8_t cb[64];
    CHECK(call.Len() == CallMsg::kHeaderLen + 12 + 2);
    CHECK(!call.Encode(cb, call.Len() - 1));
    CHECK(call.Encode(cb, sizeof(cb)) && cb[0] == kOpCall && cb[3] == 12);
    CHECK(call2.Decode(cb, call.Len()));
    CHECK(call2.req == 0x0102 && call2.nameLen == 12 && memcmp(call2.name, "matter.nodes", 12) == 0);
    CHECK(call2.paramsLen == 2 && memcmp(call2.params, "{}", 2) == 0);
    CHECK(!call2.Decode(cb, CallMsg::kHeaderLen + 11)); // the name runs past the body
    call.paramsLen = 0;
    CHECK(call.Encode(cb, sizeof(cb)) && call2.Decode(cb, call.Len()) && call2.paramsLen == 0);
    char longName[kMaxCallName + 2];
    memset(longName, 'a', sizeof(longName));
    call.name    = longName;
    call.nameLen = kMaxCallName + 1;
    uint8_t big[128];
    CHECK(!call.Encode(big, sizeof(big)));
    call.nameLen = 0;
    CHECK(!call.Encode(big, sizeof(big)));

    // result: JSON as the rest of the body
    ResultMsg res, res2;
    res.req     = 9;
    res.json    = "{\"ok\":true}";
    res.jsonLen = strlen(res.json);
    uint8_t rb[32];
    CHECK(!res.Encode(rb, res.Len() - 1));
    CHECK(res.Encode(rb, sizeof(rb)) && rb[0] == kOpResult);
    CHECK(res2.Decode(rb, res.Len()) && res2.req == 9 && res2.jsonLen == res.jsonLen &&
          memcmp(res2.json, res.json, res.jsonLen) == 0);
    CHECK(!res2.Decode(rb, ResultMsg::kHeaderLen - 1));
    rb[0] = kOpCall;
    CHECK(!res2.Decode(rb, res.Len()));
}

static void fields()
{
    uint8_t b[16];
    FieldWriter w(b, sizeof(b));
    const uint8_t v[] = { 0xaa, 0xbb, 0xcc };
    CHECK(w.U8(1) && w.U16(0x0203) && w.Field(v, sizeof(v)) && w.Field(nullptr, 0) && w.Ok());
    CHECK(w.Len() == 1 + 2 + 2 + 3 + 2);

    FieldReader r(b, w.Len());
    uint8_t u8;
    uint16_t u16;
    const uint8_t * p;
    size_t n;
    CHECK(r.U8(u8) && u8 == 1 && r.U16(u16) && u16 == 0x0203);
    CHECK(r.Field(p, n) && n == 3 && memcmp(p, v, 3) == 0);
    CHECK(r.Field(p, n) && n == 0);
    CHECK(!r.U8(u8)); // the end

    // A field whose length runs past the body, and reads past the end.
    uint8_t t[] = { 0, 5, 1, 2 };
    FieldReader r2(t, sizeof(t));
    CHECK(!r2.Field(p, n));
    uint64_t u64;
    FieldReader r3(t, sizeof(t));
    CHECK(!r3.U64(u64));

    // Overflow: the write fails, and every later one too.
    FieldWriter small(b, 4);
    CHECK(small.U16(1) && !small.Field(v, sizeof(v)) && !small.Ok() && !small.U8(1));
    static uint8_t huge[0x10000];
    FieldWriter wide(huge, sizeof(huge));
    CHECK(!wide.Field(huge, 0x10000)); // longer than a u16 length
}

static void names()
{
    CHECK(strcmp(ErrName(kErrNone), "none") == 0);
    CHECK(strcmp(ErrName(kErrPolicy), "policy") == 0);
    CHECK(strcmp(ErrName(kErrBusy), "busy") == 0);
    CHECK(strcmp(ErrName(1), "unknown") == 0); // reserved
}

int main()
{
    integers();
    frames();
    messages();
    fields();
    names();
    if (failures)
    {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    puts("ctf_proto: ok");
    return 0;
}
