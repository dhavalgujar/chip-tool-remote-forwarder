// SPDX-License-Identifier: Apache-2.0

#include "mgw_proto.h"

#include <string.h>

namespace mgw {

const char * ErrName(uint16_t code)
{
    switch (code)
    {
    case kErrNone:
        return "none";
    case kErrNoMemory:
        return "no_memory";
    case kErrBadNode:
        return "bad_node";
    case kErrInternal:
        return "internal";
    case kErrBadFrame:
        return "bad_frame";
    case kErrPolicy:
        return "policy";
    case kErrAttestation:
        return "attestation";
    case kErrSigner:
        return "signer";
    case kErrBusy:
        return "busy";
    }
    return "unknown";
}

size_t FrameReader::Feed(const uint8_t * data, size_t len)
{
    size_t used = 0;
    while (used < len && !mBad && !Ready())
    {
        const size_t want = mLen < 2 ? 2 : 2u + Get16(mBuf);
        size_t n          = want - mLen;
        if (n > len - used)
        {
            n = len - used;
        }
        memcpy(mBuf + mLen, data + used, n);
        mLen += n;
        used += n;
        // The length is known: a bad one is refused now, not when more comes.
        if (mLen == 2)
        {
            const size_t flen = Get16(mBuf);
            mBad              = flen < 1 || flen - 1 > kMaxFrameBody;
        }
    }
    return used;
}

bool FrameReader::Ready() const
{
    return !mBad && mLen >= kFrameHeaderLen && mLen == 2u + Get16(mBuf);
}

void FrameReader::Consume()
{
    mLen = 0;
}

bool FrameHeader(uint8_t * out, uint8_t type, size_t bodyLen)
{
    if (bodyLen > kMaxFrameBody)
    {
        return false;
    }
    Put16(out, static_cast<uint16_t>(bodyLen + 1));
    out[2] = type;
    return true;
}

void OpenMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = kOpOpen;
    Put16(out + 1, req);
    Put64(out + 3, node);
    Put16(out + 11, cloudLsid);
    Put64(out + 13, cloudNode);
}

bool OpenMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || b[0] != kOpOpen)
    {
        return false;
    }
    req       = Get16(b + 1);
    node      = Get64(b + 3);
    cloudLsid = Get16(b + 11);
    cloudNode = Get64(b + 13);
    return true;
}

void OpenReplyMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = ok ? kOpOpenOk : kOpOpenErr;
    Put16(out + 1, req);
    Put16(out + 3, value);
}

bool OpenReplyMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || (b[0] != kOpOpenOk && b[0] != kOpOpenErr))
    {
        return false;
    }
    ok    = b[0] == kOpOpenOk;
    req   = Get16(b + 1);
    value = Get16(b + 3);
    return true;
}

void CloseMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = kOpClose;
    Put16(out + 1, cloudLsid);
    Put16(out + 3, gwLsid);
}

bool CloseMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || b[0] != kOpClose)
    {
        return false;
    }
    cloudLsid = Get16(b + 1);
    gwLsid    = Get16(b + 3);
    return true;
}

void PingMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = pong ? kOpPong : kOpPing;
    Put32(out + 1, token);
}

bool PingMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || (b[0] != kOpPing && b[0] != kOpPong))
    {
        return false;
    }
    pong  = b[0] == kOpPong;
    token = Get32(b + 1);
    return true;
}

void ErrorMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = kOpError;
    Put16(out + 1, code);
}

bool ErrorMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || b[0] != kOpError)
    {
        return false;
    }
    code = Get16(b + 1);
    return true;
}

void EventMsg::Encode(uint8_t out[kLen]) const
{
    out[0] = kOpEvent;
    out[1] = kind;
    Put64(out + 2, node);
}

bool EventMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kLen || b[0] != kOpEvent)
    {
        return false;
    }
    kind = b[1];
    node = Get64(b + 2);
    return true;
}

bool CallMsg::Encode(uint8_t * out, size_t cap) const
{
    if (nameLen < 1 || nameLen > kMaxCallName || cap < Len())
    {
        return false;
    }
    out[0] = kOpCall;
    Put16(out + 1, req);
    out[3] = static_cast<uint8_t>(nameLen);
    memcpy(out + kHeaderLen, name, nameLen);
    if (paramsLen > 0)
    {
        memcpy(out + kHeaderLen + nameLen, params, paramsLen);
    }
    return true;
}

bool CallMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kHeaderLen || b[0] != kOpCall || len < kHeaderLen + b[3])
    {
        return false;
    }
    req       = Get16(b + 1);
    nameLen   = b[3];
    name      = reinterpret_cast<const char *>(b + kHeaderLen);
    params    = name + nameLen;
    paramsLen = len - kHeaderLen - nameLen;
    return true;
}

bool ResultMsg::Encode(uint8_t * out, size_t cap) const
{
    if (cap < Len())
    {
        return false;
    }
    out[0] = kOpResult;
    Put16(out + 1, req);
    if (jsonLen > 0)
    {
        memcpy(out + kHeaderLen, json, jsonLen);
    }
    return true;
}

bool ResultMsg::Decode(const uint8_t * b, size_t len)
{
    if (len < kHeaderLen || b[0] != kOpResult)
    {
        return false;
    }
    req     = Get16(b + 1);
    json    = reinterpret_cast<const char *>(b + kHeaderLen);
    jsonLen = len - kHeaderLen;
    return true;
}

bool FieldWriter::Raw(const void * p, size_t n)
{
    if (!mOk || mLen + n > mCap)
    {
        mOk = false;
        return false;
    }
    memcpy(mBuf + mLen, p, n);
    mLen += n;
    return true;
}

bool FieldWriter::U16(uint16_t v)
{
    uint8_t b[2];
    Put16(b, v);
    return Raw(b, 2);
}

bool FieldWriter::U64(uint64_t v)
{
    uint8_t b[8];
    Put64(b, v);
    return Raw(b, 8);
}

bool FieldWriter::Field(const uint8_t * p, size_t n)
{
    if (n > 0xffff)
    {
        mOk = false;
        return false;
    }
    return U16(static_cast<uint16_t>(n)) && (n == 0 || Raw(p, n));
}

bool FieldReader::U8(uint8_t & v)
{
    if (mAt + 1 > mLen)
    {
        return false;
    }
    v = mBuf[mAt++];
    return true;
}

bool FieldReader::U16(uint16_t & v)
{
    if (mAt + 2 > mLen)
    {
        return false;
    }
    v = Get16(mBuf + mAt);
    mAt += 2;
    return true;
}

bool FieldReader::U64(uint64_t & v)
{
    if (mAt + 8 > mLen)
    {
        return false;
    }
    v = Get64(mBuf + mAt);
    mAt += 8;
    return true;
}

bool FieldReader::Field(const uint8_t *& p, size_t & n)
{
    uint16_t l;
    if (!U16(l) || mAt + l > mLen)
    {
        return false;
    }
    p = mBuf + mAt;
    n = l;
    mAt += l;
    return true;
}

} // namespace mgw
