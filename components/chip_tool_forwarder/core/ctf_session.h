// SPDX-License-Identifier: Apache-2.0

// A CASE-type secure session keyed from a shared secret, with no handshake:
// the cloud controller and the forwarder both derive its keys from the stream's
// connection key (ctf_proto.h SessionSecret), the controller as initiator.
// Built from CHIP's public PairingSession API, the way CASE and PASE make
// theirs: allocate (which picks the local session ID), derive, activate.
#pragma once

#include <string.h>

#include <protocols/secure_channel/PairingSession.h>
#include <transport/SessionManager.h>

#include "ctf_proto.h"

namespace ctf {

// A holder that stays on its session. CHIP moves plain holders to the newest
// CASE session with the same peer (SecureSessionTable::NewerSessionAvailable),
// and on the forwarder every cloud session's peer is the cloud controller,
// whichever device or connection it is for.
class StayingSessionHolder : public chip::SessionHolderWithDelegate, private chip::SessionDelegate
{
public:
    StayingSessionHolder() : chip::SessionHolderWithDelegate(static_cast<chip::SessionDelegate &>(*this)) {}

private:
    NewSessionHandlingPolicy GetNewSessionHandlingPolicy() override { return NewSessionHandlingPolicy::kStayAtOldSession; }
    void OnSessionReleased() override {}
};

class SecretSession : public chip::PairingSession
{
public:
    ~SecretSession() override { memset(mSecret, 0, sizeof(mSecret)); }

    // Allocates the session in sm; LocalId() is its ID from then on.
    CHIP_ERROR Allocate(chip::SessionManager & sm, const chip::ScopedNodeId & local, const chip::ScopedNodeId & peer,
                        chip::CryptoContext::SessionRole role)
    {
        mLocal = local;
        mPeer  = peer;
        mRole  = role;
        return AllocateSecureSession(sm, peer);
    }

    uint16_t LocalId() const
    {
        chip::Optional<uint16_t> id = GetLocalSessionId();
        return id.HasValue() ? id.Value() : 0;
    }

    // Keys the session with secret, activates it, and hands it to holder.
    // Either way, this object lets go of it.
    CHIP_ERROR Activate(uint16_t peerSessionId, const uint8_t secret[kKeyLen], const chip::Transport::PeerAddress & address,
                        const chip::ReliableMessageProtocolConfig & remoteMrp, chip::SessionHolder & holder)
    {
        memcpy(mSecret, secret, kKeyLen);
        SetPeerSessionId(peerSessionId);
        SetRemoteMRPConfig(remoteMrp);
        CHIP_ERROR err = ActivateSecureSession(address);
        memset(mSecret, 0, sizeof(mSecret));
        if (err == CHIP_NO_ERROR)
        {
            chip::Optional<chip::SessionHandle> handle = CopySecureSession();
            err = handle.HasValue() && holder.Grab(handle.Value()) ? CHIP_NO_ERROR : CHIP_ERROR_INTERNAL;
        }
        Clear();
        return err;
    }

    // Gives up an allocated session that won't be activated.
    void Abandon() { Clear(); }

    chip::Transport::SecureSession::Type GetSecureSessionType() const override
    {
        return chip::Transport::SecureSession::Type::kCASE;
    }
    chip::ScopedNodeId GetPeer() const override { return mPeer; }
    chip::ScopedNodeId GetLocalScopedNodeId() const override { return mLocal; }
    chip::CATValues GetPeerCATs() const override { return chip::CATValues{}; }

    CHIP_ERROR DeriveSecureSession(chip::CryptoContext & session) override
    {
        VerifyOrReturnError(mSessionManager != nullptr && mSessionManager->GetSessionKeystore() != nullptr,
                            CHIP_ERROR_INCORRECT_STATE);
        return session.InitFromSecret(*mSessionManager->GetSessionKeystore(), chip::ByteSpan(mSecret), chip::ByteSpan(),
                                      chip::CryptoContext::SessionInfoType::kSessionEstablishment, mRole);
    }

private:
    chip::ScopedNodeId mLocal;
    chip::ScopedNodeId mPeer;
    uint8_t mSecret[kKeyLen] = {};
};

} // namespace ctf
