#ifndef DAVE_SESSION_H
#define DAVE_SESSION_H

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace discord {
namespace dave {
class IEncryptor;
class IDecryptor;
class IKeyRatchet;
namespace mls {
class ISession;
} // namespace mls
} // namespace dave
} // namespace discord

namespace Discord {

// Exception-safe wrapper around libdave's MLS session plus its Encryptor/
// Decryptor media-framing layer. This is the only place in TriCord that calls
// into the vendored mlspp/libdave tree directly; every public method catches
// all exceptions so none ever cross into the rest of the no-exceptions
// TriCord codebase (see Gestione/DAVE_HANDOFF.md, "Critical build blocker").
//
// Not thread-safe by itself: callers (VoiceClient) already hold voiceMutex
// for every call into this class.
class DaveSession {
  public:
	DaveSession();
	~DaveSession();

	DaveSession(const DaveSession &) = delete;
	DaveSession &operator=(const DaveSession &) = delete;

	// Tears down any existing MLS state and creates a fresh underlying MLS
	// session bound to selfUserId/channelIdSnowflake (decimal string, becomes
	// the MLS group ID). Call once per voice connection, before the gateway
	// starts sending DAVE opcodes (right after a Session Description with
	// dave_protocol_version > 0). Does NOT create the MLS group itself --
	// see createOrRecreateGroup().
	bool init(const std::string &selfUserId, const std::string &channelIdSnowflake);
	void reset();
	bool isGroupEstablished() const { return groupEstablished; }

	// Opcode 25 (DAVE MLS External Sender) payload. The underlying MLS session
	// retains this across createOrRecreateGroup() calls, so it only needs to
	// be (re-)provided when the gateway actually sends a new one.
	bool setExternalSender(const std::vector<uint8_t> &payload);

	// Opcode 24 (DAVE Protocol Prepare Epoch) with epoch == 1: (re)creates the
	// MLS group from scratch. Must be called after setExternalSender().
	bool createOrRecreateGroup();

	// Opcode 26 (DAVE MLS Key Package) payload to send back to the gateway.
	std::vector<uint8_t> getMarshalledKeyPackage();

	// Opcode 27 (DAVE MLS Proposals) payload. Returns the commit(+welcome) to
	// send back as opcode 28, if this session decided to act as committer.
	std::optional<std::vector<uint8_t>> processProposals(const std::vector<uint8_t> &payload,
	                                                       const std::set<std::string> &recognizedUserIds);

	// Opcode 29 (DAVE MLS Announce Commit Transition) commit payload. On
	// success, immediately refreshes all known decryptors to accept the new
	// epoch (kept alongside old-epoch keys for the grace window) and stages
	// the new outgoing key ratchet for executeTransition().
	bool processCommit(const std::vector<uint8_t> &payload);

	// Opcode 30 (DAVE MLS Welcome) payload, for newly joining this session.
	bool processWelcome(const std::vector<uint8_t> &payload, const std::set<std::string> &recognizedUserIds);

	// Opcode 22 (DAVE Protocol Execute Transition): switch outgoing encryption
	// to the key ratchet staged by the most recent processCommit/processWelcome.
	void executeTransition();

	// Opcode 21 (DAVE Protocol Prepare Transition) downgrade path: encrypt/
	// decrypt become passthrough (no MLS group required).
	void setPassthroughMode(bool passthrough);

	// Hooked into VoiceClient's audio pipeline between Opus and the existing
	// RTP transport encryption. ssrc identifies the local sender for codec
	// bookkeeping; senderUserId identifies the remote sender's key ratchet.
	bool encryptFrame(uint32_t ssrc, const std::vector<uint8_t> &frame, std::vector<uint8_t> &out);
	bool decryptFrame(const std::string &senderUserId, const std::vector<uint8_t> &frame,
	                   std::vector<uint8_t> &out);

	// Drops the cached decryptor for a user who left the channel.
	void removeDecryptorForUser(const std::string &userId);

  private:
	discord::dave::IDecryptor *getOrCreateDecryptorLocked(const std::string &userId);
	void refreshDecryptorRatchetsLocked();

	std::unique_ptr<discord::dave::mls::ISession> session;
	std::unique_ptr<discord::dave::IEncryptor> encryptor;
	std::map<std::string, std::unique_ptr<discord::dave::IDecryptor>> decryptors;
	std::unique_ptr<discord::dave::IKeyRatchet> pendingEncryptorRatchet;
	std::string selfUserId;
	uint64_t groupId;
	bool groupEstablished;
};

} // namespace Discord

#endif // DAVE_SESSION_H
