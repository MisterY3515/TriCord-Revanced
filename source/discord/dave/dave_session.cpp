#include "discord/dave/dave_session.h"
#include "log.h"

#include <dave/array_view.h>
#include <dave/dave_interfaces.h>
#include <dave/version.h>

namespace Discord {

namespace {
discord::dave::Codec kAudioCodec = discord::dave::Codec::Opus;
}

DaveSession::DaveSession() : groupId(0), groupEstablished(false) {}

DaveSession::~DaveSession() = default;

bool DaveSession::init(const std::string &selfUserIdIn, const std::string &channelIdSnowflake) {
	try {
		groupId = std::stoull(channelIdSnowflake);

		auto failureCallback = [](std::string const &where, std::string const &reason) {
			Logger::log("[DAVE] MLS failure in %s: %s", where.c_str(), reason.c_str());
		};

		session = discord::dave::mls::CreateSession(nullptr, "", failureCallback);
		encryptor = discord::dave::CreateEncryptor();
		decryptors.clear();
		pendingEncryptorRatchet.reset();
		groupEstablished = false;
		selfUserId = selfUserIdIn;
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] init() failed: %s", e.what());
		return false;
	}
}

bool DaveSession::createOrRecreateGroup() {
	if (!session) {
		return false;
	}
	try {
		groupEstablished = false;
		pendingEncryptorRatchet.reset();
		decryptors.clear();
		std::shared_ptr<::mlspp::SignaturePrivateKey> transientKey;
		session->Init(discord::dave::MaxSupportedProtocolVersion(), groupId, selfUserId, transientKey);
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] createOrRecreateGroup() failed: %s", e.what());
		return false;
	}
}

void DaveSession::reset() {
	try {
		if (session) {
			session->Reset();
		}
	} catch (const std::exception &e) {
		Logger::log("[DAVE] reset() failed: %s", e.what());
	}
	encryptor.reset();
	decryptors.clear();
	pendingEncryptorRatchet.reset();
	groupEstablished = false;
}

bool DaveSession::setExternalSender(const std::vector<uint8_t> &payload) {
	if (!session) {
		return false;
	}
	try {
		session->SetExternalSender(payload);
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] setExternalSender() failed: %s", e.what());
		return false;
	}
}

std::vector<uint8_t> DaveSession::getMarshalledKeyPackage() {
	if (!session) {
		return {};
	}
	try {
		return session->GetMarshalledKeyPackage();
	} catch (const std::exception &e) {
		Logger::log("[DAVE] getMarshalledKeyPackage() failed: %s", e.what());
		return {};
	}
}

std::optional<std::vector<uint8_t>> DaveSession::processProposals(const std::vector<uint8_t> &payload,
                                                                    const std::set<std::string> &recognizedUserIds) {
	if (!session) {
		return std::nullopt;
	}
	try {
		return session->ProcessProposals(payload, recognizedUserIds);
	} catch (const std::exception &e) {
		Logger::log("[DAVE] processProposals() failed: %s", e.what());
		return std::nullopt;
	}
}

void DaveSession::refreshDecryptorRatchetsLocked() {
	// currentState_ inside the MLS session already reflects the new epoch at
	// this point, so every GetKeyRatchet() call below derives new-epoch keys.
	for (auto &pair : decryptors) {
		try {
			auto ratchet = session->GetKeyRatchet(pair.first);
			if (ratchet) {
				pair.second->TransitionToKeyRatchet(std::move(ratchet));
			}
		} catch (const std::exception &e) {
			Logger::log("[DAVE] Failed to refresh decryptor ratchet for %s: %s", pair.first.c_str(), e.what());
		}
	}

	try {
		pendingEncryptorRatchet = session->GetKeyRatchet(selfUserId);
	} catch (const std::exception &e) {
		Logger::log("[DAVE] Failed to derive outgoing key ratchet: %s", e.what());
		pendingEncryptorRatchet.reset();
	}
}

bool DaveSession::processCommit(const std::vector<uint8_t> &payload) {
	if (!session) {
		return false;
	}
	try {
		auto roster = session->ProcessCommit(payload);
		if (std::holds_alternative<discord::dave::failed_t>(roster)) {
			Logger::log("[DAVE] processCommit() hard-rejected the commit");
			return false;
		}
		if (std::holds_alternative<discord::dave::ignored_t>(roster)) {
			Logger::log("[DAVE] processCommit() ignored an unprocessable commit");
			return false;
		}
		groupEstablished = true;
		refreshDecryptorRatchetsLocked();
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] processCommit() failed: %s", e.what());
		return false;
	}
}

bool DaveSession::processWelcome(const std::vector<uint8_t> &payload, const std::set<std::string> &recognizedUserIds) {
	if (!session) {
		return false;
	}
	try {
		auto roster = session->ProcessWelcome(payload, recognizedUserIds);
		if (!roster.has_value()) {
			Logger::log("[DAVE] processWelcome() failed to join the group");
			return false;
		}
		groupEstablished = true;
		refreshDecryptorRatchetsLocked();
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] processWelcome() failed: %s", e.what());
		return false;
	}
}

void DaveSession::executeTransition() {
	if (!encryptor) {
		return;
	}
	try {
		if (pendingEncryptorRatchet) {
			encryptor->SetKeyRatchet(std::move(pendingEncryptorRatchet));
			pendingEncryptorRatchet.reset();
		}
		encryptor->SetPassthroughMode(false);
	} catch (const std::exception &e) {
		Logger::log("[DAVE] executeTransition() failed: %s", e.what());
	}
}

void DaveSession::setPassthroughMode(bool passthrough) {
	try {
		if (encryptor) {
			encryptor->SetPassthroughMode(passthrough);
		}
		for (auto &pair : decryptors) {
			pair.second->TransitionToPassthroughMode(passthrough);
		}
	} catch (const std::exception &e) {
		Logger::log("[DAVE] setPassthroughMode() failed: %s", e.what());
	}
}

discord::dave::IDecryptor *DaveSession::getOrCreateDecryptorLocked(const std::string &userId) {
	auto it = decryptors.find(userId);
	if (it != decryptors.end()) {
		return it->second.get();
	}

	auto decryptor = discord::dave::CreateDecryptor();
	if (!decryptor) {
		return nullptr;
	}

	if (session && groupEstablished) {
		try {
			auto ratchet = session->GetKeyRatchet(userId);
			if (ratchet) {
				decryptor->TransitionToKeyRatchet(std::move(ratchet));
			}
		} catch (const std::exception &e) {
			Logger::log("[DAVE] Failed to seed decryptor for %s: %s", userId.c_str(), e.what());
		}
	}

	auto *raw = decryptor.get();
	decryptors[userId] = std::move(decryptor);
	return raw;
}

bool DaveSession::encryptFrame(uint32_t ssrc, const std::vector<uint8_t> &frame, std::vector<uint8_t> &out) {
	if (!encryptor) {
		return false;
	}
	try {
		encryptor->AssignSsrcToCodec(ssrc, kAudioCodec);
		out.resize(encryptor->GetMaxCiphertextByteSize(discord::dave::MediaType::Audio, frame.size()));
		size_t bytesWritten = 0;
		auto result = encryptor->Encrypt(discord::dave::MediaType::Audio, ssrc,
		                                  discord::dave::MakeArrayView<const uint8_t>(frame.data(), frame.size()),
		                                  discord::dave::MakeArrayView<uint8_t>(out.data(), out.size()), &bytesWritten);
		if (result != discord::dave::IEncryptor::Success) {
			out.clear();
			return false;
		}
		out.resize(bytesWritten);
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] encryptFrame() failed: %s", e.what());
		out.clear();
		return false;
	}
}

bool DaveSession::decryptFrame(const std::string &senderUserId, const std::vector<uint8_t> &frame,
                                std::vector<uint8_t> &out) {
	try {
		auto *decryptor = getOrCreateDecryptorLocked(senderUserId);
		if (!decryptor) {
			return false;
		}
		out.resize(decryptor->GetMaxPlaintextByteSize(discord::dave::MediaType::Audio, frame.size()));
		size_t bytesWritten = 0;
		auto result = decryptor->Decrypt(discord::dave::MediaType::Audio,
		                                  discord::dave::MakeArrayView<const uint8_t>(frame.data(), frame.size()),
		                                  discord::dave::MakeArrayView<uint8_t>(out.data(), out.size()), &bytesWritten);
		if (result != discord::dave::IDecryptor::Success) {
			out.clear();
			return false;
		}
		out.resize(bytesWritten);
		return true;
	} catch (const std::exception &e) {
		Logger::log("[DAVE] decryptFrame() failed for %s: %s", senderUserId.c_str(), e.what());
		out.clear();
		return false;
	}
}

void DaveSession::removeDecryptorForUser(const std::string &userId) {
	decryptors.erase(userId);
}

} // namespace Discord
