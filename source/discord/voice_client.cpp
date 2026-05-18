void VoiceClient::onVoiceServerUpdate(const std::string &token, const std::string &endpoint) {
	std::lock_guard<std::recursive_mutex> lock(voiceMutex);
	if (state != State::WAITING_SERVER || channelId.empty()) {
		Logger::log("[Voice] Ignoring Voice Server Update: state=%d, channelId=%s", (int)state, channelId.c_str());
		return;
	}
	
	voiceToken = token;
	Logger::log("[Voice] Received server update. Endpoint: %s", endpoint.c_str());
	
	// Remove port from endpoint if present (e.g., vss1.discord.gg:443 -> vss1.discord.gg)
	voiceEndpoint = endpoint;
	size_t portPos = voiceEndpoint.find(':');
	if (portPos != std::string::npos) {
		voiceEndpoint = voiceEndpoint.substr(0, portPos);
	}
	
	// Start Voice WebSocket connection in a separate thread to not block gateway
	state = State::CONNECTING_WS;
	
	// Use wss:// as required by Discord Voice Gateway
	std::string wsUrl = "wss://" + voiceEndpoint + "/?v=4";
	Logger::log("[Voice] Connecting to Voice WebSocket: %s", wsUrl.c_str());
	
	voiceWs.connect(wsUrl);
}

void VoiceClient::sendSelectProtocol(const std::string &ip, int port) {
	state = State::SELECTING_PROTOCOL;

	rapidjson::Document d;
	d.SetObject();
	auto &alloc = d.GetAllocator();

	d.AddMember("op", 1, alloc);
	
	rapidjson::Value data(rapidjson::kObjectType);
	data.AddMember("protocol", "udp", alloc);
	
	rapidjson::Value data2(rapidjson::kObjectType);
	data2.AddMember("address", rapidjson::Value(ip.c_str(), alloc), alloc);
	data2.AddMember("port", port, alloc);
	data2.AddMember("mode", "xsalsa20_poly1305", alloc);
	
	data.AddMember("data", data2, alloc);
	d.AddMember("d", data, alloc);

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	d.Accept(writer);

	voiceWs.send(buffer.GetString());
	Logger::log("[Voice] Sent Select Protocol");
}

void VoiceClient::update() {
	std::lock_guard<std::recursive_mutex> lock(voiceMutex);
	if (state == State::DISCONNECTED || state == State::WAITING_SERVER) return;

	voiceWs.poll();

	uint64_t now = osGetTime();

	if (state == State::READY || state == State::DISCOVERING_IP || state == State::SELECTING_PROTOCOL) {
		// Heartbeat WS (keep connection alive)
		if (heartbeatInterval > 0 && now - lastHeartbeatTime >= (uint64_t)heartbeatInterval) {
			lastHeartbeatTime = now;
			rapidjson::Document d;
			d.SetObject();
			auto &alloc = d.GetAllocator();
			d.AddMember("op", 3, alloc); // Heartbeat
			d.AddMember("d", (uint64_t)now, alloc);
			
			rapidjson::StringBuffer buffer;
			rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
			d.Accept(writer);
			voiceWs.send(buffer.GetString());
		}
	}
	
	if (state == State::DISCOVERING_IP) {
		// Retry discovery se non riceviamo risposta entro 1 secondo
		if (osGetTime() - lastDiscoveryTime > 1000) {
			if (discoveryRetries < 5) {
				performIpDiscovery();
			} else {
				Logger::log("[Voice] IP Discovery failed after 5 retries. Leaving channel.");
				leaveChannel();
			}
		}

		uint8_t buf[256];
		int len = udp.recv(buf, sizeof(buf), 0); // Non-blocking
		if (len >= 74) {
			// Il pacchetto di risposta ha l'IP a partire dall'offset 8 (fino a 64 bytes, null terminated)
			// e la porta all'offset 72 (2 bytes, Big Endian)
			char ip[65] = {0};
			memcpy(ip, buf + 8, 64);
			std::string myIp = std::string(ip);
			
			uint16_t portBE;
			memcpy(&portBE, buf + 72, 2);
			uint16_t myPort = __builtin_bswap16(portBE);

			if (!myIp.empty() && myPort > 0) {
				Logger::log("[Voice] IP Discovered: %s:%d", myIp.c_str(), myPort);
				sendSelectProtocol(myIp, myPort);
			}
		} else if (len > 0) {
				Logger::log("[Voice] Unexpected UDP packet size during discovery: %d", len);
		}
	} else if (state == State::READY) {
			// Ricevi e processa TUTTI i pacchetti audio in coda (UDP)
			uint8_t buf[2048];
			int len;
			static int packetCount = 0;
			while ((len = udp.recv(buf, sizeof(buf), 0)) > 12) {
				packetCount++;
				if (packetCount % 50 == 0) {
					Logger::log("[Voice] UDP recv: %d bytes (pkt %d)", len, packetCount);
				}

				if (decryptAudioPacket(buf, len, decodeBuf)) {
					// Audio decriptato, ora va decodificato
					int16_t pcm[1920]; // 1920 samples (max 120ms at 16kHz)
					int samples = opus_decode(decoder, decodeBuf.data(), decodeBuf.size(), pcm, 1920, 0);
					if (packetCount % 50 == 0) {
						Logger::log("[Voice] Decrypt OK, Opus samples: %d", samples);
					}
					if (samples > 0) {
						Audio::AudioManager::getInstance().queuePcm(pcm, samples);
					}
				} else {
					if (packetCount % 50 == 0) {
						Logger::log("[Voice] Decrypt FAILED for %d bytes", len);
					}
				}
			}

			// Invio pacchetti audio
			if (!muted) {
				if (Audio::AudioManager::getInstance().hasNewSamples()) {
					int16_t tempBuf[1024];
					size_t read = Audio::AudioManager::getInstance().readSamples(tempBuf, 1024);
					if (read > 0) {
						micAccumulator.insert(micAccumulator.end(), tempBuf, tempBuf + read);
					}
				}
				
				// Invia in blocchi da 20ms (320 samples a 16kHz)
				while (micAccumulator.size() >= 320) {
					int16_t micBuf[320];
					for(int i = 0; i < 320; i++) {
						micBuf[i] = micAccumulator.front();
						micAccumulator.pop_front();
					}
					
					uint8_t opusBuf[1024];
					int encodedLen = opus_encode(encoder, micBuf, 320, opusBuf, sizeof(opusBuf));
					if (encodedLen > 0) {
						encryptAudioPacket(opusBuf, encodedLen, encodeBuf);
						udp.send(encodeBuf.data(), encodeBuf.size());
					}
				}
			} else {
				// Se mutati, svuota comunque l'AudioManager per evitare lag quando si smuta
				if (Audio::AudioManager::getInstance().hasNewSamples()) {
					int16_t discardBuf[1024];
					Audio::AudioManager::getInstance().readSamples(discardBuf, 1024);
				}
				micAccumulator.clear();
			}
		}
	}
}

void VoiceClient::encryptAudioPacket(const uint8_t *opus, size_t len, std::vector<uint8_t> &out) {
	uint8_t header[12];
	header[0] = 0x80; // RTP version 2
	header[1] = 0x78; // Payload type (120 for Opus)
	
	header[2] = (sequence >> 8) & 0xFF;
	header[3] = sequence & 0xFF;
	
	header[4] = (timestamp >> 24) & 0xFF;
	header[5] = (timestamp >> 16) & 0xFF;
	header[6] = (timestamp >> 8) & 0xFF;
	header[7] = timestamp & 0xFF;
	
	header[8] = (ssrc >> 24) & 0xFF;
	header[9] = (ssrc >> 16) & 0xFF;
	header[10] = (ssrc >> 8) & 0xFF;
	header[11] = ssrc & 0xFF;

	// Nonce per xsalsa20_poly1305 è l'header RTP di 12 byte seguito da 12 byte di zero
	uint8_t nonce[24];
	memcpy(nonce, header, 12);
	memset(nonce + 12, 0, 12);

	out.resize(12 + len + 16); // 12 header + len data + 16 MAC
	memcpy(out.data(), header, 12);
	
	crypto_secretbox_easy(out.data() + 12, opus, len, nonce, secretKey);
	
	sequence++;
	timestamp += 320; // 20ms of 16kHz audio
}

bool VoiceClient::decryptAudioPacket(const uint8_t *data, size_t len, std::vector<uint8_t> &out) {
	if (len < 12 + 16) return false;

	// L'header RTP è di 12 byte
	uint8_t nonce[24];
	memcpy(nonce, data, 12);
	memset(nonce + 12, 0, 12);

	size_t cipherLen = len - 12;
	out.resize(cipherLen - 16);

	if (crypto_secretbox_open_easy(out.data(), data + 12, cipherLen, nonce, secretKey) != 0) {
		return false;
	}

	return true;
}

bool VoiceClient::isUserSpeaking(const std::string &userId) const {
	std::lock_guard<std::recursive_mutex> lock(voiceMutex);
	auto it = speakingStates.find(userId);
	if (it != speakingStates.end()) {
		return it->second;
	}
	return false;
}

} // namespace Discord
