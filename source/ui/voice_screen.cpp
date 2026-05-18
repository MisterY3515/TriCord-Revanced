#include "ui/voice_screen.h"
#include "discord/voice_client.h"
#include "ui/screen_manager.h"
#include <3ds.h>

namespace UI {

VoiceScreen::VoiceScreen() {}

void VoiceScreen::update() {
	u32 kDown = hidKeysDown();

	if (kDown & KEY_B) {
		ScreenManager::getInstance().returnToPreviousScreen();
		return;
	}

	auto &vc = Discord::VoiceClient::getInstance();
	if (!vc.isInChannel()) {
		ScreenManager::getInstance().returnToPreviousScreen();
		return;
	}

	if (kDown & KEY_A) {
		vc.leaveChannel();
		ScreenManager::getInstance().returnToPreviousScreen();
		return;
	}

	if (kDown & KEY_X) {
		vc.setMuted(!vc.isMuted());
	}
}

void VoiceScreen::renderTop(C3D_RenderTarget *target) {
	C2D_SceneBegin(target);
	C2D_TargetClear(target, ScreenManager::colorBackground());

	drawCenteredText(30.0f, 0.5f, 0.7f, 0.7f, ScreenManager::colorText(), "Voice Call", 400.0f);

	auto &vc = Discord::VoiceClient::getInstance();
	const bool connected = vc.isConnected();
	const bool muted = vc.isMuted();

	std::string status = connected ? "Connected" : "Connecting...";
	if (muted) {
		status += " (Muted)";
	}

	drawCenteredText(70.0f, 0.5f, 0.55f, 0.55f, ScreenManager::colorTextMuted(), status, 400.0f);
}

void VoiceScreen::renderBottom(C3D_RenderTarget *target) {
	C2D_SceneBegin(target);
	C2D_TargetClear(target, ScreenManager::colorBackgroundDark());

	drawCenteredText(70.0f, 0.5f, 0.5f, 0.5f, ScreenManager::colorText(), "A: Leave Call", 320.0f);
	drawCenteredText(95.0f, 0.5f, 0.5f, 0.5f, ScreenManager::colorText(), "X: Toggle Mute", 320.0f);
	drawCenteredText(140.0f, 0.5f, 0.45f, 0.45f, ScreenManager::colorTextMuted(), "B: Back", 320.0f);
}

} // namespace UI
