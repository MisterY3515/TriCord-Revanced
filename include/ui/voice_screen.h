#ifndef VOICE_SCREEN_H
#define VOICE_SCREEN_H

#include "screen_manager.h"

namespace UI {

class VoiceScreen : public Screen {
  public:
	VoiceScreen();
	~VoiceScreen() override = default;

	void update() override;
	void renderTop(C3D_RenderTarget *target) override;
	void renderBottom(C3D_RenderTarget *target) override;

	bool hidesMenu() const override { return true; }
};

} // namespace UI

#endif // VOICE_SCREEN_H
