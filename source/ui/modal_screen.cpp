#include "ui/modal_screen.h"
#include "core/i18n.h"
#include <citro2d.h>

namespace UI {

ModalScreen::ModalScreen(const std::string& title, const std::string& desc,
                         const std::vector<std::string>& buttons, std::function<void(int)> onButton)
    : title(title), desc(desc), buttons(buttons), onButton(onButton), selectedIndex(0) {
}

void ModalScreen::update() {
	u32 kDown = hidKeysDown();
	
	if (kDown & KEY_LEFT) {
		if (selectedIndex > 0) selectedIndex--;
	}
	if (kDown & KEY_RIGHT) {
		if (selectedIndex < (int)buttons.size() - 1) selectedIndex++;
	}
	if (kDown & KEY_A) {
		if (onButton) {
			onButton(selectedIndex);
		}
		ScreenManager::getInstance().returnToPreviousScreen();
	}
	if (kDown & KEY_B) {
		// Cancel = call with -1 or just go back
		ScreenManager::getInstance().returnToPreviousScreen();
	}
}

void ModalScreen::renderTop(C3D_RenderTarget *target) {
	u32 bgColor = ScreenManager::colorBackground();
	C2D_DrawRectSolid(0, 0, 0, 400, 240, bgColor);
	
	// Title
	C2D_TextBuf buf = C2D_TextBufNew(512);
	C2D_Text titleText;
	C2D_TextParse(&titleText, buf, title.c_str());
	C2D_TextOptimize(&titleText);
	C2D_DrawText(&titleText, C2D_WithColor | C2D_AlignCenter, 200.0f, 60.0f, 0.5f, 0.6f, 0.6f, 
	             ScreenManager::colorText());
	
	// Description
	C2D_Text descText;
	C2D_TextParse(&descText, buf, desc.c_str());
	C2D_TextOptimize(&descText);
	C2D_DrawText(&descText, C2D_WithColor | C2D_AlignCenter, 200.0f, 100.0f, 0.5f, 0.45f, 0.45f, 
	             ScreenManager::colorTextMuted());
	
	C2D_TextBufDelete(buf);
}

void ModalScreen::renderBottom(C3D_RenderTarget *target) {
	u32 bgColor = ScreenManager::colorBackground();
	C2D_DrawRectSolid(0, 0, 0, 320, 240, bgColor);
	
	if (buttons.empty()) return;
	
	float totalWidth = 280.0f;
	float buttonWidth = totalWidth / buttons.size();
	float startX = (320.0f - totalWidth) / 2.0f;
	float buttonY = 100.0f;
	float buttonH = 36.0f;
	
	C2D_TextBuf buf = C2D_TextBufNew(256);
	
	for (int i = 0; i < (int)buttons.size(); i++) {
		float bx = startX + i * buttonWidth + 2.0f;
		float bw = buttonWidth - 4.0f;
		
		u32 btnColor = (i == selectedIndex) ? ScreenManager::colorAccent() : ScreenManager::colorBackgroundLight();
		u32 txtColor = (i == selectedIndex) ? C2D_Color32(255, 255, 255, 255) : ScreenManager::colorText();
		
		C2D_DrawRectSolid(bx, buttonY, 0.5f, bw, buttonH, btnColor);
		
		C2D_Text btnText;
		C2D_TextParse(&btnText, buf, buttons[i].c_str());
		C2D_TextOptimize(&btnText);
		float tw, th;
		C2D_TextGetDimensions(&btnText, 0.45f, 0.45f, &tw, &th);
		C2D_DrawText(&btnText, C2D_WithColor, bx + (bw - tw) / 2.0f, buttonY + (buttonH - th) / 2.0f, 
		             0.6f, 0.45f, 0.45f, txtColor);
	}
	
	C2D_TextBufDelete(buf);
	
	// Hint at bottom
	C2D_TextBuf hintBuf = C2D_TextBufNew(128);
	C2D_Text hintText;
	C2D_TextParse(&hintText, hintBuf, "\xEE\x80\x00 Select  \xEE\x80\x01 Cancel");
	C2D_TextOptimize(&hintText);
	float hw, hh;
	C2D_TextGetDimensions(&hintText, 0.4f, 0.4f, &hw, &hh);
	C2D_DrawText(&hintText, C2D_WithColor, (320.0f - hw) / 2.0f, 220.0f, 0.5f, 0.4f, 0.4f, 
	             ScreenManager::colorTextMuted());
	C2D_TextBufDelete(hintBuf);
}

} // namespace UI
