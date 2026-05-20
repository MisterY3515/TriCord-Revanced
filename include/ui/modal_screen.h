#pragma once
#include "ui/screen_manager.h"
#include <string>
#include <functional>
#include <vector>

namespace UI {

class ModalScreen : public Screen {
public:
	ModalScreen(const std::string& title, const std::string& desc,
	            const std::vector<std::string>& buttons, std::function<void(int)> onButton);
	~ModalScreen() = default;

	void renderTop(C3D_RenderTarget *target) override;
	void renderBottom(C3D_RenderTarget *target) override;
	void update() override;
	bool hidesMenu() const override { return true; }

private:
	std::string title;
	std::string desc;
	std::vector<std::string> buttons;
	std::function<void(int)> onButton;
	int selectedIndex;
};

} // namespace UI
