#pragma once
#include "ui/screen_manager.h"
#include <string>
#include <mutex>
#include <thread>

namespace UI {

class UpdateScreen : public Screen {
public:
	UpdateScreen(const std::string& downloadUrl, const std::string& assetName);
	~UpdateScreen();

	void renderTop(C3D_RenderTarget *target) override;
	void renderBottom(C3D_RenderTarget *target) override;
	void update() override;

private:
	std::string downloadUrl;
	std::string assetName;
	
	std::thread updateThread;
	std::mutex progressMutex;
	
	size_t currentBytes;
	size_t totalBytes;
	std::string statusText;
	bool updateComplete;
	bool isSuccess;

	void performUpdate();
};

} // namespace UI
