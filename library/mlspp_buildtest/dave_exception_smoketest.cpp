#include "dave_exception_smoketest.h"

#include <stdexcept>
#include <typeinfo>

namespace {
void throwingInner() {
	throw std::runtime_error("dave smoke test exception");
}
} // namespace

bool daveExceptionSmokeTest() {
	// Exercises both -fexceptions (try/throw/catch) and -frtti (typeid) so a
	// build misconfiguration that silently drops either flag is caught here
	// rather than inside the much larger mlspp/libdave port later.
	try {
		throwingInner();
	} catch (const std::exception &e) {
		return typeid(e) == typeid(std::runtime_error);
	}
	return false;
}
