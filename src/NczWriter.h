#pragma once
#include "types.h"
#include "KeyBag.h"

namespace nstool {

// Write an NCZ when it is smaller than the source NCA. On fallback, restore
// the output position so the caller can write the original member there.
bool tryWriteNcz(const std::shared_ptr<tc::io::IStream>& file, tc::io::IStream& output, const KeyBag& keys);

}
