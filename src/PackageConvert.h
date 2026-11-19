#pragma once
#include "types.h"
#include "KeyBag.h"

namespace nstool {

void convertPackage(const std::shared_ptr<tc::io::IStream>& input, bool decompress,
	const tc::io::Path& output_path, KeyBag keys);

}
