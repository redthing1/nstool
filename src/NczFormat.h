#pragma once
#include "types.h"
#include <tc/bn.h>

namespace nstool { namespace ncz {

// https://github.com/nicoboss/nsz/blob/master/docs/formats.md
const int64_t kHeaderSize = 0x4000;
const char kSectionMagic[] = "NCZSECTN";

struct SectionHeader
{
	tc::bn::le64<int64_t> offset;
	tc::bn::le64<int64_t> size;
	tc::bn::le64<uint64_t> crypto_type;
	std::array<byte_t, 8> padding;
	std::array<byte_t, 16> key;
	std::array<byte_t, 16> counter;
};
static_assert(sizeof(SectionHeader) == 64, "NCZ section header size.");

}}
