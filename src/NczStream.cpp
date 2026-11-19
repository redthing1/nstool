#include "NczStream.h"

#include <tc/bn.h>
#include <tc/crypto/Aes128CtrEncryptor.h>
#include <tc/io/StreamUtil.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <zstd.h>

namespace {

// https://github.com/nicoboss/nsz/blob/master/docs/formats.md
const char* const kModuleName = "nstool::NczStream";
const int64_t kHeaderSize = 0x4000;
const size_t kBufferSize = 0x10000;

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

struct BlockHeader
{
	char magic[8];
	byte_t version;
	byte_t type;
	byte_t reserved;
	byte_t block_size_exponent;
	tc::bn::le32<uint32_t> block_count;
	tc::bn::le64<int64_t> decompressed_size;
};
static_assert(sizeof(BlockHeader) == 24, "NCZ block header size.");

void readExact(tc::io::IStream& file, byte_t* data, size_t size)
{
	while (size != 0)
	{
		const size_t read = file.read(data, size);
		if (read == 0)
			throw tc::io::IOException(kModuleName, "Truncated NCZ file.");
		data += read;
		size -= read;
	}
}

template <typename T>
void readExact(tc::io::IStream& file, T& data)
{
	readExact(file, reinterpret_cast<byte_t*>(&data), sizeof(data));
}

void checkZstd(size_t result)
{
	if (ZSTD_isError(result))
		throw tc::io::IOException(kModuleName, ZSTD_getErrorName(result));
}

void encryptSection(byte_t* data, size_t size, int64_t offset,
	const std::array<byte_t, 16>& key, const std::array<byte_t, 16>& counter)
{
	tc::crypto::Aes128CtrEncryptor encryptor;
	encryptor.initialize(key.data(), key.size(), counter.data(), counter.size());
	const size_t block_size = tc::crypto::Aes128CtrEncryptor::kBlockSize;
	uint64_t block = offset / block_size;
	const size_t skip = offset % block_size;
	if (skip != 0)
	{
		std::array<byte_t, block_size> first = {};
		const size_t take = std::min(size, block_size - skip);
		std::memcpy(first.data() + skip, data, take);
		encryptor.encrypt(first.data(), first.data(), first.size(), block++);
		std::memcpy(data, first.data() + skip, take);
		data += take;
		size -= take;
	}
	if (size != 0)
		encryptor.encrypt(data, data, size, block);
}

}

// A single decoded buffer covers repeated reads. For a backward seek outside
// the buffer, replay from the start of the solid stream or the selected block.
struct nstool::NczStream::Decoder
{
	std::unique_ptr<ZSTD_DCtx, decltype(&ZSTD_freeDCtx)> context{ZSTD_createDCtx(), ZSTD_freeDCtx};
	std::array<byte_t, kBufferSize> input;
	std::array<byte_t, kBufferSize> output;
	ZSTD_inBuffer pending{input.data(), 0, 0};
	int64_t frame_offset = -1;
	int64_t input_offset = 0;
	int64_t output_offset = 0;
	int64_t output_end = 0;

	void reset(int64_t offset)
	{
		if (!context)
			throw tc::io::IOException(kModuleName, "Could not allocate a Zstandard decoder.");

		checkZstd(ZSTD_DCtx_reset(context.get(), ZSTD_reset_session_only));
		pending = {input.data(), 0, 0};
		frame_offset = offset;
		input_offset = offset;
		output_offset = 0;
		output_end = 0;
	}

	size_t decompress(tc::io::IStream& file, int64_t input_end, ZSTD_outBuffer& out)
	{
		if (pending.pos == pending.size && input_offset < input_end)
		{
			const size_t size = tc::io::IOUtil::getReadableCount(input_end, input_offset, input.size());
			file.seek(input_offset, tc::io::SeekOrigin::Begin);
			readExact(file, input.data(), size);
			pending = {input.data(), size, 0};
			input_offset += size;
		}

		const size_t input_before = pending.pos;
		const size_t output_before = out.pos;
		const size_t result = ZSTD_decompressStream(context.get(), &out, &pending);
		checkZstd(result);
		if (result != 0 && pending.pos == input_before && out.pos == output_before)
			throw tc::io::IOException(kModuleName, "Incomplete NCZ Zstandard frame.");
		return result;
	}

	void fill(tc::io::IStream& file, int64_t input_end, int64_t output_size)
	{
		output_offset = output_end;
		ZSTD_outBuffer out{output.data(), tc::io::IOUtil::getReadableCount(output_size, output_end, output.size()), 0};
		size_t result;
		do {
			result = decompress(file, input_end, out);
		} while (result != 0 && out.pos < out.size);

		output_end += out.pos;
		if (output_end == output_size)
		{
			// Finish consuming the frame, including its checksum, without accepting extra output.
			byte_t extra;
			ZSTD_outBuffer tail{&extra, 1, 0};
			while (result != 0 && tail.pos == 0)
				result = decompress(file, input_end, tail);
			if (tail.pos != 0 || pending.pos != pending.size || input_offset != input_end)
				throw tc::io::IOException(kModuleName, "Unexpected data at end of NCZ Zstandard frame.");
		}
		else if (result == 0)
		{
			throw tc::io::IOException(kModuleName, "NCZ Zstandard frame ended before its declared size.");
		}
	}

	size_t decode(tc::io::IStream& file, int64_t start, int64_t input_end, int64_t output_size, int64_t offset,
		byte_t* dest, size_t count)
	{
		try {
			if (frame_offset != start || offset < output_offset)
				reset(start);
			while (offset >= output_end)
				fill(file, input_end, output_size);
		} catch (...) {
			frame_offset = -1;
			throw;
		}
		count = tc::io::IOUtil::getReadableCount(output_end, offset, count);
		std::memcpy(dest, output.data() + (offset - output_offset), count);
		return count;
	}
};

nstool::NczStream::NczStream(const std::shared_ptr<tc::io::IStream>& file) :
	mFile(file)
{
	if (!mFile || !mFile->canRead() || !mFile->canSeek())
		throw tc::NotSupportedException(kModuleName, "NCZ requires a readable, seekable stream.");

	mFile->seek(kHeaderSize, tc::io::SeekOrigin::Begin);
	char magic[8];
	tc::bn::le64<uint64_t> section_count;
	readExact(*mFile, magic);
	readExact(*mFile, section_count);
	if (std::memcmp(magic, "NCZSECTN", sizeof(magic)) != 0)
		throw tc::io::IOException(kModuleName, "Missing NCZSECTN header.");
	if (section_count.unwrap() == 0 ||
		section_count.unwrap() > uint64_t(mFile->length() - mFile->position()) / sizeof(SectionHeader))
		throw tc::io::IOException(kModuleName, "Invalid NCZ section count.");

	int64_t end = 0;
	for (uint64_t i = 0; i < section_count.unwrap(); i++)
	{
		SectionHeader header;
		readExact(*mFile, header);
		const int64_t offset = header.offset.unwrap();
		const int64_t size = header.size.unwrap();
		const uint64_t crypto_type = header.crypto_type.unwrap();
		if (offset < 0 || size < 0 || (i != 0 && offset != end) ||
			size > std::numeric_limits<int64_t>::max() - offset)
			throw tc::io::IOException(kModuleName, "Invalid NCZ section range.");
		if (crypto_type > 4)
			throw tc::io::IOException(kModuleName, "Unsupported NCZ section encryption type.");

		// Any gap before the first section is stored verbatim in the Zstandard payload.
		if (i == 0 && offset > kHeaderSize)
			mSections.push_back({offset, false, {}, {}});

		end = offset + size;
		if (size != 0 && end > kHeaderSize)
		{
			// NCZ uses the upper half of the counter and an absolute NCA block number.
			std::fill(header.counter.begin() + 8, header.counter.end(), 0);
			mSections.push_back({end, crypto_type == 3 || crypto_type == 4, header.key, header.counter});
		}
	}
	if (end <= kHeaderSize)
		throw tc::io::IOException(kModuleName, "Empty NCZ payload.");

	mLength = end;
	mPayloadOffset = mFile->position();
	readExact(*mFile, magic);
	if (std::memcmp(magic, "NCZBLOCK", sizeof(magic)) == 0)
		readBlockTable();
}

void nstool::NczStream::readBlockTable()
{
	mFile->seek(mPayloadOffset, tc::io::SeekOrigin::Begin);
	BlockHeader header;
	readExact(*mFile, header);
	if (header.version != 2 || header.type != 1 ||
		header.block_size_exponent < 14 || header.block_size_exponent > 32)
		throw tc::io::IOException(kModuleName, "Unsupported NCZ block header.");

	mBlockSize = int64_t(1) << header.block_size_exponent;
	const int64_t payload_size = mLength - kHeaderSize;
	const int64_t block_count = 1 + (payload_size - 1) / mBlockSize;
	if (header.decompressed_size.unwrap() != payload_size || header.block_count.unwrap() != block_count ||
		block_count > (mFile->length() - mFile->position()) / 4)
		throw tc::io::IOException(kModuleName, "Invalid NCZ block table.");

	int64_t offset = mFile->position() + block_count * 4;
	mBlockOffsets.push_back(offset);
	for (int64_t block = 0; block < block_count; block++)
	{
		tc::bn::le32<uint32_t> size;
		readExact(*mFile, size);
		const int64_t block_size = std::min(mBlockSize, payload_size - block * mBlockSize);
		if (size.unwrap() == 0 || size.unwrap() > block_size || size.unwrap() > mFile->length() - offset)
			throw tc::io::IOException(kModuleName, "Invalid NCZ block size.");
		offset += size.unwrap();
		mBlockOffsets.push_back(offset);
	}
	if (offset != mFile->length())
		throw tc::io::IOException(kModuleName, "Unexpected data after NCZ blocks.");
}

nstool::NczStream::~NczStream() = default;

bool nstool::NczStream::canRead() const { return mFile != nullptr; }
bool nstool::NczStream::canWrite() const { return false; }
bool nstool::NczStream::canSeek() const { return canRead(); }
int64_t nstool::NczStream::length() { return mLength; }
int64_t nstool::NczStream::position() { return mPosition; }

size_t nstool::NczStream::read(byte_t* ptr, size_t count)
{
	if (!mFile)
		throw tc::ObjectDisposedException(kModuleName, "NCZ stream is closed.");

	count = tc::io::IOUtil::getReadableCount(mLength, mPosition, count);
	size_t read = 0;
	while (read < count)
	{
		size_t size = count - read;
		if (mPosition < kHeaderSize)
		{
			size = tc::io::IOUtil::getReadableCount(kHeaderSize, mPosition, size);
			mFile->seek(mPosition, tc::io::SeekOrigin::Begin);
			readExact(*mFile, ptr + read, size);
		}
		else
		{
			const auto section = std::upper_bound(mSections.begin(), mSections.end(), mPosition,
				[](int64_t offset, const Section& entry) { return offset < entry.end; });
			size = tc::io::IOUtil::getReadableCount(section->end, mPosition, size);
			size = readPayload(ptr + read, size);
			if (section->encrypted)
				encryptSection(ptr + read, size, mPosition, section->key, section->counter);
		}
		mPosition += size;
		read += size;
	}
	if (mPosition == mLength)
		mDecoder.reset();
	return read;
}

size_t nstool::NczStream::readPayload(byte_t* ptr, size_t count)
{
	int64_t offset = mPosition - kHeaderSize;
	int64_t output_size = mLength - kHeaderSize;
	int64_t start = mPayloadOffset;
	int64_t end = mFile->length();
	if (mBlockSize != 0)
	{
		const int64_t block = offset / mBlockSize;
		start = mBlockOffsets[block];
		end = mBlockOffsets[block + 1];
		output_size = std::min(mBlockSize, output_size - block * mBlockSize);
		offset %= mBlockSize;
		if (end - start == output_size)
		{
			count = tc::io::IOUtil::getReadableCount(output_size, offset, count);
			mFile->seek(start + offset, tc::io::SeekOrigin::Begin);
			readExact(*mFile, ptr, count);
			return count;
		}
	}

	if (!mDecoder)
		mDecoder.reset(new Decoder());
	return mDecoder->decode(*mFile, start, end, output_size, offset, ptr, count);
}

size_t nstool::NczStream::write(const byte_t*, size_t)
{
	throw tc::NotSupportedException(kModuleName, "NCZ stream is read-only.");
}

int64_t nstool::NczStream::seek(int64_t offset, tc::io::SeekOrigin origin)
{
	if (!mFile)
		throw tc::ObjectDisposedException(kModuleName, "NCZ stream is closed.");

	const int64_t base = tc::io::StreamUtil::getSeekResult(0, origin, mPosition, mLength);
	if (offset < -base || offset > std::numeric_limits<int64_t>::max() - base)
		throw tc::ArgumentOutOfRangeException(kModuleName, "Invalid NCZ seek offset.");
	mPosition = base + offset;
	return mPosition;
}

void nstool::NczStream::setLength(int64_t)
{
	throw tc::NotSupportedException(kModuleName, "NCZ stream is read-only.");
}

void nstool::NczStream::flush()
{
}

void nstool::NczStream::dispose()
{
	mDecoder.reset();
	mFile.reset();
	mSections.clear();
	mBlockOffsets.clear();
	mLength = 0;
	mPosition = 0;
}
