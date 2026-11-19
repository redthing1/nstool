#pragma once
#include "types.h"

namespace nstool {

class NczStream : public tc::io::IStream
{
public:
	explicit NczStream(const std::shared_ptr<tc::io::IStream>& file);
	~NczStream() override;

	bool canRead() const override;
	bool canWrite() const override;
	bool canSeek() const override;
	int64_t length() override;
	int64_t position() override;
	size_t read(byte_t* ptr, size_t count) override;
	size_t write(const byte_t* ptr, size_t count) override;
	int64_t seek(int64_t offset, tc::io::SeekOrigin origin) override;
	void setLength(int64_t length) override;
	void flush() override;
	void dispose() override;

private:
	struct Section
	{
		int64_t end;
		bool encrypted;
		std::array<byte_t, 16> key;
		std::array<byte_t, 16> counter;
	};

	struct Decoder;
	std::unique_ptr<Decoder> mDecoder;
	std::shared_ptr<tc::io::IStream> mFile;
	std::vector<Section> mSections;
	std::vector<int64_t> mBlockOffsets;
	int64_t mBlockSize = 0;
	int64_t mPayloadOffset = 0;
	int64_t mLength = 0;
	int64_t mPosition = 0;

	void readBlockTable();
	size_t readPayload(byte_t* ptr, size_t count);
};

}
