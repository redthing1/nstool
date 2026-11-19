#include "NczWriter.h"
#include "NczFormat.h"
#include "NcaProcess.h"

#include <pietendo/hac/ContentArchiveUtil.h>
#include <pietendo/hac/define/aesctrexstorage.h>
#include <tc/crypto/Aes128CtrEncryptedStream.h>
#include <tc/crypto/Sha2256Generator.h>

#include <algorithm>
#include <zstd.h>

namespace {

using namespace nstool::ncz;
using namespace pie::hac;

const char* const kModuleName = "nstool::NczWriter";
const size_t kBufferSize = 0x100000;
const int kCompressionLevel = 9;

void readExact(tc::io::IStream& input, byte_t* data, size_t size)
{
	if (input.read(data, size) != size)
		throw tc::io::IOException(kModuleName, "Truncated NCA data.");
}

void writeExact(tc::io::IStream& output, const void* data, size_t size)
{
	if (output.write(static_cast<const byte_t*>(data), size) != size)
		throw tc::io::IOException(kModuleName, "Failed to write NCZ data.");
}

size_t checkZstd(size_t result)
{
	if (ZSTD_isError(result))
		throw tc::io::IOException(kModuleName, ZSTD_getErrorName(result));
	return result;
}

using SectionList = std::vector<SectionHeader>;

void addSection(SectionList& sections, int64_t offset, int64_t size, nca::EncryptionType type,
	const detail::aes128_key_t& key = {}, const detail::aes_iv_t& counter = {})
{
	if (size == 0)
		return;
	SectionHeader section{};
	section.offset.wrap(offset);
	section.size.wrap(size);
	section.crypto_type.wrap(type);
	section.key = key;
	section.counter = counter;
	sections.push_back(section);
}

void addPatchSections(SectionList& sections, const std::shared_ptr<tc::io::IStream>& file,
	const ContentArchiveHeader::sPartitionEntry& part, const sContentArchiveFsHeader& header,
	const detail::aes128_key_t& key, const detail::aes_iv_t& counter)
{
	const auto& table = header.patch_info.aes_ctr_ex_bucket;
	const auto table_offset = table.offset.unwrap();
	const auto table_size = table.size.unwrap();
	const auto count = table.header.entry_count.unwrap();
	const auto node_size = aesctrexstorage::kNodeSize;
	if (table.header.st_magic.unwrap() != bktr::kBktrStructMagic ||
		table.header.version.unwrap() != bktr::kBktrVersion || count <= 0 ||
		table_offset > uint64_t(part.size) || table_size > uint64_t(part.size) - table_offset ||
		table_size < 2 * node_size)
		throw tc::Exception(kModuleName, "Invalid NCA AES-CTR-Ex table.");

	tc::crypto::Aes128CtrEncryptedStream table_reader(file, key, counter);
	table_reader.seek(part.offset + table_offset, tc::io::SeekOrigin::Begin);
	sAesCtrExStorageBlock root;
	readExact(table_reader, reinterpret_cast<byte_t*>(&root), sizeof(root));

	const auto bucket_count = root.header.bucket_count.unwrap();
	const auto data_end = root.header.total_size.unwrap();
	if (bucket_count == 0 || bucket_count > table_size / node_size - 1 || data_end > table_offset)
		throw tc::Exception(kModuleName, "Invalid NCA AES-CTR-Ex bucket count.");

	uint64_t cursor = 0;
	int64_t entries_read = 0;
	for (uint32_t i = 0; i < bucket_count; i++)
	{
		sAesCtrExStorageBucket bucket;
		readExact(table_reader, reinterpret_cast<byte_t*>(&bucket), sizeof(bucket));
		const auto entry_count = bucket.header.entry_count.unwrap();
		const auto bucket_end = bucket.header.end_offset_bucket.unwrap();
		if (entry_count == 0 || entry_count > bucket.entries.size() || bucket_end > data_end)
			throw tc::Exception(kModuleName, "Invalid NCA AES-CTR-Ex bucket.");

		for (uint32_t j = 0; j < entry_count; j++)
		{
			const auto& entry = bucket.entries[j];
			const uint64_t end = j + 1 == entry_count ? bucket_end : bucket.entries[j + 1].offset.unwrap();
			if (uint64_t(entry.offset.unwrap()) != cursor || end <= cursor || end > bucket_end)
				throw tc::Exception(kModuleName, "Invalid NCA AES-CTR-Ex section range.");
			detail::aes_iv_t section_counter;
			ContentArchiveUtil::getNcaPartitionAesCtr(entry.generation.unwrap(), header.secure_value.unwrap(), section_counter.data());
			addSection(sections, part.offset + cursor, end - cursor, nca::EncryptionType_AesCtrEx, key, section_counter);
			cursor = end;
		}
		entries_read += entry_count;
	}
	if (entries_read != count || cursor != data_end)
		throw tc::Exception(kModuleName, "Incomplete NCA AES-CTR-Ex table.");

	// The remaining metadata uses the partition's default counter.
	addSection(sections, part.offset + cursor, part.size - cursor, nca::EncryptionType_AesCtr, key, counter);
}

SectionList getSections(const std::shared_ptr<tc::io::IStream>& file, const nstool::KeyBag& keys)
{
	nstool::NcaProcess process;
	process.setInputFile(file);
	process.setKeyCfg(keys);
	process.setCliOutputMode(nstool::CliOutputMode());
	process.readHeader();

	const auto& archive = process.getHeader();
	if (archive.getContentType() != nca::ContentType_Program && archive.getContentType() != nca::ContentType_PublicData)
		return {};

	auto partitions = archive.getPartitionEntryList();
	std::sort(partitions.begin(), partitions.end(), [](const ContentArchiveHeader::sPartitionEntry& a,
		const ContentArchiveHeader::sPartitionEntry& b) { return a.offset < b.offset; });

	SectionList sections;
	int64_t cursor = 0;
	for (const auto& part : partitions)
	{
		if (part.offset < cursor || part.offset > file->length() || part.size <= 0 || part.size > file->length() - part.offset)
			throw tc::Exception(kModuleName, "Invalid NCA partition range.");

		const auto& header = process.getHeaderBlock().fs_header[part.header_index];
		detail::sha256_hash_t hash;
		tc::crypto::GenerateSha2256Hash(hash.data(), reinterpret_cast<const byte_t*>(&header), sizeof(header));
		if (hash != part.fs_header_hash)
			throw tc::Exception(kModuleName, "Invalid NCA partition header hash.");

		const auto type = static_cast<nca::EncryptionType>(header.encryption_type);
		if (header.sparse_info.generation.unwrap() != 0 ||
			(type != nca::EncryptionType_None && type != nca::EncryptionType_AesXts &&
			 type != nca::EncryptionType_AesCtr && type != nca::EncryptionType_AesCtrEx))
			return {};

		addSection(sections, cursor, part.offset - cursor, nca::EncryptionType_None);
		if (type == nca::EncryptionType_None || type == nca::EncryptionType_AesXts)
		{
			addSection(sections, part.offset, part.size, nca::EncryptionType_None);
		}
		else
		{
			const auto& key = process.getAesCtrKey();
			if (key.isNull())
				throw tc::Exception(kModuleName, "Could not determine NCA content key.");
			detail::aes_iv_t counter;
			ContentArchiveUtil::getNcaPartitionAesCtr(&header, counter.data());
			if (type == nca::EncryptionType_AesCtr)
				addSection(sections, part.offset, part.size, type, key.get(), counter);
			else
				addPatchSections(sections, file, part, header, key.get(), counter);
		}
		cursor = part.offset + part.size;
	}
	if (!sections.empty())
		addSection(sections, cursor, file->length() - cursor, nca::EncryptionType_None);
	return sections;
}

}

bool nstool::tryWriteNcz(const std::shared_ptr<tc::io::IStream>& file, tc::io::IStream& output, const KeyBag& keys)
{
	if (file->length() <= kHeaderSize)
		return false;

	const auto sections = getSections(file, keys);
	if (sections.empty())
		return false;

	const int64_t start = output.position();
	tc::ByteData data(kBufferSize);
	file->seek(0, tc::io::SeekOrigin::Begin);
	readExact(*file, data.data(), kHeaderSize);
	writeExact(output, data.data(), kHeaderSize);
	writeExact(output, kSectionMagic, sizeof(kSectionMagic) - 1);
	tc::bn::le64<uint64_t> count;
	count.wrap(sections.size());
	writeExact(output, &count, sizeof(count));
	writeExact(output, sections.data(), sections.size() * sizeof(SectionHeader));

	std::unique_ptr<ZSTD_CCtx, decltype(&ZSTD_freeCCtx)> context(ZSTD_createCCtx(), ZSTD_freeCCtx);
	if (!context)
		throw tc::io::IOException(kModuleName, "Could not allocate a Zstandard encoder.");
	checkZstd(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_compressionLevel, kCompressionLevel));
	checkZstd(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_enableLongDistanceMatching, 1));
	checkZstd(ZSTD_CCtx_setParameter(context.get(), ZSTD_c_windowLog, 27));
	checkZstd(ZSTD_CCtx_setPledgedSrcSize(context.get(), file->length() - kHeaderSize));
	tc::ByteData compressed(ZSTD_CStreamOutSize());

	const auto encode = [&](size_t size, ZSTD_EndDirective mode) {
		ZSTD_inBuffer in{data.data(), size, 0};
		size_t pending;
		do {
			ZSTD_outBuffer out{compressed.data(), compressed.size(), 0};
			pending = checkZstd(ZSTD_compressStream2(context.get(), &out, &in, mode));
			if (out.pos)
				writeExact(output, compressed.data(), out.pos);
		} while (in.pos < in.size || (mode == ZSTD_e_end && pending != 0));
	};

	for (const auto& section : sections)
	{
		const int64_t end = section.offset.unwrap() + section.size.unwrap();
		int64_t offset = std::max(kHeaderSize, section.offset.unwrap());
		if (offset >= end)
			continue;

		std::shared_ptr<tc::io::IStream> input = file;
		const auto type = section.crypto_type.unwrap();
		if (type == nca::EncryptionType_AesCtr || type == nca::EncryptionType_AesCtrEx)
			input = std::make_shared<tc::crypto::Aes128CtrEncryptedStream>(file, section.key, section.counter);
		input->seek(offset, tc::io::SeekOrigin::Begin);
		while (offset < end)
		{
			const size_t size = tc::io::IOUtil::getReadableCount(end, offset, data.size());
			readExact(*input, data.data(), size);
			encode(size, ZSTD_e_continue);
			offset += size;
		}
	}
	encode(0, ZSTD_e_end);

	if (output.position() - start < file->length())
		return true;

	output.seek(start, tc::io::SeekOrigin::Begin);
	return false;
}
