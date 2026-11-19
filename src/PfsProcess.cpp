#include "PfsProcess.h"
#include "NczStream.h"
#include <cstring>
#include <limits>

#include <pietendo/hac/PartitionFsUtil.h>

#include <tc/io/VirtualFileSystem.h>
#include <pietendo/hac/PartitionFsSnapshotGenerator.h>


nstool::PfsProcess::PfsProcess() :
	mModuleName("nstool::PfsProcess"),
	mFile(),
	mCliOutputMode(true, false, false, false),
	mVerify(false),
	mPfs(),
	mFileSystem(),
	mFsProcess()
{
}

pie::hac::PartitionFsHeader nstool::PfsProcess::readHeader(tc::io::IStream& file)
{
	const char* module = "nstool::PfsProcess";
	if (!file.canRead() || !file.canSeek())
		throw tc::NotSupportedException(module, "Input stream requires read/seek permissions.");

	pie::hac::sPfsHeader header;
	file.seek(0, tc::io::SeekOrigin::Begin);
	if (file.read(reinterpret_cast<byte_t*>(&header), sizeof(header)) != sizeof(header))
		throw tc::Exception(module, "Truncated PartitionFs header.");

	const auto magic = header.st_magic.unwrap();
	if (magic != pie::hac::pfs::kPfsStructMagic && magic != pie::hac::pfs::kHashedPfsStructMagic)
		throw tc::Exception(module, "Invalid PartitionFs magic.");

	const size_t entry_size = magic == pie::hac::pfs::kPfsStructMagic ?
		sizeof(pie::hac::sPfsFile) : sizeof(pie::hac::sHashedPfsFile);
	const int64_t entries_end = sizeof(header) + int64_t(header.file_num.unwrap()) * entry_size;
	const int64_t header_size = entries_end + header.name_table_size.unwrap();
	if (header_size > file.length() || uint64_t(header_size) > std::numeric_limits<size_t>::max())
		throw tc::Exception(module, "Truncated PartitionFs header.");

	tc::ByteData data(static_cast<size_t>(header_size));
	std::memcpy(data.data(), &header, sizeof(header));
	const size_t remaining = data.size() - sizeof(header);
	if (remaining != 0 && file.read(data.data() + sizeof(header), remaining) != remaining)
		throw tc::Exception(module, "Truncated PartitionFs header.");

	const byte_t* entry = data.data() + sizeof(header);
	const byte_t* names = data.data() + entries_end;
	for (uint32_t i = 0; i < header.file_num.unwrap(); i++, entry += entry_size)
	{
		// Both entry types start with the same offset, size and name offset.
		pie::hac::sPfsFile fields;
		std::memcpy(&fields, entry, sizeof(fields));
		const auto name_offset = fields.name_offset.unwrap();
		if (name_offset >= header.name_table_size.unwrap() ||
			!std::memchr(names + name_offset, 0, header.name_table_size.unwrap() - name_offset))
			throw tc::Exception(module, "Invalid PartitionFs file name.");
		if (fields.data_offset.unwrap() < 0 || fields.data_offset.unwrap() > std::numeric_limits<int64_t>::max() - header_size)
			throw tc::Exception(module, "Invalid PartitionFs file offset.");
	}

	pie::hac::PartitionFsHeader result;
	result.fromBytes(data.data(), data.size());
	return result;
}

void nstool::PfsProcess::process(bool decompress_ncz)
{
	if (!mFile)
		throw tc::Exception(mModuleName, "No file reader set.");
	mPfs = readHeader(*mFile);

	// create virtual filesystem
	if (decompress_ncz && mPfs.getFsType() != pie::hac::PartitionFsHeader::TYPE_PFS0)
	{
		throw tc::Exception(mModuleName, "NSZ requires a PFS0 container.");
	}
	pie::hac::PartitionFsSnapshotGenerator snapshot(mFile, mVerify ?
		pie::hac::PartitionFsSnapshotGenerator::ValidationMode_Warn :
		pie::hac::PartitionFsSnapshotGenerator::ValidationMode_None);
	if (decompress_ncz)
	{
		auto& listing = snapshot.dir_entries.front().dir_listing;
		for (auto& name : listing.file_list)
		{
			if (name.size() < 4 || name.compare(name.size() - 4, 4, ".ncz") != 0)
				continue;

			const auto compressed_path = listing.abs_path + name;
			const auto file = snapshot.file_entry_path_map.find(compressed_path);
			if (file == snapshot.file_entry_path_map.end())
				throw tc::Exception(mModuleName, fmt::format("Duplicate NSZ entry: {:s}", name));

			name.back() = 'a';
			const auto restored_path = listing.abs_path + name;
			if (!snapshot.file_entry_path_map.emplace(restored_path, file->second).second)
				throw tc::Exception(mModuleName, fmt::format("Duplicate NSZ entry: {:s}", name));

			auto& entry = snapshot.file_entries[file->second];
			entry.stream = std::make_shared<NczStream>(entry.stream);
			snapshot.file_entry_path_map.erase(file);
		}
	}
	mFsProcess.setFsFormatName(decompress_ncz ? "NSZ" : "PartitionFs");
	mFileSystem = std::make_shared<tc::io::VirtualFileSystem>(snapshot);
	mFsProcess.setInputFileSystem(mFileSystem);

	// set properties for FsProcess
	mFsProcess.setFsProperties({
		fmt::format("Type:        {:s}", pie::hac::PartitionFsUtil::getFsTypeAsString(mPfs.getFsType())), 
		fmt::format("FileNum:     {:d}", mPfs.getFileList().size())
	});
	
	mFsProcess.process();
}

void nstool::PfsProcess::setInputFile(const std::shared_ptr<tc::io::IStream>& file)
{
	mFile = file;
}

void nstool::PfsProcess::setCliOutputMode(CliOutputMode type)
{
	mCliOutputMode = type;
	mFsProcess.setShowFsInfo(mCliOutputMode.show_basic_info);
}

void nstool::PfsProcess::setVerifyMode(bool verify)
{
	mVerify = verify;
}

void nstool::PfsProcess::setShowFsTree(bool show_fs_tree)
{
	mFsProcess.setShowFsTree(show_fs_tree);
}

void nstool::PfsProcess::setFsRootLabel(const std::string& root_label)
{
	mFsProcess.setFsRootLabel(root_label);
}

void nstool::PfsProcess::setExtractJobs(const std::vector<nstool::ExtractJob>& extract_jobs)
{
	mFsProcess.setExtractJobs(extract_jobs);
}

const pie::hac::PartitionFsHeader& nstool::PfsProcess::getPfsHeader() const
{
	return mPfs;
}

const std::shared_ptr<tc::io::IFileSystem>& nstool::PfsProcess::getFileSystem() const
{
	return mFileSystem;
}
