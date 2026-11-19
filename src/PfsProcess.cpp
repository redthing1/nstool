#include "PfsProcess.h"
#include "NczStream.h"
#include "util.h"

#include <pietendo/hac/PartitionFsUtil.h>
#include <tc/io/LocalFileSystem.h>

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

void nstool::PfsProcess::process(bool decompress_ncz)
{
	if (mFile == nullptr)
	{
		throw tc::Exception(mModuleName, "No file reader set.");
	}
	if (mFile->canRead() == false || mFile->canSeek() == false)
	{
		throw tc::NotSupportedException(mModuleName, "Input stream requires read/seek permissions.");
	}

	tc::ByteData scratch;

	// read base header to determine complete header size
	if (mFile->length() < tc::io::IOUtil::castSizeToInt64(sizeof(pie::hac::sPfsHeader)))
	{
		throw tc::Exception(mModuleName, "Corrupt PartitionFs: File too small");
	}

	scratch = tc::ByteData(sizeof(pie::hac::sPfsHeader));
	mFile->seek(0, tc::io::SeekOrigin::Begin);
	mFile->read(scratch.data(), scratch.size());
	if (validateHeaderMagic(((pie::hac::sPfsHeader*)scratch.data())) == false)
	{
		throw tc::Exception(mModuleName, "Corrupt PartitionFs: Header had incorrect struct magic.");
	}

	// read complete size header
	size_t pfsHeaderSize = determineHeaderSize(((pie::hac::sPfsHeader*)scratch.data()));
	if (mFile->length() < tc::io::IOUtil::castSizeToInt64(pfsHeaderSize))
	{
		throw tc::Exception(mModuleName, "Corrupt PartitionFs: File too small");
	}

	scratch = tc::ByteData(pfsHeaderSize);
	mFile->seek(0, tc::io::SeekOrigin::Begin);
	mFile->read(scratch.data(), scratch.size());

	// process PFS
	mPfs.fromBytes(scratch.data(), scratch.size());

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

size_t nstool::PfsProcess::determineHeaderSize(const pie::hac::sPfsHeader* hdr)
{
	size_t fileEntrySize = 0;
	if (hdr->st_magic.unwrap() == pie::hac::pfs::kPfsStructMagic)
		fileEntrySize = sizeof(pie::hac::sPfsFile);
	else
		fileEntrySize = sizeof(pie::hac::sHashedPfsFile);

	return sizeof(pie::hac::sPfsHeader) + hdr->file_num.unwrap() * fileEntrySize + hdr->name_table_size.unwrap();
}

bool nstool::PfsProcess::validateHeaderMagic(const pie::hac::sPfsHeader* hdr)
{
	return hdr->st_magic.unwrap() == pie::hac::pfs::kPfsStructMagic || hdr->st_magic.unwrap() == pie::hac::pfs::kHashedPfsStructMagic;
}
