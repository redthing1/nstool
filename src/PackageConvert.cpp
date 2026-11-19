#include "PackageConvert.h"
#include "NczStream.h"
#include "NczWriter.h"
#include "PfsProcess.h"
#include "util.h"

#include <tc/io/FileStream.h>
#include <tc/io/LocalFileSystem.h>
#include <tc/io/SubStream.h>

#include <set>

namespace {

bool hasSuffix(const std::string& name, const std::string& suffix)
{
	return name.size() >= suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}

void nstool::convertPackage(const std::shared_ptr<tc::io::IStream>& input, bool decompress,
	const tc::io::Path& output_path, KeyBag keys)
{
	const char* module = "nstool::convertPackage";
	const char* extension = decompress ? ".nsp" : ".nsz";
	if (output_path.size() == 0 || !hasSuffix(output_path.back(), extension))
		throw tc::ArgumentException(module, fmt::format("Output filename must end in {:s}.", extension));

	const auto source = PfsProcess::readHeader(*input);
	if (source.getFsType() != pie::hac::PartitionFsHeader::TYPE_PFS0 || source.getFileList().empty())
		throw tc::ArgumentException(module, "Conversion requires a nonempty PFS0 package.");

	pie::hac::PartitionFsHeader placeholder;
	std::set<std::string> names;
	for (const auto& entry : source.getFileList())
	{
		auto name = entry.name;
		if (hasSuffix(name, ".ncz"))
		{
			if (!decompress)
				throw tc::ArgumentException(module, "The input contains NCZ members. Use NSZ input type.");
			name.back() = 'a';
		}
		if (!names.insert(name).second)
			throw tc::ArgumentException(module, fmt::format("Duplicate package entry: {:s}", name));
		placeholder.addFile(name, 0);

		if (!decompress && hasSuffix(name, ".tik"))
		{
			tc::io::SubStream ticket(input, entry.offset, entry.size);
			keys.importTicket(ticket, name, false);
		}
	}
	placeholder.toBytes();

	auto output = std::make_shared<tc::io::FileStream>(output_path, tc::io::FileMode::CreateNew, tc::io::FileAccess::Write);
	try {
		output->seek(placeholder.getBytes().size(), tc::io::SeekOrigin::Begin);
		pie::hac::PartitionFsHeader destination;
		tc::ByteData cache(0x10000);

		for (const auto& entry : source.getFileList())
		{
			auto name = entry.name;
			std::shared_ptr<tc::io::IStream> member = std::make_shared<tc::io::SubStream>(input, entry.offset, entry.size);
			const int64_t start = output->position();
			fmt::print("Converting {:s}...\n", name);
			if (decompress && hasSuffix(name, ".ncz"))
			{
				member = std::make_shared<NczStream>(member);
				name.back() = 'a';
				copyStream(*member, *output, cache);
			}
			else if (!decompress && hasSuffix(name, ".nca") && tryWriteNcz(member, *output, keys))
			{
				name.back() = 'z';
			}
			else
			{
				copyStream(*member, *output, cache);
			}
			destination.addFile(name, output->position() - start);
		}

		destination.toBytes();
		output->setLength(output->position());
		const auto& header = destination.getBytes();
		if (header.size() != placeholder.getBytes().size())
			throw tc::io::IOException(module, "Package header size changed during conversion.");
		output->seek(0, tc::io::SeekOrigin::Begin);
		if (output->write(header.data(), header.size()) != header.size())
			throw tc::io::IOException(module, "Failed to write package header.");
		output->flush();
	}
	catch (...) {
		output.reset();
		try {
			tc::io::LocalFileSystem().removeFile(output_path);
		} catch (const tc::Exception&) {
			fmt::print("[WARNING] Could not remove incomplete package.\n");
		}
		throw;
	}
}
