#include "scn.hpp"

namespace scn
{
	bool read_only(u64 image_base, u64 ptr)
	{
		auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(image_base);
		auto nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(
			reinterpret_cast<u64>(dos_header) + dos_header->e_lfanew);

		auto section_count = nt_header->FileHeader.NumberOfSections;
		auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(
			reinterpret_cast<u64>(nt_header) + sizeof(u32) + sizeof(IMAGE_FILE_HEADER) +
			nt_header->FileHeader.SizeOfOptionalHeader);


		// for each section try and find the section that contains this pointer...
		for (auto idx = 0u; idx < section_count; ++idx)
			// if the section contains this pointer...
			if (ptr >= sections[idx].VirtualAddress + image_base &&
				ptr < sections[idx].VirtualAddress + image_base + sections[idx].Misc.VirtualSize)
				// returns true if the section isnt discardable and isnt writeable (I.E in memory and readonly)...
				return !(sections[idx].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) &&
				!(sections[idx].Characteristics & IMAGE_SCN_MEM_WRITE);

		// pointer isnt inside of the driver...
		return false;
	}
}