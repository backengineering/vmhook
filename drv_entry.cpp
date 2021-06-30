//
// Registers on image load callback then applies vmhook to EAC
// 
//

#include "scn.hpp"
#include "shithook.hpp"
#include "sha1.hpp"
#include "md5.hpp"

//
// game cheat offset flash backs...
//

#define EAC_VM_HANDLE_OFFSET 0xE93D
#define EAC_SHA1_OFFSET 0x4C00
#define EAC_MD5_OFFSET 0x37378
#define EAC_CRC32_OFFSET 0x27C8C
#define EAC_IMAGE_BASE 0x140000000

#define DBG_PRINT(format, ...) \
	DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, \
	"[vmhook-eac [core number = %d]]" format, KeGetCurrentProcessorNumber(), __VA_ARGS__)

//
// vm handler indexes for READQ...
//

u8 readq_idxs[] = { 247, 215, 169, 159, 71, 60, 55, 43, 23 };

//
// vm handler indexes for READDW
//

u8 readdw_idxs[] = { 218, 180, 179, 178, 163, 137, 92, 22, 12 };

// 
// vm handler indexes for READB
//

u8 readb_idxs[] = { 249, 231, 184, 160, 88, 85, 48, 9, 2 };

vm::hook_t* g_vmhook = nullptr;
vm::handler::table_t* g_vm_table = nullptr;
u64 __image_base = 0u, __image_size = 0u, __image_clone = 0u;
inline_hook_t __crc32_hook, __sha1_hook, __md5_hook;

void*
operator new(
	u64 size
	)
{
	//
	// Could have also used ExAllocatePoolZero...
	//

	return RtlZeroMemory(ExAllocatePool(NonPagedPool, size), size);
}

void
operator delete
(
	void* ptr,
	u64 size
	)
{
	UNREFERENCED_PARAMETER(size);
	ExFreePool(ptr);
}

__declspec(noinline)
void hook_sha1(
	void *data, unsigned int len, void* result
)
{
	sha1_ctx ctx;
	sha1_init(&ctx);

	if (scn::read_only(__image_base, (u64)data))
	{
		DBG_PRINT("sha1 hash data = 0x%p, len = 0x%x, result = 0x%p\n", data, len, result);
		sha1_update(&ctx, (unsigned char*)__image_clone + (((u64)data) - __image_base), len);
		sha1_final((unsigned char*)result, &ctx);
		return;
	}

	sha1_update(&ctx, (unsigned char*) data, len);
	sha1_final((unsigned char*)result, &ctx);
}

void
image_loaded(
	PUNICODE_STRING image_name,
	HANDLE pid,
	PIMAGE_INFO image_info
)
{
	// 
	// PID is zero when the module being loaded is going into the kernel...
	//

	if (!pid && wcsstr(image_name->Buffer, L"EasyAntiCheat.sys"))
	{
		if (g_vmhook && g_vm_table && __image_clone)
			delete g_vmhook, delete g_vm_table, ExFreePool((void*)__image_clone);

		//
		// allocate memory for a g_vmhook, g_vm_table and then zero it...
		//

		// > 0x00007FF77A233736 mov rcx, [r12+rax*8]
		// > 0x00007FF77A23373D ror rcx, 0x30 <--- decrypt vm handler entry...
		// > 0x00007FF77A233747 add rcx, r13
		// > 0x00007FF77A23374A jmp rcx
		vm::decrypt_handler_t _decrypt_handler =
			[](u64 val) -> u64
		{
			return _rotr64(val, 0x30);
		};

		// > 0x00007FF77A233736 mov rcx, [r12+rax*8]
		// > 0x00007FF77A23373D ror rcx, 0x30 <--- inverse to encrypt vm handler entry...
		// > 0x00007FF77A233747 add rcx, r13
		// > 0x00007FF77A23374A jmp rcx
		vm::encrypt_handler_t _encrypt_handler =
			[](u64 val) -> u64
		{
			return _rotl64(val, 0x30);
		};

		vm::handler::edit_entry_t _edit_entry =
			[](u64* entry_ptr, u64 val) -> void
		{
			//
			// disable write protect bit in cr0...
			//

			{
				auto cr0 = __readcr0();
				cr0 &= 0xfffffffffffeffff;
				__writecr0(cr0);
				_disable();
			}

			*entry_ptr = val;

			//
			// enable write protect bit in cr0...
			//

			{
				auto cr0 = __readcr0();
				cr0 |= 0x10000;
				_enable();
				__writecr0(cr0);
			}
		};

		auto image_base = reinterpret_cast<u64>(image_info->ImageBase);
		auto handler_table_ptr = reinterpret_cast<u64*>(image_base + EAC_VM_HANDLE_OFFSET);

		__image_clone = reinterpret_cast<u64>(ExAllocatePool(NonPagedPool, image_info->ImageSize));
		RtlCopyMemory((void*)__image_clone, (void*)image_base, image_info->ImageSize);

		g_vm_table = new vm::handler::table_t(handler_table_ptr, _edit_entry);
		g_vmhook = new vm::hook_t(image_base, EAC_IMAGE_BASE, _decrypt_handler, _encrypt_handler, g_vm_table);
		__image_base = image_base, __image_size = image_info->ImageSize;

		const auto callback = [](vm::registers* regs, u8 handler_idx)
		{
			const auto read_addr = reinterpret_cast<u64*>(regs->rbp)[0];

			// shoot the tires right off the virtualized integrity checks in about 2 lines of code...
			if (scn::read_only(__image_base, read_addr))
			{
				DBG_PRINT(" READ(Q/DW/B) EasyAntiCheat.sys+0x%x\n", (read_addr - __image_base));
				reinterpret_cast<u64*>(regs->rbp)[0] = __image_clone + (read_addr - __image_base);
			}
		};

		// install hooks on READQ virtual machine handlers...
		for (auto idx = 0u; idx < sizeof readq_idxs; ++idx)
			g_vm_table->set_callback(readq_idxs[idx], callback);

		// install hooks on READDW virtual machine handlers...
		for (auto idx = 0u; idx < sizeof readdw_idxs; ++idx)
			g_vm_table->set_callback(readdw_idxs[idx], callback);

		// install hooks on READB virtual machine handlers...
		for (auto idx = 0u; idx < sizeof readb_idxs; ++idx)
			g_vm_table->set_callback(readb_idxs[idx], callback);

		//
		// hooks all vm handlers and starts callbacks...
		//
		g_vmhook->start();

		// hook on sha1...
		make_inline_hook(&__sha1_hook,
			reinterpret_cast<void*>(
				image_base + EAC_SHA1_OFFSET), &hook_sha1, true);
	}
}

/*++

Routine Description:
	This is the entry routine for the vmhook-eac driver.

Arguments:
	drv_object - Pointer to driver object created by the system.
	reg_path - Receives the full registry path to the SERVICES
			node of the current control set.

Return Value:
	An NTSTATUS code.

--*/

extern "C"
NTSTATUS
DriverEntry( // entry called from ZwSwapCert...
	PDRIVER_OBJECT drv_object,
	PUNICODE_STRING reg_path
)
{
	UNREFERENCED_PARAMETER(drv_object);
	UNREFERENCED_PARAMETER(reg_path);

	//
	// This kernel driver cannot be unloaded so there is no unload routine...
	// This is because ZwSwapCert will cause the system to crash...
	//

	DBG_PRINT("> Registering ImageLoad Callbacks...\n");
	return PsSetLoadImageNotifyRoutine(&image_loaded);
}