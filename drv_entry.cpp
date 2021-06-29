//
// Registers on image load callback then applies vmhook to EAC
// 
//

#include <ntifs.h>
#include <intrin.h>
#include <vmhook.hpp>

//
// game cheat offset flash backs...
//

#define EAC_VM_HANDLE_OFFSET 0xE93D
#define EAC_IMAGE_BASE 0x140000000

//
// vm handler indexes for READQ...
//

u8 readq_idxs[] = { 247, 215, 169, 159, 71, 60, 55, 43, 23 };

//
// vm handler indexes for READDW
//

u8 readdw_idxs[] = { 218, 180, 179, 178, 163, 137, 92, 22, 12 };

vm::hook_t* g_vmhook = nullptr;
vm::handler::table_t* g_vm_table = nullptr;

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
		if (g_vmhook && g_vm_table)
			delete g_vmhook, delete g_vm_table;

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
			return _rotl64(val, 0x30);
		};

		// > 0x00007FF77A233736 mov rcx, [r12+rax*8]
		// > 0x00007FF77A23373D ror rcx, 0x30 <--- inverse to encrypt vm handler entry...
		// > 0x00007FF77A233747 add rcx, r13
		// > 0x00007FF77A23374A jmp rcx
		vm::encrypt_handler_t _encrypt_handler =
			[](u64 val) -> u64
		{
			return _rotr64(val, 0x30);
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

		g_vm_table = new vm::handler::table_t(handler_table_ptr, _edit_entry);
		g_vmhook = new vm::hook_t(image_base, EAC_IMAGE_BASE, _decrypt_handler, _encrypt_handler, g_vm_table);

		// install hooks on READQ virtual machine handlers...
		for (auto idx = 0u; idx < sizeof readq_idxs; ++idx)
		{
			g_vm_table->set_callback(readq_idxs[idx],
				[](vm::registers* regs, u8 handler_idx)
				{
					DbgPrint("> READQ, reading address = 0x%p\n", reinterpret_cast<u64*>(regs->rbp)[0]);
				}
			);
		}

		for (auto idx = 0u; idx < sizeof readdw_idxs; ++idx)
		{
			g_vm_table->set_callback(readdw_idxs[idx],
				[](vm::registers* regs, u8 handler_idx)
				{
					DbgPrint("> READDW, reading address = 0x%p\n", reinterpret_cast<u64*>(regs->rbp)[0]);
				}
			);
		}

		//
		// hooks all vm handlers and starts callbacks...
		//
		g_vmhook->start();
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

	DbgPrint("> Registering ImageLoad Callbacks...\n");
	return PsSetLoadImageNotifyRoutine(&image_loaded);
}