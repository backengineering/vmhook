# If you are looking for multi-vm support please [refer to this branch](https://githacks.org/_xeroxz/vmhook-eac/-/tree/multi-vm)

![](https://githacks.org/_xeroxz/vmhook-eac/-/raw/a2e38c76b1fb9a53527c2441b06bb25b768d9959/bin/running-with-patch.png)

### About - Hooking Into The VMProtect 2 Virtual Machine And Spoofing Memory Reads

This is a small POC to show an interesting design weakness in VMProtect 2 which can aid an attacker in such a way that reading memory can be manipulated in a centralized way. In this POC all `READQ/DW/B` virtual instructions are hooked, when virtualized integrity check routines try and read unwriteable sections, the pointer is changed to an untouched clone of the driver. This means all inlined virtualized integrity checks can be bypassed with a few lines of code. This is not possible without the aid of VMProtect 2's design... So im refering to having reusable vm handlers as a design weakness...

***This is less about EasyAntiCheat and more about a design weakness in VMProtect 2... EasyAntiCheat is merely used for a real world example, in addition, nothing released here is undetected, it has plenty of detection vectors...***

```
00000603	67.09356689	[vmhook-eac [core number = 20]] READ(Q/DW/B) EasyAntiCheat.sys+0x1000	
00000604	67.09357452	[vmhook-eac [core number = 20]] READ(Q/DW/B) EasyAntiCheat.sys+0x1000	
00000605	67.09359741	[vmhook-eac [core number = 20]] READ(Q/DW/B) EasyAntiCheat.sys+0x1010	
00000606	67.09359741	[vmhook-eac [core number = 20]] READ(Q/DW/B) EasyAntiCheat.sys+0x1010	
00000607	67.09362793	[vmhook-eac [core number = 20]] READ(Q/DW/B) EasyAntiCheat.sys+0x1020	
```

*note: not all integrity checks are virtualized, there were at least one other outside of virtualization*

#### SHA1 Integrity Checks

Integrity checks outside of the VMProtect 2 virtual machine are not effected by my POC. In particular, a SHA1 hash of both `.text` and `.eac0` is computed, the SHA1 hash function itself is not virtualized so it is not affected by my `READQ/DW/B` hook.

```
00126334	68.50553894	[vmhook-eac [core number = 13]]sha1 hash data = 0xFFFFF80061B91000, len = 0x51d28, result = 0xFFFFFE8158E60BF0	
00126335	68.50672913	[vmhook-eac [core number = 13]]sha1 hash data = 0xFFFFF80061C0B000, len = 0x2bc79d, result = 0xFFFFFE8158E60BF0	
```

*Side Note: Check out that len? its not aligned, this means you can patch the alignment/padding at the end of both of these sections if you wanted and the SHA1 integrity checks would be fine...*

Thus a hook is placed on this SHA1 hash function and spoofed results are computed... you can locate this function by searching for SHA1 magic numbers: 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0... The SHA1 function should really be virtualized since these magic constant values can be located instantly...


### Solution, Possible Alternatives

* 1.) If EasyAntiCheat were to patch their own driver using `MmMapIoSpaceEx` - `PAGE_READWRITE` (for HVCI support), they could compute a SHA1 hash, then revert the changes, compute a second SHA1 hash... If the hashes are the same, then you know someone is hooking SHA1, or hooking `READQ/DW/B` virtual instructions... In other words, instead of checking for patches, check to see if your patches result in a different hash... ***When i say patch i mean, change some padding/alignment bytes at the end of an unwriteable section***...

* 2.) Map the driver into the usermode service as READONLY, this way the usermode service can just read the mapping and compute a hash... This has its own attack vectors considering it would require calling out to ntoskrnl/external code, however the idea is what matters, having multiple sources of integrity checking is ideal.

### How To Update

#### VM Handler Table Indexes

These vm handler indexes are for EasyAntiCheat.sys 6/23/2021, when the driver gets re-vmprotected these vm handler indexes need to be updated.

```cpp
//
// vm handler indexes for READQ...
//

inline u8 g_readq_idxs[] = { 247, 215, 169, 159, 71, 60, 55, 43, 23 };

//
// vm handler indexes for READDW
//

inline u8 g_readdw_idxs[] = { 218, 180, 179, 178, 163, 137, 92, 22, 12 };

//
// vm handler indexes for READB
//

inline u8 g_readb_idxs[] = { 249, 231, 184, 160, 88, 85, 48, 9, 2 };
```

#### Offsets

`EAC_VM_HANDLE_OFFSET` contains the offset from the module base to the vm handler table, as of right now EAC only uses a single virtual machine in their VMProtect config so there is only a single vm handler table...
 
`EAC_SHA1_OFFSET` contains the offset from the module base to the sha1 function...
you can locate this function by searching for SHA1 magic numbers: `0x67452301`, `0xEFCDAB89`
`0x98BADCFE`, `0x10325476`, `0xC3D2E1F0`. These crypto functions should be virtualized so their constant values cannot be located using IDA --> search "immidate values".

`EAC_IMAGE_BASE` contains the "ImageBase" value inside of the OptionalHeaders field of the NT
headers... This value gets updated with the actual module base of the driver once loaded into
memory... I didnt want to read it off disk so I just made it a macro here...

```cpp
#define EAC_VM_HANDLE_OFFSET 0xE93D
#define EAC_SHA1_OFFSET 0x4C00
#define EAC_IMAGE_BASE 0x140000000
```

#### VM Handler Table Entry Encrypt/Decrypt

Since EasyAntiCheat is only using a single VM in their VMProtect 2 config, you will only need to update these two lambdas with the new instruction that is used to decrypt virtual machine handler table entries...

You can use [vmprofiler-cli](https://githacks.org/vmp2/vmprofiler-cli/-/releases) to obtain these instructions... Since the entry point of the driver is virtualized you can simply take the "AddressOfEntryPoint" relative virtual address and use it as the `--vmentry` flag...

```cpp
// > 0x00007FF77A233736 mov rcx, [r12+rax*8]
// > 0x00007FF77A23373D ror rcx, 0x30 <--- decrypt vm handler entry...
// > 0x00007FF77A233747 add rcx, r13
// > 0x00007FF77A23374A jmp rcx
vm::decrypt_handler_t _decrypt_handler = []( u64 val ) -> u64 { return _rotr64( val, 0x30 ); };

// > 0x00007FF77A233736 mov rcx, [r12+rax*8]
// > 0x00007FF77A23373D ror rcx, 0x30 <--- inverse to encrypt vm handler entry...
// > 0x00007FF77A233747 add rcx, r13
// > 0x00007FF77A23374A jmp rcx
vm::encrypt_handler_t _encrypt_handler = []( u64 val ) -> u64 { return _rotl64( val, 0x30 ); };
```
