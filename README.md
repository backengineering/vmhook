This is a small POC to show an interesting design weakness in VMProtect 2 which aids an attacker in such a way that reading memory can be manipulated in a centralized way.

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
