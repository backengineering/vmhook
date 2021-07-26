#pragma once
#include <scn.hpp>
#include <sha1.hpp>
#include <shithook.hpp>

#define VM_COUNT 10
#define EAC_SHA1_OFFSET 0x1D8F0
#define EAC_IMAGE_BASE 0x140000000

#define DBG_PRINT( format, ... )                                                                                       \
    DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[vmhook-eac [core number = %d]]" format,                        \
                KeGetCurrentProcessorNumber(), __VA_ARGS__ )

template < class T > inline T __ROL__( T value, int count )
{
    const unsigned int nbits = sizeof( T ) * 8;

    if ( count > 0 )
    {
        count %= nbits;
        T high = value >> ( nbits - count );
        if ( T( -1 ) < 0 ) // signed value
            high &= ~( ( T( -1 ) << count ) );
        value <<= count;
        value |= high;
    }
    else
    {
        count = -count % nbits;
        T low = value << ( nbits - count );
        value >>= count;
        value |= low;
    }
    return value;
}

inline u8 __ROL1__( u8 value, int count )
{
    return __ROL__( ( u8 )value, count );
}

inline u16 __ROL2__( u16 value, int count )
{
    return __ROL__( ( u16 )value, count );
}

inline u32 __ROL4__( u32 value, int count )
{
    return __ROL__( ( u32 )value, count );
}

inline u64 __ROL8__( u64 value, int count )
{
    return __ROL__( ( u64 )value, count );
}

inline u8 __ROR1__( u8 value, int count )
{
    return __ROL__( ( u8 )value, -count );
}

inline u16 __ROR2__( u16 value, int count )
{
    return __ROL__( ( u16 )value, -count );
}

inline u32 __ROR4__( u32 value, int count )
{
    return __ROL__( ( u32 )value, -count );
}

inline u64 __ROR8__( u64 value, int count )
{
    return __ROL__( ( u64 )value, -count );
}

struct vm_meta_data_t
{
    u32 table_rva;
    u8 read_callback_count;
    u8 read_callback_indexes[ 256 ];

    vm::encrypt_handler_t encrypt;
    vm::decrypt_handler_t decrypt;
};

const vm_meta_data_t table_one = { 0x29829,
                                   28,
                                   {
                                       0x17, 0x48, 0x5e, 0x89, 0x93, 0xbc, 0xe1, 0xed, 0xfb, 0x13,
                                       0x1f, 0x21, 0x41, 0x59, 0x78, 0x82, 0x9e, 0xcb, 0xd9, 0xee,
                                       0x6,  0x5d, 0x60, 0x95, 0xb4, 0x2e, 0x6c, 0xbd,
                                   },
                                   []( u64 val ) -> u64 { return val + 0x6A78538F; },
                                   []( u64 val ) -> u64 { return val - 0x6A78538F; } };

const vm_meta_data_t table_two = { 0xf415,
                                   31,
                                   {
                                       0x0,  0x1,  0x20, 0x37, 0x44, 0x4a, 0x6b, 0xb7, 0xc6, 0xd2, 0xd,
                                       0x10, 0x3f, 0x90, 0x98, 0xb6, 0xbd, 0xe1, 0x25, 0x61, 0xa0, 0xa6,
                                       0xbc, 0xd0, 0xde, 0xed, 0xf6, 0x4,  0x5c, 0x78, 0xdc,
                                   },
                                   []( u64 val ) -> u64 { return val * -1; },
                                   []( u64 val ) -> u64 { return val * -1; } };

const vm_meta_data_t table_three = { 0x10e7d,
                                     25,
                                     {
                                         0xc,  0x12, 0x21, 0x40, 0x5e, 0x7f, 0xa0, 0xbc, 0xf8, 0xfe, 0x10, 0x23, 0x39,
                                         0x3e, 0x59, 0x65, 0x77, 0xc3, 0x7b, 0xd6, 0xea, 0xf7, 0x3f, 0x4d, 0x94,
                                     },
                                     []( u64 val ) -> u64 { return val + 1; },
                                     []( u64 val ) -> u64 { return val - 1; } };

const vm_meta_data_t table_four = { 0x7e100,
                                    26,
                                    {
                                        0xc,  0x25, 0x5d, 0x63, 0x75, 0xf8, 0x21, 0x23, 0x38, 0x59, 0x73, 0x85, 0xc5,
                                        0xcb, 0x1c, 0x2c, 0x42, 0x5b, 0x68, 0x89, 0xa7, 0xb3, 0xbd, 0x2e, 0x45, 0xb5,
                                    },
                                    []( u64 val ) -> u64 { return __ROR8__( val, 0x2D ); },
                                    []( u64 val ) -> u64 { return __ROL8__( val, 0x2D ); } };

const vm_meta_data_t table_five = { 0x7C100,
                                    29,
                                    {
                                        0x3d, 0x62, 0x67, 0x7a, 0x82, 0xab, 0xdc, 0xf3, 0x13, 0x57,
                                        0x5d, 0x6f, 0x78, 0xae, 0xb1, 0xd2, 0x40, 0x48, 0x5f, 0x85,
                                        0xad, 0xc3, 0x1d, 0x8c, 0x95, 0xa4, 0xb7, 0xc1, 0xe4,
                                    },
                                    []( u64 val ) -> u64 { return val + 1; },
                                    []( u64 val ) -> u64 { return val - 1; } };

const vm_meta_data_t table_six = { 0x7b100,
                                   21,
                                   {
                                       0x2a, 0x59, 0xc3, 0xfb, 0x8,  0xc,  0x90, 0xa2, 0xa5, 0xc9, 0xde,
                                       0xe8, 0xf5, 0x4,  0x2b, 0x38, 0x8a, 0xd6, 0x9,  0x78, 0x7e,
                                   },
                                   []( u64 val ) -> u64 { return val + 1; },
                                   []( u64 val ) -> u64 { return val - 1; } };

const vm_meta_data_t table_seven = { 0x7d900,
                                     23,
                                     {
                                         0x49, 0x53, 0x54, 0x55, 0x59, 0x63, 0x65, 0x6f, 0xc5, 0x30, 0x4e, 0x90,
                                         0x91, 0x9f, 0x5e, 0x6e, 0x8a, 0x92, 0xe0, 0x23, 0x47, 0x5f, 0x7f,
                                     },
                                     []( u64 val ) -> u64 { return _byteswap_uint64( val ); },
                                     []( u64 val ) -> u64 { return _byteswap_uint64( val ); } };

const vm_meta_data_t table_eight = { 0x7c900,
                                     17,
                                     {
                                         0x24,
                                         0x32,
                                         0xac,
                                         0x11,
                                         0x20,
                                         0x87,
                                         0xbe,
                                         0xf,
                                         0x1c,
                                         0x33,
                                         0xa8,
                                         0x40,
                                         0x64,
                                         0x99,
                                         0xc4,
                                         0xd5,
                                         0xfd,
                                     },
                                     []( u64 val ) -> u64 { return val ^ 0x70D337C5; },
                                     []( u64 val ) -> u64 { return val ^ 0x70D337C5; } };

const vm_meta_data_t table_nine = { 0x7b900,
                                    24,
                                    {
                                        0x43, 0x4c, 0xad, 0x30, 0x66, 0x69, 0x73, 0x80, 0xd3, 0xf4, 0x21, 0x53,
                                        0x60, 0x8a, 0xfc, 0x36, 0x7b, 0x8c, 0x96, 0x9f, 0xc4, 0xc7, 0xea, 0xf8,
                                    },
                                    []( u64 val ) -> u64 { return val ^ 0x60895574; },
                                    []( u64 val ) -> u64 { return val ^ 0x60895574; } };

const vm_meta_data_t table_ten = { 0x7d100,
                                   27,
                                   {
                                       0x34, 0x3f, 0x97, 0x9e, 0xd6, 0x5f, 0x7b, 0x8f, 0xaf,
                                       0xba, 0xcb, 0xef, 0xd,  0x16, 0x4e, 0x64, 0x65, 0xbd,
                                       0xd5, 0xd9, 0xec, 0x15, 0x38, 0x58, 0x91, 0xdf, 0xfc,
                                   },
                                   []( u64 val ) -> u64 { return val ^ 0x6FC7A2BC; },
                                   []( u64 val ) -> u64 { return val ^ 0x6FC7A2BC; } };

const vm_meta_data_t *vm_meta_data[ VM_COUNT ] = { &table_one, &table_two,   &table_three, &table_four, &table_five,
                                                   &table_six, &table_seven, &table_eight, &table_nine, &table_ten };

inline u64 g_image_base = 0u, g_image_size = 0u, g_image_clone = 0u;
inline inline_hook_t g_sha1_hook;