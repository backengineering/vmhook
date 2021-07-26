#include <vmhook-eac.hpp>

void *operator new( u64 size )
{
    //
    // Could have also used ExAllocatePoolZero...
    //

    return RtlZeroMemory( ExAllocatePool( NonPagedPool, size ), size );
}

void operator delete( void *ptr, u64 size )
{
    UNREFERENCED_PARAMETER( size );
    ExFreePool( ptr );
}

__declspec( noinline ) void hook_sha1( void *data, unsigned int len, void *result )
{
    sha1_ctx ctx;
    sha1_init( &ctx );

    //
    // if EAC is trying to sha1 hash any data in readonly sections...
    // then we hash the clone of the driver before it was patched...
    //
    // note: relocations are the same in the clone so those wont need to be handled...
    //

    if ( scn::read_only( g_image_base, ( u64 )data ) )
    {
        DBG_PRINT( "sha1 hash data = 0x%p, len = 0x%x, result = 0x%p\n", data, len, result );
        sha1_update( &ctx, ( unsigned char * )g_image_clone + ( ( ( u64 )data ) - g_image_base ), len );
        sha1_final( ( unsigned char * )result, &ctx );
        return;
    }

    //
    // else simply sha1 hash the data and return back to EasyAntiCheat.sys....
    //

    sha1_update( &ctx, ( unsigned char * )data, len );
    sha1_final( ( unsigned char * )result, &ctx );
}

void image_loaded( PUNICODE_STRING image_name, HANDLE pid, PIMAGE_INFO image_info )
{
    if ( !pid && wcsstr( image_name->Buffer, L"EasyAntiCheat.sys" ) )
    {
        if ( vm::g_vmctx && g_image_clone )
            delete vm::g_vmctx, ExFreePool( ( void * )g_image_clone );

        vm::handler::edit_entry_t _edit_entry = []( u64 *entry_ptr, u64 val ) -> void {
            //
            // disable write protect bit in cr0...
            //

            {
                _disable();
                auto cr0 = __readcr0();
                cr0 &= 0xfffffffffffeffff;
                __writecr0( cr0 );
            }

            *entry_ptr = val;

            //
            // enable write protect bit in cr0...
            //

            {
                auto cr0 = __readcr0();
                cr0 |= 0x10000;
                __writecr0( cr0 );
                _enable();
            }
        };

        auto image_base = reinterpret_cast< u64 >( image_info->ImageBase );

        //
        // Clone the entire driver into a kernel pool, keep in mind relocations will also be
        // the same as the original driver! Dont call any code in this clone, only refer to it...
        //

        vm::g_vmctx = new vm::hook_t();
        g_image_base = image_base, g_image_size = image_info->ImageSize;
        g_image_clone = ( u64 )RtlCopyMemory( ExAllocatePool( NonPagedPool, image_info->ImageSize ),
                                              image_info->ImageBase, image_info->ImageSize );

        const auto callback = []( vm::registers *regs, u8 handler_idx ) {
            const auto read_addr = reinterpret_cast< u64 * >( regs->rbp )[ 0 ];

            // shoot the tires right off the virtualized integrity checks in about 2 lines of code...
            if ( scn::read_only( g_image_base, read_addr ) )
            {
                // DBG_PRINT( " READ(Q/DW/B) EasyAntiCheat.sys+0x%x\n", ( read_addr - g_image_base ) );
                reinterpret_cast< u64 * >( regs->rbp )[ 0 ] = g_image_clone + ( read_addr - g_image_base );
            }
        };

        for ( auto idx = 0u; idx < VM_COUNT; ++idx )
        {
            auto vm_handler_table =
                new vm::handler::table_t( g_image_base, EAC_IMAGE_BASE, vm_meta_data[ idx ]->table_rva, _edit_entry,
                                          vm_meta_data[ idx ]->decrypt, vm_meta_data[ idx ]->encrypt );

            for ( auto cnt = 0u; cnt < vm_meta_data[ idx ]->read_callback_count; ++cnt )
                vm_handler_table->set_callback( vm_meta_data[ idx ]->read_callback_indexes[ cnt ], callback );

            vm::g_vmctx->add_table( vm_handler_table );
        }

        //
        // hooks all vm handlers and starts callbacks...
        //
        vm::g_vmctx->start();

        // hook on sha1 since it executes outside of the virtual machine...
        // and does an integrity check on .text and .eac0...
        make_inline_hook( &g_sha1_hook, ( void * )( image_base + EAC_SHA1_OFFSET ), &hook_sha1, true );
    }
}

//
// this entry point is called by ZwSwapCert...
//

extern "C" NTSTATUS drv_entry( PDRIVER_OBJECT drv_object, PUNICODE_STRING reg_path )
{
    UNREFERENCED_PARAMETER( drv_object );
    UNREFERENCED_PARAMETER( reg_path );

    //
    // This kernel driver cannot be unloaded so there is no unload routine...
    // This is because ZwSwapCert will cause the system to crash...
    //

    DBG_PRINT( "> registering on image load callbacks...\n" );
    return PsSetLoadImageNotifyRoutine( &image_loaded );
}