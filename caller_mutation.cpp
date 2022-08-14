#include <iostream>
#include <Windows.h>
#include <thread>
#include <functional>
#include <span>

#define _DEBUG

void map_mutation_function( void* callee_function_address, std::span< std::uint8_t > overwritten_function_bytes )
{
	const auto alloc_func = VirtualAlloc( nullptr, overwritten_function_bytes.size( ), MEM_COMMIT, PAGE_EXECUTE_READWRITE );

	if( !alloc_func )
		throw std::runtime_error( "failed to allocate function" );

#ifdef _DEBUG
	std::printf( "allocated function address %p\n", alloc_func );
#endif

	std::memcpy( alloc_func, overwritten_function_bytes.data( ), overwritten_function_bytes.size( ) );

	DWORD vp_old_protection{ 0u };

	VirtualProtect( callee_function_address, 5,  PAGE_EXECUTE_READWRITE, &vp_old_protection );

	const auto relative_address = reinterpret_cast< std::uint32_t >( alloc_func ) - reinterpret_cast< std::uint32_t >( callee_function_address ) - 5;

	*static_cast< std::uint8_t* >( callee_function_address ) = 0xE9;
	*reinterpret_cast< std::uint32_t* >( reinterpret_cast< std::uint32_t >( callee_function_address ) + 1 ) = relative_address;

	VirtualProtect( callee_function_address, 5,  vp_old_protection, &vp_old_protection );
}

std::vector< std::uint8_t > ret_function_instrs( void* function_address )
{
	std::vector< std::uint8_t > function_bytes{ };
	auto byte = static_cast< std::uint8_t* >( function_address );
	do 
	{
		function_bytes.push_back( *byte );
		++byte;

	} while ( *reinterpret_cast< std::uint32_t* >( byte ) != 0xCCCCCCCC );
	return function_bytes;
}


DWORD vp_old_protection{ 0u };
void* caller_next_instr{ nullptr };

_declspec( naked ) void mutate( )
{
	__asm
	{
		mov eax, [ esp ]
		mov caller_next_instr, eax
		xor eax, eax
	}
	caller_next_instr = reinterpret_cast< void* >( reinterpret_cast< std::uint32_t >( caller_next_instr ) - 5 );

	VirtualProtect( caller_next_instr , 5, PAGE_EXECUTE_READWRITE, &vp_old_protection );
	std::memset( caller_next_instr,  0x90, 5 );
	VirtualProtect( caller_next_instr, 5, vp_old_protection, &vp_old_protection );

	__asm
	{
		pop ebp
		jmp caller_next_instr 
	}
}

void main_thread( HMODULE dll_module )
{
	const auto base = reinterpret_cast< std::uint32_t >( GetModuleHandleA( nullptr ) );
	const auto callee_address = base + 0xDEADBEEF;

	auto mutate_function_bytes = ret_function_instrs( &mutate );
	map_mutation_function( reinterpret_cast< void* >( callee_address ), mutate_function_bytes );
}



bool __stdcall DllMain( HMODULE dll_module, const std::uint32_t reason_for_call, void* )
{
	if( reason_for_call == DLL_PROCESS_ATTACH )
	{
		std::thread{ main_thread, dll_module }.detach( );
	}
	return true;
}