#include <iostream>
#include <Windows.h>
#include <thread>
#include <functional>
#include <span>
#include <cstdint>

#define _DEBUG

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


void* map_mutation_function(  void* callee_function_address, std::span< std::uint8_t > overwritten_function_bytes )
{
	static const auto base_module_code_base = reinterpret_cast< std::uint32_t >( GetModuleHandleA( nullptr ) ) + 0x1000;
	const auto callee_function_instrs = ret_function_instrs( callee_function_address );

	const auto mutation_func = VirtualAlloc( nullptr, overwritten_function_bytes.size( ), MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	const auto new_callee = VirtualAlloc( nullptr, callee_function_instrs.size( ), MEM_COMMIT, PAGE_EXECUTE_READWRITE );
	
	if( !mutation_func )
		throw std::runtime_error( "failed to allocate function" );
	if( !new_callee )
		throw std::runtime_error( "failed to allocate new callee" );

#ifdef _DEBUG
	std::printf( "allocated mutation function:  %p\n", mutation_func );
	std::printf( "allocated new callee: %p\n", new_callee );
#endif
	
	for( auto it = callee_function_instrs.begin( ); it < callee_function_instrs.end( ); ++it )
	{
		if( *it == 0xE8 )
		{
			const auto rel_call = reinterpret_cast< std::uint32_t* >( it._Ptr + 1 );
			*rel_call = *rel_call - reinterpret_cast< std::uint32_t >( new_callee ) + base_module_code_base;
		}
	}

	std::memcpy( mutation_func, overwritten_function_bytes.data( ), overwritten_function_bytes.size( ) );
	std::memcpy( new_callee, callee_function_instrs.data( ), callee_function_instrs.size( ) );

	DWORD vp_old_protection{ 0u };

	VirtualProtect( callee_function_address, 5,  PAGE_EXECUTE_READWRITE, &vp_old_protection );

	const auto relative_address = reinterpret_cast< std::uint32_t >( mutation_func ) - reinterpret_cast< std::uint32_t >( callee_function_address ) - 5;

	*static_cast< std::uint8_t* >( callee_function_address ) = 0xE9;
	*reinterpret_cast< std::uint32_t* >( reinterpret_cast< std::uint32_t >( callee_function_address ) + 1 ) = relative_address;

	VirtualProtect( callee_function_address, 5,  vp_old_protection, &vp_old_protection );

	return new_callee;
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
	constexpr auto rel_addr_of_callee = 0xDEADBEEF;

	const auto callee_address = base + rel_addr_of_callee;

	auto mutate_function_bytes = ret_function_instrs( &mutate );
	const auto new_callee = reinterpret_cast< void( * )( ) >( map_mutation_function( reinterpret_cast< void* >( callee_address ), mutate_function_bytes ) );

	new_callee( );
}



bool __stdcall DllMain( HMODULE dll_module, const std::uint32_t reason_for_call, void* )
{
	if( reason_for_call == DLL_PROCESS_ATTACH )
	{
		std::thread{ main_thread, dll_module }.detach( );
	}
	return true;
}
