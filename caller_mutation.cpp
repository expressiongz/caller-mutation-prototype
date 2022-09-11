#include <iostream>
#include <Windows.h>
#include <thread>
#include <span>
#include <array>
#include <unordered_map>
#define _DEBUG

std::vector< std::uint8_t > ret_function_bytes( void* address )
{
	auto byte = static_cast< std::uint8_t* >( address );
	std::vector< std::uint8_t > function_bytes{ };

	static const std::unordered_map< std::uint8_t, std::uint8_t > ret_bytes_map
	{
		{
			0xC2,
			0x03
		},
		{
			0xC3,
			0x01
		}
	};

	static const auto alignment_bytes = std::to_array< std::uint8_t >
	( 
		{ 0xCC, 0x90 } 
	);

	while( true )
	{
		function_bytes.push_back( *byte );

		for( const auto& ret_byte : ret_bytes_map )
		{
			const auto& [ opcode, opcode_sz ] = ret_byte;
			if( *byte == opcode )
			{
				for( const auto& alignment_byte : alignment_bytes )
				{
					if( *( byte + opcode_sz ) == alignment_byte )
						return function_bytes;
				}
			}
			
		}
		++byte;
	}
	
}


void* map_mutation_function( void* callee_function_address, std::span< std::uint8_t > overwritten_function_bytes )
{
	const auto callee_function_instrs = ret_function_bytes( callee_function_address );

	const auto mutation_func = VirtualAlloc( nullptr, overwritten_function_bytes.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	const auto new_callee = VirtualAlloc( nullptr, callee_function_instrs.size( ), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	
	if( !mutation_func )
		throw std::runtime_error( "failed to allocate mutation function" );
	if( !new_callee )
		throw std::runtime_error( "failed to allocate new callee" );

#ifdef _DEBUG
	std::printf( "allocated mutation function:  %p\n", mutation_func );
	std::printf( "allocated new callee: %p\n", new_callee );
#endif
	
	for( auto it = callee_function_instrs.begin( ); it < callee_function_instrs.end( ); ++it )
	{
		if( *it == 0xE9 || *it == 0xE8 )
		{
			const auto dist = std::distance( callee_function_instrs.begin( ), it );
			const auto o_rel_offset = *reinterpret_cast< std::uint32_t* >( it._Ptr + 1 );
			const auto o_next_instr = reinterpret_cast< std::uint32_t >( callee_function_address ) + dist + 5;
			const auto callee_abs_address = o_next_instr + o_rel_offset;
			const auto next_instr = reinterpret_cast< std::uint32_t >( new_callee ) + dist + 5;
			const auto rel_addr = callee_abs_address - next_instr;
			*reinterpret_cast< std::uint32_t* >( it._Ptr + 1 ) = rel_addr;
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
	constexpr auto rel_addr_of_callee = 0x1000;

	const auto callee_address = base + rel_addr_of_callee;

	auto mutate_function_bytes = ret_function_bytes( &mutate );
	const auto new_callee = reinterpret_cast< void( __cdecl * )( const char* ) >( map_mutation_function( reinterpret_cast< void* >( callee_address ), mutate_function_bytes ) );

	new_callee( "exprssn 2 good" );
}



bool __stdcall DllMain( HMODULE dll_module, const std::uint32_t reason_for_call, void* )
{
	if( reason_for_call == DLL_PROCESS_ATTACH )
	{
		std::thread{ main_thread, dll_module }.detach( );
	}
	return true;
}
