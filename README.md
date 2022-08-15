# caller-mutation-prototype
A prototype made for a base idea of how to achieve caller mutation
# How it works
This works by hooking a function to execute our instructions which will mutate that function's caller's instruction which calls our function to 0x90 ( nop / no operation ) which will prevent any calls to the callee, it will then create a copy of the callee with fixed relative calls and returns the address of that copy, allowing you to call the function with the same behavior as the callee.
