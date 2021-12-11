.intel_syntax noprefix
.global _dlopen_addr_s
.global _dlopen_param1_s
.global _dlopen_param2_s
.global _dlsym_addr_s
.global _dlsym_param2_s
.global _dlclose_addr_s
.global _inject_start_s
.global _inject_end_s
.global _inject_function_param_s
.global _printf_addr_s
.global _debug_sign_s
.data
_inject_start_s:

	
loop:
	jmp loop

	mov    %rsi,0x2
_dlopen_param1_s:
	mov    %rdi,0x1122334455667788
_dlopen_addr_s:
	movabs %rax,0x1122334455667788
	call   %rax
	push %rax
_dlsym_param2_s:
	mov    %rsi,0x1122334455667788
	mov    %rdi,%rax
_dlsym_addr_s:
	mov %rbx,0x1122334455667788
	call   %rbx


	call %rax

	pop %rax
	mov %rdi,%rax
_dlclose_addr_s:
	mov %rbx,0x1122334455667788
	call %rbx
	int 0x80
	int 0xcc



_inject_end_s:
.space 0x400, 0
.end
