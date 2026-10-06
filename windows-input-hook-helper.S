/*
 * Native x86-64 Windows helper for KIDZ.
 *
 * It installs WH_KEYBOARD_LL and WH_MOUSE_LL hooks from code that genuinely
 * lives in a native PE module.  A nonzero hook result consumes ordinary input.
 * The PowerShell guard owns this child process; terminating it releases both
 * hooks automatically.
 *
 * Build on GNU binutils 2.42+:
 *   as --64 -o windows-input-hook-helper.o windows-input-hook-helper.S
 *   ld -mi386pep --subsystem windows --entry start --strip-all \
 *      --image-base 0x140000000 --file-alignment 512 --section-alignment 4096 \
 *      --disable-dynamicbase --disable-high-entropy-va --disable-reloc-section \
 *      --no-insert-timestamp \
 *      -o windows-input-hook-helper.exe windows-input-hook-helper.o
 */

    .equ IMAGE_BASE, 0x140000000
    .equ WH_KEYBOARD_LL, 13
    .equ WH_MOUSE_LL, 14

    .section .text,"ax"
    .global start

/* Windows x64 process entry point. */
start:
    subq $40, %rsp

    xorl %ecx, %ecx
    call *iat_GetModuleHandleW(%rip)
    movq %rax, %r14

    movl $WH_KEYBOARD_LL, %ecx
    leaq keyboard_hook(%rip), %rdx
    movq %r14, %r8
    xorl %r9d, %r9d
    call *iat_SetWindowsHookExW(%rip)
    testq %rax, %rax
    jz hook_failed
    movq %rax, %r12

    movl $WH_MOUSE_LL, %ecx
    leaq mouse_hook(%rip), %rdx
    movq %r14, %r8
    xorl %r9d, %r9d
    call *iat_SetWindowsHookExW(%rip)
    testq %rax, %rax
    jz mouse_failed
    movq %rax, %r13

message_loop:
    leaq message_buffer(%rip), %rcx
    xorl %edx, %edx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    call *iat_GetMessageW(%rip)
    testl %eax, %eax
    jle clean_exit

    leaq message_buffer(%rip), %rcx
    call *iat_TranslateMessage(%rip)
    leaq message_buffer(%rip), %rcx
    call *iat_DispatchMessageW(%rip)
    jmp message_loop

mouse_failed:
    call *iat_GetLastError(%rip)
    movl %eax, %ebx
    movq %r12, %rcx
    call *iat_UnhookWindowsHookEx(%rip)
    movl %ebx, %ecx
    call *iat_ExitProcess(%rip)

hook_failed:
    call *iat_GetLastError(%rip)
    movl %eax, %ecx
    call *iat_ExitProcess(%rip)

clean_exit:
    movq %r13, %rcx
    call *iat_UnhookWindowsHookEx(%rip)
    movq %r12, %rcx
    call *iat_UnhookWindowsHookEx(%rip)
    xorl %ecx, %ecx
    call *iat_ExitProcess(%rip)

/* LRESULT CALLBACK keyboard_hook(int code, WPARAM, LPARAM) */
keyboard_hook:
    testl %ecx, %ecx
    js keyboard_chain
    movl $1, %eax
    ret
keyboard_chain:
    movq %r8, %r9
    movq %rdx, %r8
    movslq %ecx, %rdx
    xorl %ecx, %ecx
    jmp *iat_CallNextHookEx(%rip)

/* LRESULT CALLBACK mouse_hook(int code, WPARAM, LPARAM) */
mouse_hook:
    testl %ecx, %ecx
    js mouse_chain
    movl $1, %eax
    ret
mouse_chain:
    movq %r8, %r9
    movq %rdx, %r8
    movslq %ecx, %rdx
    xorl %ecx, %ecx
    jmp *iat_CallNextHookEx(%rip)

    .section .bss,"aw"
    .align 16
/* MSG is 48 bytes on 64-bit Windows; reserve extra space defensively. */
message_buffer:
    .skip 64

    .section .idata$2,"aw"
    .align 8

/* IMAGE_IMPORT_DESCRIPTOR entries. */
import_descriptors:
    .long kernel32_int - IMAGE_BASE
    .long 0
    .long 0
    .long kernel32_name - IMAGE_BASE
    .long kernel32_iat - IMAGE_BASE

    .long user32_int - IMAGE_BASE
    .long 0
    .long 0
    .long user32_name - IMAGE_BASE
    .long user32_iat - IMAGE_BASE

    .section .idata$3,"aw"
    .fill 20, 1, 0

    .section .idata$4,"aw"
    .align 8
kernel32_int:
    .quad hn_GetModuleHandleW - IMAGE_BASE
    .quad hn_GetLastError - IMAGE_BASE
    .quad hn_ExitProcess - IMAGE_BASE
    .quad 0

user32_int:
    .quad hn_SetWindowsHookExW - IMAGE_BASE
    .quad hn_UnhookWindowsHookEx - IMAGE_BASE
    .quad hn_CallNextHookEx - IMAGE_BASE
    .quad hn_GetMessageW - IMAGE_BASE
    .quad hn_TranslateMessage - IMAGE_BASE
    .quad hn_DispatchMessageW - IMAGE_BASE
    .quad 0

    .section .idata$5,"aw"
    .align 8
kernel32_iat:
iat_GetModuleHandleW:
    .quad hn_GetModuleHandleW - IMAGE_BASE
iat_GetLastError:
    .quad hn_GetLastError - IMAGE_BASE
iat_ExitProcess:
    .quad hn_ExitProcess - IMAGE_BASE
    .quad 0

user32_iat:
iat_SetWindowsHookExW:
    .quad hn_SetWindowsHookExW - IMAGE_BASE
iat_UnhookWindowsHookEx:
    .quad hn_UnhookWindowsHookEx - IMAGE_BASE
iat_CallNextHookEx:
    .quad hn_CallNextHookEx - IMAGE_BASE
iat_GetMessageW:
    .quad hn_GetMessageW - IMAGE_BASE
iat_TranslateMessage:
    .quad hn_TranslateMessage - IMAGE_BASE
iat_DispatchMessageW:
    .quad hn_DispatchMessageW - IMAGE_BASE
    .quad 0

    .section .idata$6,"aw"
    .align 2
hn_GetModuleHandleW:
    .short 0
    .asciz "GetModuleHandleW"
hn_GetLastError:
    .short 0
    .asciz "GetLastError"
hn_ExitProcess:
    .short 0
    .asciz "ExitProcess"
hn_SetWindowsHookExW:
    .short 0
    .asciz "SetWindowsHookExW"
hn_UnhookWindowsHookEx:
    .short 0
    .asciz "UnhookWindowsHookEx"
hn_CallNextHookEx:
    .short 0
    .asciz "CallNextHookEx"
hn_GetMessageW:
    .short 0
    .asciz "GetMessageW"
hn_TranslateMessage:
    .short 0
    .asciz "TranslateMessage"
hn_DispatchMessageW:
    .short 0
    .asciz "DispatchMessageW"

kernel32_name:
    .asciz "KERNEL32.dll"
user32_name:
    .asciz "USER32.dll"
