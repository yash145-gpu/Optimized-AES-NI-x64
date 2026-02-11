;;;     Yash Shinde    MCA   25112041    SEM-I      PUCSD     B-25      
;;;     Project Guide :  Achyut.K ROY 


;;  Highly Optimized Low Latency Hardware AES128ECB Implementation and Benchmarking
;;  x86_64 Intel Assembly without any external library 
;;  CPU: Intel Skylake ; AVX2, AES-NI

;Random Key generation from urandom
;Align key to 16bytes
;Align ptext,data to 16bytes
;Key Expansion (Round Encryption keys) : 128Bytes x 11 
;Key Inversion (Round Decryption keys) : 128Bytes x 11 
;Populate vector registers with round keys 
;Cache Prefetch & Warmup with dummy round
;Urolled Encryption and Decryption cycle
;Cipher file Out
;Serialize CPU pipeline 
;Read CPU clock cycle timestamp (RDTSC)
;Benchmark Enc+Dec cycle for 10000 rounds 
;Calculate Avg clock cycle cost for 1 round;
;Terminate

default rel
bits 64
section .data
    Bench_iterations equ 10000
    vec db 'plainVector128',0  
    op  db 'encop',0 

section .bss
    align 16  
    key       resq 2
    align 16  
    ctext     resq 2
    align 16  
    decrypted resq 2
    
    align 16  
    KeyEnc   resq 22
    align 16  
    KeyDec   resq 22
    
    align 16  
    ptext     resq 2 
    fd        resb 1
  
section .text
global _start
_start:
    ;Random keygen 
    mov rax, 318      
    lea rdi, [key]  
    mov rsi, 16           
    xor rdx, rdx              
    syscall

    mov rax, 2                   
    mov rdi, vec             
    xor rsi, rsi                    
    syscall   
   
    mov [fd], rax                
    xor rax, rax                   
    mov rdi, [fd]                 
    lea rsi, [ptext]          
    mov rdx, 16                   
    syscall  
    mov rax, 3                   
    mov rdi, [fd]                
    syscall  
    
    ;key expansion & key inversion
    lea rdi, [key]
    lea rsi, [KeyEnc]
    call ExpandKey 
    lea rdi, [KeyEnc] 
    lea rsi, [KeyDec]
    call invertRK
  
  
   lea rdi, [KeyEnc]
   movdqa xmm1,  [rdi]    
   movdqa xmm2,  [rdi + 0x10]    
   movdqa xmm3,  [rdi + 0x20]    
   movdqa xmm4,  [rdi + 0x30]    
   movdqa xmm5,  [rdi + 0x40]    
   movdqa xmm6,  [rdi + 0x50]   
   movdqa xmm7,  [rdi + 0x60]    
   movdqa xmm8,  [rdi + 0x70]   
   movdqa xmm9,  [rdi + 0x80]   
   movdqa xmm10, [rdi + 0x90]    
   movdqa xmm11, [rdi + 0xA0]    ;11 enc xmm0-10
   lea rdi, [KeyDec]
   movdqa xmm12, [rdi]    
   movdqa xmm13, [rdi + 0x10]    
   movdqa xmm14, [rdi + 0x20]    
   movdqa xmm15, [rdi + 0x30]    ;4 dec xmm12-15
   
 ;CACHE WARMUP ROUND ENC
 ;0th Round  :key Addition
 ;Rounds 1-9 :SubBytes->ShiftRows->MixColumn->AddRoundKey
 ;Last AES ENC round without MixColumn 
 movdqa xmm0, [ptext]
    pxor    xmm0, xmm1        
    aesenc  xmm0, xmm2     
    aesenc  xmm0, xmm3    
    aesenc  xmm0, xmm4      
    aesenc  xmm0, xmm5   
    aesenc  xmm0, xmm6  
    aesenc  xmm0, xmm7      
    aesenc  xmm0, xmm8      
    aesenc  xmm0, xmm9      
    aesenc  xmm0, xmm10      
    aesenclast xmm0, xmm11  
    movdqa [ctext],xmm0
    call FileStr  
   
mov rcx,Bench_iterations

; Cache Prefetching  
prefetchnta [ptext]
prefetch [KeyDec]
prefetch [KeyDec + 64]
lea rdi, [KeyDec]
;Serialize CPU Pipeline , Benchmarking Starts here
lfence  
rdtsc
shl rdx, 32
or rax, rdx
mov rbx, rax     
; xmm0-15 -> ptext : xmm0 , xmm1-11 Enc keys , xmm12-15 Dec keys , Dec keys 5-11 from KeyDec
align 16
 AES_MAIN:
 movdqa xmm0,[ptext]
    pxor    xmm0, xmm1        
    aesenc  xmm0, xmm2     
    aesenc  xmm0, xmm3    
    aesenc  xmm0, xmm4      
    aesenc  xmm0, xmm5   
    aesenc  xmm0, xmm6  
    aesenc  xmm0, xmm7      
    aesenc  xmm0, xmm8      
    aesenc  xmm0, xmm9      
    aesenc  xmm0, xmm10      
    aesenclast xmm0, xmm11  
      
    pxor    xmm0, [rdi + 0xA0]      
    aesdec  xmm0, [rdi + 0x90]      
    aesdec  xmm0, [rdi + 0x80]    
    aesdec  xmm0, [rdi + 0x70]     
    aesdec  xmm0, [rdi + 0x60]       
    aesdec  xmm0, [rdi + 0x50]     
    aesdec  xmm0, [rdi + 0x40]   
    aesdec  xmm0, xmm15      
    aesdec  xmm0, xmm14      
    aesdec  xmm0, xmm13      
    aesdeclast xmm0, xmm12         
    dec rcx
    jnz AES_MAIN
 
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, rbx      
    
    mov rbx, Bench_iterations
    xor rdx, rdx
    div rbx           
    
    call UintOut 
    call nl
    
  mov rbx, ctext
  mov rcx, 16
  call BytesOut
  call nl
  
  movdqa [decrypted], xmm0
  mov rbx, decrypted
  mov rcx, 16
  call BytesOut
  call nl
  
  mov rbx, key
  mov rcx, 16
  call BytesOut
  call nl
      
 mov rax, 60
 xor rdi, rdi
 syscall 

ExpandKey: 
   movdqa xmm0, [rdi]
   movdqa [rsi], xmm0
    aeskeygenassist xmm2, xmm0, 0x01
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x02
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x04
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x08
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x10
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x20
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x40
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x80
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x1B
    call expandnxt
    aeskeygenassist xmm2, xmm0, 0x36
    call expandnxt
    ret

expandnxt:
    pshufd xmm2, xmm2, 0xff
   movdqa xmm1, xmm0
    pslldq xmm1, 4
    pxor xmm0, xmm1
    pslldq xmm1, 4
    pxor xmm0, xmm1
    pslldq xmm1, 4
    pxor xmm0, xmm1
    pxor xmm0, xmm2
    add rsi, 16
   movdqa [rsi], xmm0
    ret

invertRK:
   movdqa xmm0, [rdi]
   movdqa [rsi], xmm0  
   movdqa xmm0, [rdi + 0x10]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x10], xmm0
   movdqa xmm0, [rdi + 0x20]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x20], xmm0
   movdqa xmm0, [rdi + 0x30]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x30], xmm0
   movdqa xmm0, [rdi + 0x40]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x40], xmm0
   movdqa xmm0, [rdi + 0x50]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x50], xmm0
   movdqa xmm0, [rdi + 0x60]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x60], xmm0
   movdqa xmm0, [rdi + 0x70]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x70], xmm0
   movdqa xmm0, [rdi + 0x80]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x80], xmm0
   movdqa xmm0, [rdi + 0x90]
    aesimc xmm0, xmm0
   movdqa [rsi + 0x90], xmm0
   movdqa xmm0, [rdi + 0xA0]
   movdqa [rsi + 0xA0], xmm0
    ret
    
UintOut:
    push rbx
    push rcx
    push rdx
    push rsi   
    mov rcx, 10
    mov rbx, rsp
    sub rsp, 32
    lea rdi, [rsp + 31]
    mov byte [rdi], 0
    
PrintL:
    xor rdx, rdx
    div rcx
    add dl, '0'
    dec rdi
    mov [rdi], dl
    test rax, rax
    jnz PrintL

    mov rsi, rdi
    mov rdx, rsp
    add rdx, 32
    sub rdx, rsi
    mov rax, 1
    mov rdi, 1
    syscall

    add rsp, 32
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret
BytesOut:
    mov rax, 1
    mov rdi, 1
    mov rsi, rbx
    mov rdx, rcx
    syscall
    ret
nl:
    push 10
    mov rax, 1
    mov rdi, 1
    mov rsi,rsp
    mov rdx, 1
    syscall
    add rsp, 8 
    ret
    
FileStr:
    push rdi
    mov rax, 2           
    lea rdi, [op]
    mov rsi, 0301o             
    mov rdx, 0644o                
    syscall
     mov [fd], rax
    mov rax, 1                    
    mov rdi, [fd]
    lea rsi, [ctext]
    mov rdx, 16
    syscall
    mov rax, 3
    mov rdi, [fd]
    syscall
    pop rdi
    ret
