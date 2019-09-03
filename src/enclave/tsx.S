.data
.globl g_original_ssa_rip
.globl g_worker_ssa_gpr
g_worker_ssa_gpr:
  .word 0x0
  .word 0x0
  .word 0x0
  .word 0x0
g_original_ssa_rip:
  .word 0x0
  .word 0x0
  .word 0x0
  .word 0x0

.text
.globl custom_eresume_handler
.type custom_eresume_handler,@function
custom_eresume_handler:
  push %rax
  push %rbx
  lea g_worker_ssa_gpr(%rip),%rax
  mov (%rax),%rbx
  movl $12345,(%rbx)
  pop %rbx
  pop %rax
  jmp *g_original_ssa_rip(%rip)
