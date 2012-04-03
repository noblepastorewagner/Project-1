#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

/* Reads a 32-bit int at user virtual address UADDR.
 * UADDR need not be valid. This function returns false if not (and terminates
 * the user program? TODO). */
static bool
get_int_32 (const uint32_t *result, const uint32_t *uaddr)
{
    uint8_t uaddr_8;
    *result = 0;
    for (int i = 0; i < 4; ++i) {
        uaddr_8 = get_user((uint8_t) uaddr);
        if (uaddr_8 == -1) {
            /* TODO kill the user program? Do it in page_fault()?
             * Or in system call handler? */
            return false;
        }
        result += uaddr_8 << (i << 3);
    }
    return true;
}


/* Reads a byte at user virtual address UADDR.
 * UADDR must be below PHYS_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int
get_user (const uint8_t *uaddr)
{
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below PHYS_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
    int error_code;
    asm ("movl $1f, %0; movb %b2, %1; 1:"
            : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
