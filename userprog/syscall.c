#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void sys_exit(struct intr_frame *f);
static void sys_write(struct intr_frame *f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  printf ("system call!\n");
  /* Read the system call number off of caller's stack */
  uint32_t call_number;
  bool success = get_int_32(&call_number, (uint32_t *) f->esp);
  /* Terminate if invalid address */
  if (!success) {
      thread_exit();
  }
  switch (call_number) {
      case SYS_WRITE:
          sys_write(f);
          break;
      case SYS_EXIT:
          sys_exit(f);
          break;
      default:
          thread_exit();
  }
}

static void
sys_write(struct intr_frame *f)
{
  uint32_t fd;
  uint32_t buffer;
  uint32_t size;

  if(get_int_32(&fd, (uint32_t *) f->esp + 1) && get_int_32(&buffer, (uint32_t *) f->esp + 2) && get_int_32(&size, (uint32_t *) f->esp + 3))
  {
    if(fd == 1)
    {
      putbuf((const char *) buffer, (size_t) size);
      f->eax = size; 
    }
  }
  else
  {
    thread_exit();
  }
}

static void
sys_exit(struct intr_frame *f)
{
    uint32_t result;
    bool success = get_int_32(&result, (uint32_t *) f->esp + 1);

    /* We will terminate either way, but set the exit code only if the address
     * was valid (the default -1 will be used otherwise). */
    if (success) {
        thread_current()->exit_code = result;
    }

    thread_exit();
}

/* Reads a 32-bit int at user virtual address UADDR.
 * UADDR need not be valid. This function returns false if not (and the user
 * program should be terminated by the caller). It returns true on success. */
bool
get_int_32 (uint32_t *result, const uint32_t *uaddr)
{
    int i;

    /* Make sure pointer isn't in kernel address space */
    if ((void *) uaddr >= PHYS_BASE) {
        return false;
    }

    /* Get the value, byte by byte */
    int uaddr_8;
    *result = 0;
    for (i = 0; i < 4; ++i) {
        uaddr_8 = get_user((uint8_t *) uaddr + i);
        if (uaddr_8 == -1) {
            return false;
        }
        result += (uint32_t) uaddr_8 << (i << 3);
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
