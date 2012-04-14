#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

static void syscall_handler (struct intr_frame *);
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void sys_exit(struct intr_frame *f);
static void sys_write(struct intr_frame *f);
static void sys_remove(struct intr_frame *f);
static void sys_create(struct intr_frame *f);
static void sys_open(struct intr_frame *f);

struct file *fds[256];

void
syscall_init (void) 
{
  int i;
  for (i = 0; i < 256; ++i) {
      fds[i] = NULL;
  }
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  //printf ("system call! Thread: %s\n", thread_name());
  /* Read the system call number off of caller's stack */
  uint32_t call_number;
  bool success = get_int_32(&call_number, (uint32_t *) f->esp);
  /* Terminate if invalid address */
  if (!success) {
      //DEBUG
      //printf("System call number pointer was bad.\n");
      thread_exit();
  } else {
    //DEBUG
    //printf("syscall number %d\n", call_number);
  }
  switch (call_number) {
      case SYS_WRITE:
          sys_write(f);
          break;
      case SYS_EXIT:
          sys_exit(f);
          break;
      case SYS_REMOVE:
          sys_remove(f);
          break;
      case SYS_HALT:
      case SYS_EXEC:
      case SYS_WAIT:
      case SYS_CREATE:
          sys_create(f);
          break;
      case SYS_OPEN:
          sys_open(f);
          break;
      case SYS_FILESIZE:
      case SYS_READ:
      case SYS_SEEK:
      case SYS_TELL:
      case SYS_CLOSE:
      default:
          thread_exit();
  }
}

static void
sys_open(struct intr_frame *f)
{
    char *file;
    if (get_int_32((uint32_t *) &file, (uint32_t *) f->esp + 1) && validate_address(file))
    {
        /* Find a free file descriptor */
        int fd = 0;
        int i;
        for (i = 3; i < 256; ++i) {
            if (fds[i] == NULL) {
                fd = i;
                break;
            }
        }
        /* Return error if none available */
        if (fd == 0) {
            f->eax = -1;
            return;
        }
        
        /* Actually open the file */
        struct file *file_ptr = filesys_open(file);
        if (file_ptr == NULL) {
            f->eax = -1;
            return;
        } else {
            fds[fd] = file_ptr;
            f->eax = fd;
            return;
        }
    }
    else
    {
        f->eax = -1;
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
        //DEBUG
        //printf("exit() succeeeding: code is %d\n", result);
    } //else {
        //printf("exit() had bad arg pointer\n");
    //}

    thread_exit();
}

static void
sys_remove(struct intr_frame *f)
{
    char *file;
    if (!get_int_32((uint32_t *) & file, (uint32_t *) f->esp + 1))
    {
        f->eax = false;
        thread_exit();
    }
    else if (!validate_address(file))
    {
        f->eax = false;
        thread_exit();
    }
    else
    {
        f->eax = filesys_remove(file);
    }
}

static void
sys_create(struct intr_frame *f)
{
    char *file;
    unsigned int initial_size;
    if (!get_int_32((uint32_t *) & file, (uint32_t *) f->esp + 1))
    {
        f->eax = false;
        thread_exit();
    }
    else if (!get_int_32((uint32_t *) & initial_size, (uint32_t *) f->esp + 2))
    {
        f->eax = false;
        thread_exit();
    }
    else if (!validate_address(file))
    {
        f->eax = false;
        thread_exit();
    }
    else
    {
        f->eax = filesys_create(file, initial_size);
    }
}

/* Validate address by trying to read a byte at the address. */
bool
validate_address (const void *uaddr)
{
    /* Make sure address isn't in kernel memory */
    if (uaddr >= PHYS_BASE) {
        return false;
    }

    /* Make sure it's not NULL and owned by process */
    return get_user((const uint8_t *) uaddr) != -1;
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
        *result += (uint32_t) uaddr_8 << (i << 3);
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
