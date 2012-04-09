#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* Next 2 functions are from Pintos docs. To assist in reading user memory
 * safely. */

static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);

#endif /* userprog/syscall.h */
