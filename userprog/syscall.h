#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include <stdbool.h>
#include <stdint.h>

void syscall_init (void);
bool get_int_32(uint32_t *result, const uint32_t *uaddr);
bool validate_address (const void *uaddr);

#endif /* userprog/syscall.h */
