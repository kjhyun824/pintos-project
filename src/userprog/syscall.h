#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
/* SJ */
struct fd_struct* find_struct_by_fd(int fd);
#endif /* userprog/syscall.h */
