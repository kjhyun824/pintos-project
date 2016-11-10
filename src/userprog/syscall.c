#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "lib/user/syscall.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static void syscall_handler (struct intr_frame *);

struct lock file_lock;
struct lock thr_lock;

	void
syscall_init (void) 
{
	lock_init(&file_lock);
	lock_init(&thr_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* SJ */
struct fd_struct*
find_struct_by_fd(int fd) {
	struct thread *cur = thread_current();
	struct list_elem *temp;
	struct fd_struct *finded;
	bool success = false;

	if ( !list_empty(&(cur->fd_list)) ) {
		temp = list_front(&(cur->fd_list));
		while(1) {
			finded = list_entry(temp,struct fd_struct,elem);
			if ( finded->fd == fd ) {
				success = true;
				break;
			}
			if ( temp == list_back(&(cur->fd_list)) ) break;
			temp = list_next(temp);
		}
	}

	if(success) 
		return finded;
	return NULL;
}

void halt (void) {
	shutdown_power_off();
}

void exit (int status) {
	if ( thread_current()->parent_tid != 0 ) {
		struct thread *t = thread_by_tid(thread_current()->parent_tid);
		struct list_elem *temp = list_front(&t->child_list);

		while(1) {
			if ( list_entry(temp,struct child_struct,elem)->tid == thread_current()->tid ) break;
			if ( temp == list_back(&t->child_list) ) break;
			temp = temp->next; 
		}
		list_entry(temp,struct child_struct,elem)->exit_status = status;
	}

	printf("%s: exit(%d)\n",thread_current()->name,status);

	child_list_remove(thread_current());

	thread_exit();
}

pid_t exec (const char *cmd_line) {
	lock_acquire(&file_lock);

	pid_t pid = process_execute(cmd_line);
	struct child_struct *cs = palloc_get_page(PAL_USER);

	cs->tid = pid;
	cs->exit_status = -1;
	cs->waited = false;
	list_push_back(&thread_current()->child_list,&cs->elem);

	lock_release(&file_lock);

	if(pid == -1) return -1;

	struct thread *t = thread_by_tid(pid);
	t->parent_tid = thread_current()->tid;


	return pid;
}

int wait (pid_t pid) {
	int wait_res = process_wait(pid);
	return wait_res;
}

bool create (const char *file, unsigned initial_size) {
	if ( file == NULL ) exit(-1);
	lock_acquire(&file_lock);
	bool success = filesys_create(file,initial_size);
	lock_release(&file_lock);
	return success;
}

bool remove (const char *file) {
	lock_acquire(&file_lock);
	bool success = filesys_remove(file);
	lock_release(&file_lock);
	return success;
}

int open (const char *file) {
	if ( file == NULL ) return -1;

	lock_acquire(&file_lock);
	struct file* opened = filesys_open(file);
	struct thread* cur = thread_current();
	if(opened == NULL) { lock_release(&file_lock); return -1; }
	else {
		struct fd_struct *new_fd = palloc_get_page(PAL_USER);
		if(!list_empty(&(cur->fd_list))) {
			new_fd->fd = list_entry(list_back(&(cur->fd_list)), struct fd_struct, elem)->fd + 1;
		} else {
			new_fd->fd = 2;
		}
		new_fd->file = opened;
		list_push_back(&(cur->fd_list), &(new_fd->elem));

		if ( strcmp(thread_current()->name, file) == 0 ) {
			file_deny_write(opened);
		}
		lock_release(&file_lock);

		return new_fd->fd;
	}
}

int filesize (int fd) {
	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(!fdst)	{lock_release(&file_lock); return -1;}

	int len_res = file_length(fdst->file);
	lock_release(&file_lock);
	return len_res;
}

int read (int fd, void *buffer, unsigned size) { 
	if(thread_current()->name != "main" && buffer >= PHYS_BASE) exit(-1);
	if ( fd == 0 ) return input_getc();

	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(!fdst) { lock_release(&file_lock); return -1; }

	int bytes_read = file_read(fdst->file, buffer, size);
	lock_release(&file_lock);
	return bytes_read;
}

int write (int fd, const void *buffer, unsigned size) {
	if(fd == 1) {
		putbuf((char *)buffer,size);
		return size;
	}

	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(!fdst) { lock_release(&file_lock); return -1; }

	int bytes_written = file_write(fdst->file, buffer, size);
	lock_release(&file_lock);
	return bytes_written;
}

void seek (int fd, unsigned position) {
	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(fdst) {
		file_seek(fdst->file, position);
	}
	lock_release(&file_lock);
}

unsigned tell (int fd) {
	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(!fdst) { lock_release(&file_lock); return -1; }

	unsigned tell_res = file_tell(fdst->file) + 1;
	lock_release(&file_lock);
	return tell_res;
}

void close (int fd) {
	lock_acquire(&file_lock);
	struct fd_struct* fdst = find_struct_by_fd(fd);
	if(fdst) { 
		list_remove(&fdst->elem);
		file_close(fdst->file);
	}
	palloc_free_page(fdst);
	lock_release(&file_lock);
}

	static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	int *ptr = f->esp;
	int i;
	struct thread *curr = thread_current();

	switch(*ptr) {
		case SYS_HALT://0
			halt();
			break;
		case SYS_EXIT://1
			if ( !is_user_vaddr(ptr + 4) || ptr < (void *) 0x08048000 ) 	exit(-1);
			exit(*(ptr+1));
			break;
		case SYS_EXEC://2
			f->eax = (uint32_t) exec(*(ptr+1));
			break;
		case SYS_WAIT://3
			f->eax = (uint32_t) wait(*(ptr+1));
			break;
		case SYS_CREATE://4
			f->eax = (uint32_t) create(*(ptr+1),*(ptr+2));
			break;
		case SYS_REMOVE://5
			f->eax = (uint32_t) remove(*(ptr+1));
			break;
		case SYS_OPEN://6
			f->eax = (uint32_t) open(*(ptr+1));
			break;
		case SYS_FILESIZE://7
			f->eax = (uint32_t) filesize(*(ptr+1));
			break;
		case SYS_READ://8
			f->eax = (uint32_t) read(*(ptr+1),*(ptr+2),*(ptr+3));
			break;
		case SYS_WRITE://9
			f->eax = (uint32_t) write(*(ptr+1),*(ptr+2),*(ptr+3));
			break;
		case SYS_SEEK://10
			seek(*(ptr+1),*(ptr+2));
			break;
		case SYS_TELL://11
			f->eax = (uint32_t) tell(*(ptr+1));
			break;
		case SYS_CLOSE://12
			close(*(ptr+1));
			break;
		default:
			printf("No proper handler\n");
	}
	//thread_exit ();
}
