/* halt.c

   Simple program to test whether running a user program works.
 	
   Just invokes a system call that shuts down the OS. */

#include <syscall.h>

int
main (void)
{
/*	int handle;
	handle = open("sample.txt");
	close(handle);
	*/
  int handle, byte_cnt;

	char sample[] = {"test.txt"};
 	create ("test.txt", sizeof sample - 1);
  handle = open ("test.txt");

  byte_cnt = write (handle, sample, sizeof sample - 1);
 
  /* not reached */
}
