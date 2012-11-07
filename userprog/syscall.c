#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
 
static int sys_halt (void);
static int sys_exit (int status);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static int sys_create (const char *ufile, unsigned initial_size);
static int sys_remove (const char *ufile);
static int sys_open (const char *ufile);
static int sys_filesize (int handle);
static int sys_read (int handle, void *udst_, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static int sys_close (int handle);
 
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);

static bool mem_access(const void *addr, const void *sp);
 
/* Serializes file system operations. */
static struct lock fs_lock;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&fs_lock);
}
 
/* System call handler. */
static void
syscall_handler (struct intr_frame *f)
{
	//Get the system call number from the sp
	int *sys_call = f->esp;
	//Check if we have a valid user address
	mem_access( sys_call, f->esp );
	
	switch( *sys_call )
	{
		case SYS_HALT:
			f->eax = sys_halt( );
			break;
			
		case SYS_EXIT:
			f->eax = sys_exit( *(sys_call+1) ); //Have to dereference here because its a pointer to the argurment
			break;
			
		case SYS_EXEC:
			f->eax = sys_exec( *(sys_call+1) );
			break;
			
		case SYS_WAIT:
			f->eax = sys_wait( *(sys_call+1) ); 
			break;
			
		case SYS_CREATE:
			f->eax = sys_create( *(sys_call+1),  *(sys_call+2) ); 
			break;
			
		case SYS_REMOVE:
			f->eax = sys_remove( *(sys_call+1) ); 
			break;
			
		case SYS_OPEN:
			f->eax = sys_open( *(sys_call+1) ); 
			break;
			
		case SYS_FILESIZE:
			f->eax = sys_filesize( *(sys_call+1) ); 
			break;
			
		case SYS_READ:
			f->eax = sys_read( *(sys_call+1), *(sys_call+2), *(sys_call+3) );
			break;			
			
		case SYS_WRITE:
			f->eax = sys_write( *(sys_call+1), *(sys_call+2), *(sys_call+3) ); 
			break;
			
		case SYS_SEEK:
			f->eax = sys_seek( *(sys_call+1), *(sys_call+1)  ); 
			break;
			
		case SYS_TELL:
			f->eax = sys_tell( *(sys_call+1) ); 
			break;
			
		case SYS_CLOSE:
			f->eax = sys_close( *(sys_call+1) ); 
			break;
	}
}

/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
  return (uaddr < PHYS_BASE
          && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

static bool
mem_access(const void *addr, const void *sp)
{
	//Check if user address is valid
	if( !verify_user( addr )
		|| !is_user_vaddr( addr )
		|| addr == NULL
		|| addr < sp
	)
	{
		thread_current()->status = THREAD_DYING;
		thread_exit();
	}
	return true;
}
 
/* Copies a byte from user address USRC to kernel address DST.
   USRC must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static inline bool
put_user (uint8_t *udst, uint8_t byte)
{
  int eax;
  asm ("movl $1f, %%eax; movb %b2, %0; 1:"
       : "=m" (*udst), "=&a" (eax) : "q" (byte));
  return eax != 0;
}
 
/* Copies SIZE bytes from user address USRC to kernel address
   DST.
   Call thread_exit() if any of the user accesses are invalid. */
static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;
 
  for (; size > 0; size--, dst++, usrc++) 
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
      thread_exit ();
}
 
/* Creates a copy of user string US in kernel memory
   and returns it as a page that must be freed with
   palloc_free_page().
   Truncates the string at PGSIZE bytes in size.
   Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
  char *ks;
  size_t length;
 
  ks = palloc_get_page (0);
  if (ks == NULL)
    thread_exit ();
 
  for (length = 0; length < PGSIZE; length++)
    {
      if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
        {
          palloc_free_page (ks);
          thread_exit (); 
        }
      if (ks[length] == '\0')
        return ks;
    }
  ks[PGSIZE - 1] = '\0';
  return ks;
}
 
/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
static int
sys_exit (int exit_code) 
{
  thread_current ()->wait_status->exit_code = exit_code;
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *ufile) 
{
	tid_t thread_id;
	char* kernalFile = copy_in_string( ufile );	
	
	lock_acquire( &fs_lock );
	thread_id = process_execute( kernalFile );
	palloc_free_page( kernalFile );
	lock_release( &fs_lock );
	
	return thread_id;
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
	return process_wait( child );
}
 
/* Create system call. */
static int
sys_create (const char *ufile, unsigned initial_size) 
{
  char *kfile = copy_in_string (ufile);
  
  lock_acquire (&fs_lock);
  bool result = filesys_create (kfile, initial_size) ;
  lock_release (&fs_lock);
  
  return result;
}
 
/* Remove system call. */
static int
sys_remove (const char *ufile) 
{
  char *kfile = copy_in_string (ufile);
  
  lock_acquire (&fs_lock);
  bool result = filesys_remove (kfile) ;
  lock_release (&fs_lock);
  
  return result;
}
 
/* A file descriptor, for binding a file handle to a file. */
struct file_descriptor
  {
    struct list_elem elem;      /* List element.  */
    struct file *file;          /* File. */
    int handle;                 /* File handle. */
  };
 
/* Open system call. */
static int
sys_open (const char *ufile) 
{
  char *kfile = copy_in_string (ufile);
  struct file_descriptor *fd;
  int handle = -1;
 
  fd = malloc (sizeof *fd);
  if (fd != NULL)
    {
      lock_acquire (&fs_lock);
      fd->file = filesys_open (kfile);
      if (fd->file != NULL)
        {
          struct thread *cur = thread_current ();
          handle = fd->handle = cur->next_handle++;
          list_push_front (&cur->fds, &fd->elem);
        }
      else 
        free (fd);
      lock_release (&fs_lock);
    }
  
  palloc_free_page (kfile);
  return handle;
}
 
/* Returns the file descriptor associated with the given handle.
   Terminates the process if HANDLE is not associated with an
   open file. */
static struct file_descriptor *
lookup_fd (int handle)
{
/* Add code to lookup file descriptor in the current thread's fds */
  thread_exit ();
}
 
/* Filesize system call. */
static int
sys_filesize (int handle) 
{
/* Add code */
  thread_exit ();
}
 
/* Read system call. */
static int
sys_read (int handle, void *udst_, unsigned size) 
{
/* Add code */
  thread_exit ();
}
 
/* Write system call. */
static int
sys_write (int handle, void *usrc_, unsigned size) 
{
  uint8_t *usrc = usrc_;
  struct file_descriptor *fd = NULL;
  int bytes_written = 0;

  /* Lookup up file descriptor. */
  if (handle != STDOUT_FILENO)
    fd = lookup_fd (handle);

  lock_acquire (&fs_lock);
  while (size > 0) 
    {
      /* How much bytes to write to this page? */
      size_t page_left = PGSIZE - pg_ofs (usrc);
      size_t write_amt = size < page_left ? size : page_left;
      off_t retval;

      /* Check that we can touch this user page. */
      if (!verify_user (usrc)) 
        {
          lock_release (&fs_lock);
          thread_exit ();
        }

      /* Do the write. */
      if (handle == STDOUT_FILENO)
        {
          putbuf (usrc, write_amt);
          retval = write_amt;
        }
      else
        retval = file_write (fd->file, usrc, write_amt);
      if (retval < 0) 
        {
          if (bytes_written == 0)
            bytes_written = -1;
          break;
        }
      bytes_written += retval;

      /* If it was a short write we're done. */
      if (retval != (off_t) write_amt)
        break;

      /* Advance. */
      usrc += retval;
      size -= retval;
    }
  lock_release (&fs_lock);
 
  return bytes_written;
}
 
/* Seek system call. */
static int
sys_seek (int handle, unsigned position) 
{
/* Add code */
  thread_exit ();
}
 
/* Tell system call. */
static int
sys_tell (int handle) 
{
/* Add code */
  thread_exit ();
}
 
/* Close system call. */
static int
sys_close (int handle) 
{
/* Add code */
  thread_exit ();
}
 
/* On thread exit, close all open files. */
void
syscall_exit (void) 
{
/* Add code */
  return;
}
