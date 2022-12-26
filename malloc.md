# Malloc exploit 

This document aims to introduce parts of the malloc implementation that may be useful for binary exploitation. The document is not going to give a self-contained introduction but it can be used as a cheat sheet. See the source code to find out the details.

Many heap attacks exploit the `ptmalloc` implementation in glibc. The attacks are strongly depend on the specific implementation so all exploitations don't work for a program.

We can check the source code at [elixir.bootlin.com](https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c). We use glibc-2.26 for demonstration. Use `objdump -T ./libc.so.6 | grep malloc` to find the version information.

## References

- https://sourceware.org/glibc/wiki/MallocInternals
- https://github.com/shellphish/how2heap
- https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
- https://sploitfun.wordpress.com/2015/06/26/linux-x86-exploit-development-tutorial-series/

## Memory Layout: malloc_chunk

```c
struct malloc_chunk {
  /* INTERNAL_SIZE_T is defined as size_t */
  INTERNAL_SIZE_T      mchunk_prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      mchunk_size;       /* Size in bytes, including overhead. */

  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;

  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

/**
An allocated chunk looks like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Free chunks are stored in circular doubly-linked lists, and look like this:

    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `head:' |             Size of chunk, in bytes                     |A|0|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Forward pointer to next chunk in list             |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Back pointer to previous chunk in list            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Unused space (may be 0 bytes long)                .
            .                                                               .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    `foot:' |             Size of chunk, in bytes                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|0|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The P (PREV_INUSE) bit: If that bit is *clear*, then the word before the current 
chunk size contains the previous chunk size.

The A (NON_MAIN_ARENA) bit: cleared for chunks on the initial, main_arena. 
Allocated Arena - the main arena uses the application's heap. Other arenas use 
mmap'd heaps.

The M (IS_MAPPED) bit: set for chunks allocated by mmap. If the M bit is set, 
the other bits are ignored (because mmapped chunks are neither in an arena, 
nor adjacent to a freed chunk).

**/
```

It is noteworthy that:

- After initialization, a special chunk `top` is forced to always exist.
- Chunks always begin on even word boundaries, so the mem is double-word aligned.
- Chunks in fastbins don't bother using the trailing size field. 

## Arena

The contiguous region of heap memory is called arena. The arena created by main thread is called `main_arena` and those created by threads are called `thead_arena`. Each arena structure has a mutex in it which is used to control access to that arena. 

The number of arenas is limited by the number of CPU cores:

```c
// https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c#L1789
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
// https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/arena.c#L901
static mstate
internal_function
arena_get2 (size_t size, mstate avoid_arena)
{
    mstate a;
    static size_t narenas_limit;
    narenas_limit = NARENAS_FROM_NCORES (n);
      
    size_t n = narenas;
    if (__glibc_unlikely (n <= narenas_limit - 1))
    {
      if (catomic_compare_and_exchange_bool_acq (&narenas, n + 1, n))
        goto repeat;
      a = _int_new_arena (size);
      if (__glibc_unlikely (a == NULL))
        catomic_decrement (&narenas);
    } 
    else
        a = reused_arena (avoid_arena);
}
```

A single thread arena can have multiple heaps (uncontiguous memory regions), while main arena only has one heap. When main arena runs out of space, sbrk’d heap segment is extended. Each heap (except the one in main arena) has its own header `heap_info`. Each arena also has its header `malloc_state`. Arena header contains information about bins, top chunk, last remainder chunk, etc. The main arena header is a global variable `main_area` in data segment but the thread arena header is a part of first heap segment in the thread arena.

Each thread has a thread-local variable that remembers which arena it last used. If that arena is in use when a thread needs to use it the thread will block to wait for the arena to become free. If the thread has never used an arena before then it may try to reuse an unused one, create a new one, or pick the next one on the global list.

## tcache

The Thread Local Cache (tcache) is a performance optimization in glibc. Each thread has a per-thread cache (called the tcache) containing a small collection of chunks which can be accessed without needing to lock an arena. These chunks are stored as an array of singly-linked lists, like fastbins, but with links pointing to the payload (user area) not the chunk header. Each bin contains one size chunk, so the array is indexed (indirectly) by chunk size. Unlike fastbins, the tcache is limited in how many chunks are allowed in each bin (tcache_count). If the tcache bin is empty for a given requested size, the next larger sized chunk is not used (could cause internal fragmentation), instead the fallback is to use the normal malloc routines i.e. locking the thread's arena and working from there.

```c
/* We overlay this structure on the user-data portion of a chunk when
   the chunk is stored in the per-thread cache.  */
typedef struct tcache_entry
{
  struct tcache_entry *next;
  /* This field exists to detect double frees.  */
  uintptr_t key;    // A random variable that is set when tcache is initilized. 
} tcache_entry;
```

## mmap

When user request size is more than 128 KB, the memory is allocated using mmap syscall.

## Bins

Freelist datastructures are referred as bins.

- All procedures maintain the invariant that no consolidated chunk physically borders another one, so each chunk in a list is known to be preceeded and followed by either inuse chunks or the ends of memory.
- Chunks in bins are kept in size order, with ties going to the approximately least recently used chunk.
- To simplify use in double-linked lists, each bin header acts as a malloc_chunk.

### Fastbins

An array of lists holding recently freed small chunks. Fastbins are **single-linked, uses LIFO**. Chunks in fastbins keep their inuse bit set, so they cannot be consolidated with other free chunks. `malloc_consolidate` releases all chunks in fastbins and consolidates them with other free chunks.

```c
#define MAX_FAST_SIZE     (80 * SIZE_SZ / 4)  // 80/160 bytes for 32/64-bit
#define NFASTBINS  (fastbin_index (request2size (MAX_FAST_SIZE)) + 1) // ~10

// The i-th bin has chunks of size ((i+2) * 8/16)
#define fastbin_index(sz) \
  ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

typedef struct malloc_chunk *mfastbinptr;

struct malloc_state
{
    mfastbinptr fastbinsY[NFASTBINS];
}
```

Exploitations: 

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc

### Unsorted bin

Unsorted bin contains a circular double linked list of recently free chunks. This approach gives a second chance to reuse the recently freed chunks of any sizes.

```c
#define NBINS             128

struct malloc_state
{
    mchunkptr bins[NBINS * 2 - 2]; 
    // Bin 0 does not exist.
    // Bin 1           – Unsorted bin
    // Bin 2 to Bin 63 – Small bin (# = 62)
    // Bin 64 to ..... – Large bin
}
```

### Small bin

Chunks of size less than 512 bytes is called as small chunk. 

```c
#define MALLOC_ALIGNMENT       (2 *SIZE_SZ < __alignof__ (long double)      \
                                ? __alignof__ (long double) : 2 *SIZE_SZ)
    
#define NSMALLBINS         64
#define SMALLBIN_WIDTH    MALLOC_ALIGNMENT
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)

// Bins for sizes < 512 bytes contain chunks of all the same size, spaced
// 8/16 bytes apart.
#define smallbin_index(sz) \
  ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4) : (((unsigned) (sz)) >> 3))\
   + SMALLBIN_CORRECTION)
```

### Large bin

Chunks of size greater than equal to 512 is called a large chunk.

```c
/**
Larger bins are approximately logarithmically spaced:

    64 bins of size       8
    32 bins of size      64
    16 bins of size     512
     8 bins of size    4096
     4 bins of size   32768
     2 bins of size  262144
     1 bin  of size what's left
**/
```
