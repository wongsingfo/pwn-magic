# Malloc exploit 

This document aims to introduce parts of the malloc implementation that may be useful for binary exploitation. The document is not going to give a self-contained introduction but it can be used as a cheat sheet. See the source code to find out the details.

Many heap attacks exploit the `ptmalloc` implementation in glibc. The attacks are strongly depend on the specific implementation so all exploitations don't work for a program.

We can check the source code at [elixir.bootlin.com](https://elixir.bootlin.com/glibc/glibc-2.26/source/malloc/malloc.c). We use glibc-2.26 for demonstration. Use `objdump -T ./libc.so.6 | grep malloc` to find the version information.

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

The M (IS_MAPPED) bit: set for chunks allocated by mmap. If the M bit is set, 
the other bits are ignored (because mmapped chunks are neither in an arena, 
nor adjacent to a freed chunk).

**/
```

It is noteworthy that:

- After initialization, a special chunk `top' is forced to always exist.
- Chunks always begin on even word boundaries, so the mem is double-word aligned.
- Chunks in fastbins don't bother using the trailing size field. 

## Bins

- All procedures maintain the invariant that no consolidated chunk physically borders another one, so each chunk in a list is known to be preceeded and followed by either inuse chunks or the ends of memory.
- Chunks in bins are kept in size order, with ties going to the approximately least recently used chunk.
- To simplify use in double-linked lists, each bin header acts as a malloc_chunk.

###  fastbins

An array of lists holding recently freed small chunks. Fastbins are single-linked, uses LIFO. Chunks in fastbins keep their inuse bit set, so they cannot be consolidated with other free chunks. malloc_consolidate releases all chunks in fastbins and consolidates them with other free chunks.

Exploitations: 

- Fastbin Double Free
- House of Spirit
- Alloc to Stack
- Arbitrary Alloc
