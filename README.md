allocator.h: a file containing function prototypes for functionality in each of your allocators, and some helpful constants. You do not need to modify this file, but can use these constants automatically in your code.
segment.h, and segment.c: supporting files needed for programs to use your heap allocator, that provide the heap segment size and heap segment start. You do not need to modify these files.
debug_break.h: a provided file with a helpful function for debugging that allows you to call a function to simulate hitting a GDB breakpoint where that function is called. You do not need to modify this file.

Code Study: Test Harness
A heap allocator isn't an executable program, but rather a set of functions that can be called from programs. Therefore, to test a heap allocator, we need test programs that call those functions. Our provided test_harness.c program is a program that tests calling your heap allocator functions in various ways. It takes as input a test allocator script (a text file in a specified format) that it parses to know what requests to send the heap allocator. While executing the script, it attempts to verify that each request was correctly satisfied. It looks for various externally-visible problems (blocks that are unaligned/overlapping/outside segment, failure to preserve payload data, etc). When you compile using make, it will create 3 different compiled versions of this program to test with, one using each type of heap allocator: test_bump, test_implicit and test_explicit. You can specify one or more script files as command line arguments to the test harness and it will run and evaluate on each of them. You can also use something called filename globbing to specify multiple test files to run with the test harness all at once. For example, you can specify samples/example*.script (note the asterisk) as the filename to run all provided test files in the samples folder starting with example as its name.

Allocator Scripts
An allocator script is a file that contains a sequence of requests in a compact text-based format. The three request types are a (allocate) r(reallocate) and f (free). Each request has an id-number that can be referred to in a subsequent realloc or free.

a id-number size
r id-number size
f id-number
A script file containing:

a 0 24
a 1 100
f 0
r 1 300
f 1
is converted by the test harness into these calls to your allocator:

void *ptr0 = mymalloc(24);
void *ptr1 = mymalloc(100);
myfree(ptr0);
ptr1 = myrealloc(ptr1, 300);
myfree(ptr1);

General Requirements
The following requirements apply to both allocators:

The interface should match the standard libc allocator. Carefully read the malloc man page for what constitutes a well-formed request and the required handling to which your allocator must conform. Note there are a few oddballs (malloc(0) and the like) to take into account. Ignore esoteric details from the NOTES section of the man page.
There is no requirement on how to handle improper requests. If a client reallocs a stack address, frees an already freed pointer, overruns past the end of an allocated block, or other such incorrect usage, your response can be anything, including crashing or corrupting the heap. We will not test on these cases.
An allocated block must be at least as large as requested, but it is not required to be exactly that size. The maximum size request your design must accommodate is specified as a constant in allocator.h. If asked for a block larger than the max size, your allocater can return NULL, just as it would for any request that cannot be serviced. You should not assume the value of this constant beyond that it will not be larger than the max value of a size_t.
Every allocated block must be aligned to an address that is a multiple of the ALIGNMENT constant, also in allocator.h. You may assume that this value is 8, and it is fine for your code to work only with an alignment of 8. However, you should still use the constant instead of hardcoding the value. This alignment applies to payloads that are returned to the client, not to internal heap data such as headers. It's your choice whether small requests are rounded up to some minimum size.
myinit's job is to properly initialize the allocator's state. It should return true if the initialization was successful, or false if the parameters are invalid / the allocator is unable to initialize. For the parameters passed in, you may assume that the heap starting address is a non-NULL value aligned to the ALIGNMENT constant, and that the heap size is a multiple of ALIGNMENT. You should not assume anything else about the parameters, such as that the heap size is large enough for the heap allocator to use.
Your allocator cannot invoke any memory-management functions. By "memory-management" we specifically mean those operations that allocate or deallocate memory, so no calls to malloc, realloc, free, calloc, sbrk, brk, mmap, or related variants. The use of other library functions is fine, e.g. memmove and memset can be used as they do not allocate or deallocate memory.
You will need to use a small number of global variables / data, but limited to at most 500 bytes in total. This restriction dictates the bulk of the heap housekeeping must be stored within the heap segment itself.
You must have an implemented validate_heap function that thoroughly checks the heap data structures and state and returns whether or not any problems were found (see next section).
You must have an implemented dump_heap function that prints out a representation of what the heap currently looks like (see next section).
validate_heap
The test harness is written to look for external issues/inconsistencies in an allocator, but it cannot peer inside the allocator to check its internal state to make sure it's correct. For instance, the test harness may alert you to the allocator returning NULL, but it may not be able to notice that this was due to the doubly-linked free list getting corrupted a few requests back. To help identify these internal issues, you should implement the validate_heap helper function; it is a function that can check for issues with internal heap allocator state. The test harness calls this function periodically, so if something goes wrong you can be alerted at the exact moment it happens. When implementing validate_heap, don't repeat the checks the test harness already does for you, but instead augment them by reviewing the internal consistency of the heap. You should write your implementation of validate_heap as you implement each allocator feature - you should not just go back and add it at the end! As your heap data structures become more complex, validate_heap should become more sophisticated to match them.

To provide some examples, your validate_heap might walk the entire heap and verify such things as:

Does the housekeeping information (location, size, free status) for each block appear reasonable? Is all of the heap segment accounted for?
For your explicit allocator, is every block in the free list marked as free? Is every block marked free listed on the free list? Is each listed only once?
For your explicit allocator, have adjacent free blocks been coalesced according to your policy?
Are redundancies in the data structures consistent, e.g. does the count of free blocks match the length of the free list, or the total bytes in-use match the sum of in-use block sizes?
A strong implementation looks for potential issues and reports only on failures. You should not, for example, dump a printout of the entire heap to then manually look through for potential issues. That is something that dump_heap (see next section) can do.

Tip 1: We provide a breakpoint() function (see debug_break.h) that will force a stop in the debugger. You may want to call this function from your validate_heap when it detects something is incorrect.

Tip 2: The more comprehensive and thorough checks done by validate_heap, the more useful it will be to you. A good validate_heap will also be slow -- do not be at all concerned about this, this function is a development/debugging aid, there is no desire for it to be efficient and it will not be invoked during any performance measurements.

1) Implement An Implicit Free List Allocator
Now you're ready to implement your first heap allocator design. The specific features that your implicit free list allocator must support are:

Headers that track block information (size, status in-use or free) - you must use the header design mentioned in lecture that is 8 bytes big, using any of the least significant 3 bits to store the status
Free blocks that are recycled and reused for subsequent malloc requests if possible
A malloc implementation that searches the heap for free blocks via an implicit list (i.e. traverses block-by-block).
Your implicit free list allocator is not required to:

implement any coalescing of freed blocks (the explicit allocator will do this)
support in-place realloc (the explicit allocator will do this); for realloc requests you may satisfy the request by moving the memory to another location
use a footer, as done in the textbook
resize the heap when out of memory. If your allocator runs out of memory, it should indicate that to the client.
This allocator won't be that zippy of a performer but recycling freed nodes should certainly improve utilization over the bump allocator.

The bulleted list above indicates the minimum specification that you are required to implement. Further details are intentionally unspecified as we leave these design decisions up to you; this means it is your choice whether you search using first-fit/next-fit/best-fit, and so on. 

Heap Allocator Requirements
A heap allocator cannot assume anything about the order of allocation and free requests, or even that every allocation request is accompanied by a matching free request.

A heap allocator marks memory regions as allocated or available. It must remember which is which to properly provide memory to clients.

A heap allocator may have options for which memory to use to fulfill an allocation request. It must decide this based on a variety of factors.

A heap allocator must respond immediately to allocation requests and should not e.g. prioritize or reorder certain requests to improve performance.

Return addresses that are 8-byte-aligned (must be multiples of 8).

Implicit Free List Allocator
Key idea: in order to reuse blocks, we need a way to track which blocks are
allocated and which ones are free.
• We could store this information in a separate global data structure, but this is,
in general, inefficient and requires substantial overhead.
• Instead: let’s allocate extra space before each block for a header storing its
payload size and whether it's free or in use.
• When we allocate a block, we look through all blocks to find a free one and
update its header to reflect its allocation size and status.
• When we free a block, we update its header to be clear it's now free.
• The header should be 8 bytes (or larger).
• By storing header information, we’re implicitly maintaining a list of free blocks.

Representing Headers
How can we store both a size and a status (free versus allocated) in 8 bytes?
int for size, int for status? no! malloc/realloc use size_t for sizes!
Key idea: block sizes will always be multiples of 8.
• Least-significant 3 bits aren’t really needed to represent block size if they’re assumed to always be zeroes!
• Solution: use one of the 3 least-significant bits to store free/allocated status

How can we choose a free block to use for an allocation request?
• First fit: search the list from beginning each time and choose first free block that fits.
• Next fit: instead of starting at the beginning, continue where previous search left off.
• Best fit: examine every free block and choose the one with the smallest size that fits.

Should we store the block size as
(A) payload size, or
(B) header + payload size?
Up to you! Your decision affects
how you traverse the list (but be
careful of off-by-one errors)

Splitting Policy
So far, we have seen that a
reasonable allocation request splits
a free block into an allocated block
and a free block with remaining
space. What about edge cases?
Up to you!
A. Throw into allocation for e as extra padding?
B. Make a "zero-byte free block"? External fragmentation – unused free blocks

Questions we considered:
1. How do we keep track of free blocks? We use headers!
2. How do we choose an appropriate free block in which to place a newly
allocated block? We iterate through all blocks!
3. After we place a newly allocated block in some free block, what do we do
with the rest of the free block? We try to make the most of it!
4. What do we do with a block that has just been freed? We update its header!

Final Assignment: Implicit Allocator
Must have headers that track block information (size, status in-use or free) –
you must use the 8 byte header size, storing the status using the free bits

Must allow, when possible, free blocks to be recycled and reused for
subsequent malloc requests
• Must have a malloc implementation that searches the heap for free blocks via
its implicit list (i.e., traverses block-by-block).
• Does not need to coalesce free blocks.
• Does not need to support in-place realloc.

implicit.c 
#include "./allocator.h"
#include "./debug_break.h"

bool myinit(void *heap_start, size_t heap_size) {
    /* TODO(you!): remove the line below and implement this!
     * This must be called by a client before making any allocation
     * requests.  The function returns true if initialization was
     * successful, or false otherwise. The myinit function can be
     * called to reset the heap to an empty state. When running
     * against a set of of test scripts, our test harness calls
     * myinit before starting each new script.
     */
    return false;
}

void *mymalloc(size_t requested_size) {
    // TODO(you!): remove the line below and implement this!
    return NULL;
}

void myfree(void *ptr) {
    // TODO(you!): implement this!
}

void *myrealloc(void *old_ptr, size_t new_size) {
    // TODO(you!): remove the line below and implement this!
    return NULL;
}

bool validate_heap() {
    /* TODO(you!): remove the line below and implement this to
     * check your internal structures!
     * Return true if all is ok, or false otherwise.
     * This function is called periodically by the test
     * harness to check the state of the heap allocator.
     * You can also use the breakpoint() function to stop
     * in the debugger - e.g. if (something_is_wrong) breakpoint();
     */
    return false;
}

/* Function: dump_heap
 * -------------------
 * This function prints out the the block contents of the heap.  It is not
 * called anywhere, but is a useful helper function to call from gdb when
 * tracing through programs.  It prints out the total range of the heap, and
 * information about each block within it.
 */
void dump_heap() {
    // TODO(you!): Write this function to help debug your heap.
}

allocator.h 
/* File: allocator.h
 * -----------------
 * Interface file for the custom heap allocator.
 */
#ifndef _ALLOCATOR_H
#define _ALLOCATOR_H

#include <stdbool.h> // for bool
#include <stddef.h>  // for size_t

// Alignment requirement for all blocks
#define ALIGNMENT 8

// maximum size of block that must be accommodated
#define MAX_REQUEST_SIZE (1 << 30)



/* Function: myinit
 * ----------------
 * This must be called by a client before making any allocation
 * requests.  The function returns true if initialization was successful,
 * or false otherwise. The myinit function can be called to reset
 * the heap to an empty state. When running against a set of
 * of test scripts, our test harness calls myinit before starting
 * each new script.
 */
bool myinit(void *heap_start, size_t heap_size);

/* Function: mymalloc
 * ------------------
 * Custom version of malloc.
 */
void *mymalloc(size_t requested_size);


/* Function: myrealloc
 * -------------------
 * Custom version of realloc.
 */
void *myrealloc(void *old_ptr, size_t new_size);


/* Function: myfree
 * ----------------
 * Custom version of free.
 */
void myfree(void *ptr);


/* Function: validate_heap
 * -----------------------
 * This is the hook for your heap consistency checker. Returns true
 * if all is well, or false on any problem.  This function is 
 * called periodically by the test harness to check the state of 
 * the heap allocator.
 */
bool validate_heap();

#endif

debug_break.h 
/* File: debug_break.h
 * -------------------
 * If running under the debugger, a call to breakpoint() will
 * behave as though execution hit a gdb breakpoint. If not 
 * running under debugger, breakpoint() is a no-op. Call this
 * function in your validate_heap() to break when an error is detected.
 * 
 *  Written by jzelenski, updated Spring 2018
 */

#ifndef DEBUG_BREAK_H
#define DEBUG_BREAK_H

#include <signal.h>

void dummy(int signum) {
    // only called if debugger hasn't installed own handler (ignore)
}

#define breakpoint()            \
do {                            \
        signal(SIGTRAP, dummy); \
        __asm__("int3");        \
} while(0)


#endif

segment.h
/* File: segment.h
 * ---------------
 * An interface to the OS low-level allocator. Used to reserve a large
 * segment of memory to be used by a custom heap allocator.
 */

#ifndef _SEGMENT_H_
#define _SEGMENT_H_
#include <stddef.h> // for size_t


/* Function: init_heap_segment
 * ---------------------------
 * This function is called to initialize the heap segment and allocate the
 * segment to hold total_size bytes. If init_heap_segment 
 * is called again, it discards the current heap segment and re-configures. 
 * The function returns the base address of the heap segment if successful 
 * or NULL if the initialization failed. The base address of the heap segment 
 * is always aligned to start on a page boundary (page size is 4096 bytes).
 */
void *init_heap_segment(size_t total_size);



/* Functions: heap_segment_start, heap_segment_size
 * ------------------------------------------------
 * heap_segment_start returns the base address of the current heap segment
 * (NULL if no segment has been initialized).
 * heap_segment_size returns the current segment size in bytes.
 */
void *heap_segment_start();
size_t heap_segment_size();


#endif

segment.c
/* File: segment.c
 * ---------------
 * Handles low-level storage underneath the heap allocator. It reserves
 * the large memory segment using the OS-level mmap facility.
 *
 * Written by jzelenski, updated Spring 2018
 */

#include "segment.h"
#include <assert.h>
#include <sys/mman.h>

/* Place segment at fixed address, as default addresses are quite high
 * and easily mistaken for stack addresses.
 */
#define HEAP_START_HINT (void *)0x107000000L

// Static means these variables are only visible within this file
static void *segment_start = NULL;
static size_t segment_size = 0;

void *heap_segment_start() {
    return segment_start;
}

size_t heap_segment_size() {
    return segment_size;
}

void *init_heap_segment(size_t total_size) {
    // Discard any previous segment via munmap
    if (segment_start != NULL) {
        if (munmap(segment_start, total_size) == -1) return NULL;
        segment_start = NULL;
        segment_size = 0;
    }
    
    // Re-initialize by reserving entire segment with mmap
    segment_start = mmap(HEAP_START_HINT, total_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    assert(segment_start != MAP_FAILED);
    segment_size = total_size;
    return segment_start;
}

ChatGPT
It looks like you've uploaded several screenshots related to heap memory allocation, specifically regarding the implementation and visualization of different strategies for memory management such as implicit first-fit, best-fit, and coalescing strategies in a heap allocator system.

If you need help understanding these concepts, analyzing the code, or have specific questions about the implementation or the images you've uploaded, feel free to ask! How can I assist you with these images?

User
using shared slides and information above , can you give me 
complete code and give comments in the code

And also consider 
test_harness.c 
/*
 * Files: test_harness.c
 * ---------------------
 * Reads and interprets text-based script files containing a sequence of
 * allocator requests. Runs the allocator on a script and validates
 * results for correctness.
 *
 * When you compile using `make`, it will create 3 different
 * compiled versions of this program, one using each type of
 * heap allocator.
 *
 * Written by jzelenski, updated by Nick Troccoli Winter 18-19
 */

#include <error.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "allocator.h"
#include "segment.h"


/* TYPE DECLARATIONS */


// enum and struct for a single allocator request
enum request_type {
    ALLOC = 1,
    FREE,
    REALLOC
};
typedef struct {
    enum request_type op;   // type of request
    int id;                 // id for free() to use later
    size_t size;            // num bytes for alloc/realloc request
    int lineno;             // which line in file
} request_t;

// struct for facts about a single malloc'ed block
typedef struct {
    void *ptr;
    size_t size;
} block_t;

// struct for info for one script file
typedef struct {
    char name[128];     // short name of script
    request_t *ops;     // array of requests read from script
    int num_ops;        // number of requests
    int num_ids;        // number of distinct block ids
    block_t *blocks;    // array of memory blocks malloc returns when executing
    size_t peak_size;   // total payload bytes at peak in-use
} script_t;

// Amount by which we resize ops when needed when reading in from file
const int OPS_RESIZE_AMOUNT = 500;

const int MAX_SCRIPT_LINE_LEN = 1024;

const long HEAP_SIZE = 1L << 32;


/* FUNCTION PROTOTYPES */


static int test_scripts(char *script_names[], int num_script_names, bool quiet);
static bool read_line(char buffer[], size_t buffer_size, FILE *fp, int *pnread);
static script_t parse_script(const char *filename);
static request_t parse_script_line(char *buffer, int lineno, char *script_name);
static size_t eval_correctness(script_t *script, bool quiet, bool *success);
static void *eval_malloc(int req, size_t requested_size, script_t *script, bool *failptr);
static void *eval_realloc(int req, size_t requested_size, script_t *script, bool *failptr);
static bool verify_block(void *ptr, size_t size, script_t *script, int lineno);
static bool verify_payload(void *ptr, size_t size, int id, script_t *script, int lineno, char *op);
static void allocator_error(script_t *script, int lineno, char* format, ...);


/* CORRECTNESS EVALUATION IMPLEMENTATION */


/* Function: main
 * --------------
 * The main function parses command-line arguments (currently only -q for quiet)
 * and any script files that follow and runs the heap allocator on the specified
 * script files.  It outputs statistics about the run of each script, such as
 * the number of successful runs, number of failures, and average utilization.
 */
int main(int argc, char *argv[]) {
    // Parse command line arguments
    char c;
    bool quiet = false;
    while ((c = getopt(argc, argv, "q")) != EOF) {
        if (c == 'q') {
            quiet = true;
        }
    }
    if (optind >= argc) {
        error(1, 0, "Missing argument. Please supply one or more script files.");
    }

    // disable stdout buffering, all printfs display to terminal immediately
    setvbuf(stdout, NULL, _IONBF, 0);
    
    return test_scripts(argv + optind, argc - optind, quiet);
}

/* Function: test_scripts
 * ----------------------
 * Runs the scripts with names in the specified array, with more or less output
 * depending on the value of `quiet`.  Returns the number of failures during all
 * the tests.
 */
static int test_scripts(char *script_names[], int num_script_names, bool quiet) {
    int nsuccesses = 0;
    int nfailures = 0;

    // Utilization summed across all successful script runs (each is % out of 100)
    int total_util = 0;

    for (int i = 0; i < num_script_names; i++) {
        script_t script = parse_script(script_names[i]);

        // Evaluate this script and record the results
        printf("\nEvaluating allocator on %s...", script.name);
        bool success;
        size_t used_segment = eval_correctness(&script, quiet, &success);
        if (success) {
            printf("successfully serviced %d requests. (payload/segment = %zu/%zu)", 
                script.num_ops, script.peak_size, used_segment);
            if (used_segment > 0) {
                total_util += (100 * script.peak_size) / used_segment;
            }
            nsuccesses++;
        } else {
            nfailures++;
        }

        free(script.ops);
        free(script.blocks);
    }

    if (nsuccesses) {
        printf("\nUtilization averaged %d%%\n", total_util / nsuccesses);
    }
    return nfailures;
}

/* Function: eval_correctness
 * --------------------------
 * Check the allocator for correctness on given script. Interprets the
 * script operation-by-operation and reports if it detects any "obvious"
 * errors (returning blocks outside the heap, unaligned, 
 * overlapping blocks, etc.)
 */
static size_t eval_correctness(script_t *script, bool quiet, bool *success) {
    *success = false;
    
    init_heap_segment(HEAP_SIZE);
    if (!myinit(heap_segment_start(), heap_segment_size())) {
        allocator_error(script, 0, "myinit() returned false");
        return -1;
    }

    if (!quiet && !validate_heap()) {
        allocator_error(script, 0, "validate_heap() after myinit returned false");
        return -1;
    }

    // Track the topmost address used by the heap for utilization purposes
    void *heap_end = heap_segment_start();

    // Track the current amount of memory allocated on the heap
    size_t cur_size = 0;

    // Send each request to the heap allocator and check the resulting behavior
    for (int req = 0; req < script->num_ops; req++) {
        int id = script->ops[req].id;
        size_t requested_size = script->ops[req].size;

        if (script->ops[req].op == ALLOC) {
            bool fail = false;
            void *p = eval_malloc(req, requested_size, script, &fail);
            if (fail) {
                return -1;
            }

            cur_size += requested_size;
            if ((char *)p + requested_size > (char *)heap_end) {
                heap_end = (char *)p + requested_size;
            }
        } else if (script->ops[req].op == REALLOC) {
            size_t old_size = script->blocks[id].size;
            bool fail = false;
            void *p = eval_realloc(req, requested_size, script, &fail);
            if (fail) {
                return -1;
            }

            cur_size += (requested_size - old_size);
            if ((char *)p + requested_size > (char *)heap_end) {
                heap_end = (char *)p + requested_size;
            }
        } else if (script->ops[req].op == FREE) {
            size_t old_size = script->blocks[id].size;
            void *p = script->blocks[id].ptr;

            // verify payload intact before free
            if (!verify_payload(p, old_size, id, script, 
                script->ops[req].lineno, "freeing")) {
                return -1;
            }
            script->blocks[id] = (block_t){.ptr = NULL, .size = 0};
            myfree(p);
            cur_size -= old_size;
        }

        // check heap consistency after each request and stop if any error
        if (!quiet && !validate_heap()) {
            allocator_error(script, script->ops[req].lineno, 
                "validate_heap() returned false, called in-between requests");
            return -1;
        }

        if (cur_size > script->peak_size) {
            script->peak_size = cur_size;
        }
    }

    // verify payload is still intact for any block still allocated
    for (int id = 0; id < script->num_ids; id++) {
        if (!verify_payload(script->blocks[id].ptr, script->blocks[id].size, 
            id, script, -1, "at exit")) {
            return -1;
        }
    }

    *success = true;
    return (char *)heap_end - (char *)heap_segment_start();
}

/* Function: eval_malloc
 * ---------------------
 * Performs a test of a call to mymalloc of the given size.  The req number
 * specifies the operation's index within the script.  This function verifies
 * the entire malloc'ed block and fills in the payload with a low-order byte
 * of the request id.  If the request fails, the boolean pointed to by
 * failptr is set to true - otherwise, it is set to false.  If it is set to
 * true this function returns NULL; otherwise, it returns what was returned
 * by mymalloc.
 */
static void *eval_malloc(int req, size_t requested_size, script_t *script, 
    bool *failptr) {

    int id = script->ops[req].id;

    void *p;
    if ((p = mymalloc(requested_size)) == NULL && requested_size != 0) {
        allocator_error(script, script->ops[req].lineno, 
            "heap exhausted, malloc returned NULL");
        *failptr = true;
        return NULL;
    }

    /* Test new block for correctness: must be properly aligned
     * and must not overlap any currently allocated block.
     */
    if (!verify_block(p, requested_size, script, script->ops[req].lineno)) {
        *failptr = true;
        return NULL;
    }

    /* Fill new block with the low-order byte of new id
     * can be used later to verify data copied when realloc'ing.
     */
    memset(p, id & 0xFF, requested_size);
    script->blocks[id] = (block_t){.ptr = p, .size = requested_size};
    *failptr = false;
    return p;
}

/* Function: eval_realloc
 * ---------------------
 * Performs a test of a call to myrealloc of the given size.  The req number
 * specifies the operation's index within the script.  This function verifies
 * the entire realloc'ed block and fills in the payload with a low-order byte
 * of the request id.  If the request fails, the boolean pointed to by
 * failptr is set to true - otherwise, it is set to false.  If it is set to true
 * this function returns NULL; otherwise, it returns what was returned by
 * myrealloc.
 */
static void *eval_realloc(int req, size_t requested_size, script_t *script, 
    bool *failptr) {

    int id = script->ops[req].id;
    size_t old_size = script->blocks[id].size;

    void *oldp = script->blocks[id].ptr;
    if (!verify_payload(oldp, old_size, id, script, 
        script->ops[req].lineno, "pre-realloc-ing")) {
        *failptr = true;
        return NULL;
    }

    void *newp;
    if ((newp = myrealloc(oldp, requested_size)) == NULL && requested_size != 0) {
        allocator_error(script, script->ops[req].lineno, 
            "heap exhausted, realloc returned NULL");
        *failptr = true;
        return NULL;
    }

    script->blocks[id].size = 0;
    if (!verify_block(newp, requested_size, script, script->ops[req].lineno)) {
        *failptr = true;
        return NULL;
    }

    // Verify new block contains the data from the old block
    if (!verify_payload(newp, (old_size < requested_size ? old_size : requested_size), 
        id, script, script->ops[req].lineno, "post-realloc-ing (preserving data)")) {
        *failptr = true;
        return NULL;
    }

    // Fill new block with the low-order byte of new id
    memset(newp, id & 0xFF, requested_size);
    script->blocks[id] = (block_t){.ptr = newp, .size = requested_size};

    *failptr = false;
    return newp;
}


/* Function: verify_block
 * ----------------------
 * Does some checks on the block returned by allocator to try to
 * verify correctness.  If any problem shows up, reports an allocator error
 * with details and line from script file. The checks it performs are:
 *  -- verify block address is correctly aligned
 *  -- verify block address is within heap segment
 *  -- verify block address + size doesn't overlap any existing allocated block
 */
static bool verify_block(void *ptr, size_t size, script_t *script, int lineno) {
    // address must be ALIGNMENT-byte aligned
    if (((uintptr_t)ptr) % ALIGNMENT != 0) {
        allocator_error(script, lineno, "New block (%p) not aligned to %d bytes",
                        ptr, ALIGNMENT);
        return false;
    }

    if (ptr == NULL && size == 0) {
        return true;
    }

    // block must lie within the extent of the heap
    void *end = (char *)ptr + size;
    void *heap_end = (char *)heap_segment_start() + heap_segment_size();
    if (ptr < heap_segment_start() || end > heap_end) {
        allocator_error(script, lineno, "New block (%p:%p) not within heap segment (%p:%p)",
                        ptr, end, heap_segment_start(), heap_end);
        return false;
    }

    // block must not overlap any other blocks
    for (int i = 0; i < script->num_ids; i++) {
        if (script->blocks[i].ptr == NULL || script->blocks[i].size == 0) {
            continue;
        }

        void *other_start = script->blocks[i].ptr;
        void *other_end = (char *)other_start + script->blocks[i].size;
        if ((ptr >= other_start && ptr < other_end) || (end > other_start && end < other_end) ||
            (ptr < other_start && end >= other_end)) {
            allocator_error(script, lineno, "New block (%p:%p) overlaps existing block (%p:%p)",
                            ptr, end, other_start, other_end);
            return false;
        }
    }

    return true;
}

/* Function: verify_payload
 * ------------------------
 * When a block is allocated, the payload is filled with a simple repeating
 * pattern based on its id.  Check the payload to verify those contents are
 * still intact, otherwise raise allocator error.
 */
static bool verify_payload(void *ptr, size_t size, int id, script_t *script, 
    int lineno, char *op) {

    for (size_t i = 0; i < size; i++) {
        if (*((unsigned char *)ptr + i) != (id & 0xFF)) {
            allocator_error(script, lineno, 
                "invalid payload data detected when %s address %p", op, ptr);
            return false;
        }
    }
    return true;
}

/* Function: allocator_error
 * ------------------------
 * Report an error while running an allocator script.  Prints out the script
 * name and line number where the error occured, and the specified format
 * string, including any additional arguments as part of that format string.
 */
static void allocator_error(script_t *script, int lineno, char* format, ...) {
    va_list args;
    fprintf(stdout, "\nALLOCATOR FAILURE [%s, line %d]: ", 
        script->name, lineno);
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    fprintf(stdout,"\n");
}


/* SCRIPT PARSING IMPLEMENTATION */


/* Fuction: parse_script
 * ---------------------
 * This function parses the script file at the specified path, and returns an
 * object with info about it.  It expects one request per line, and adds each
 * request's information to the ops array within the script.  This function
 * throws an error if the file can't be opened, if a line is malformed, or if
 * the file is too long to store each request on the heap.
 */
static script_t parse_script(const char *path) {
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        error(1, 0, "Could not open script file \"%s\".", path);
    }

    // Initialize a script object to store the information about this script
    script_t script = { .ops = NULL, .blocks = NULL, .num_ops = 0, .peak_size = 0};
    const char *basename = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
    strncpy(script.name, basename, sizeof(script.name) - 1);
    script.name[sizeof(script.name) - 1] = '\0';

    int lineno = 0;
    int nallocated = 0;
    int maxid = 0;
    char buffer[MAX_SCRIPT_LINE_LEN];

    for (int i = 0; read_line(buffer, sizeof(buffer), fp, &lineno); i++) {

        // Resize script->ops if we need more space for lines
        if (i == nallocated) {
            nallocated += OPS_RESIZE_AMOUNT;
            void *new_memory = realloc(script.ops, 
                nallocated * sizeof(request_t));
            if (!new_memory) {
                free(script.ops);
                error(1, 0, "Libc heap exhausted. Cannot continue.");
            }
            script.ops = new_memory;
        }

        script.ops[i] = parse_script_line(buffer, lineno, script.name);

        if (script.ops[i].id > maxid) {
            maxid = script.ops[i].id;
        }

        script.num_ops = i + 1;
    }

    fclose(fp);
    script.num_ids = maxid + 1;

    script.blocks = calloc(script.num_ids, sizeof(block_t));
    if (!script.blocks) {
        error(1, 0, "Libc heap exhausted. Cannot continue.");
    }

    return script;
}

/* Function: read_line
 * --------------------
 * This function reads one line from the specified file and stores at most
 * buffer_size characters from it in buffer, removing any trailing newline.
 * It skips lines that are all-whitespace or that contain comments (begin with
 * # as first non-whitespace character).  When reading a line, it increments the
 * counter pointed to by `pnread` once for each line read/skipped. This function
 * returns true if did read a valid line eventually, or false otherwise.
 */
static bool read_line(char buffer[], size_t buffer_size, FILE *fp, 
    int *pnread) {

    while (true) {
        if (fgets(buffer, buffer_size, fp) == NULL) {
            return false;
        }

        (*pnread)++;

        // remove any trailing newline
        if (buffer[strlen(buffer)-1] == '\n') {
            buffer[strlen(buffer)-1] ='\0'; 
        }

        /* Stop only if this line is not a comment line (comment lines start
         * with # as first non-whitespace character)
         */
        char ch;
        if (sscanf(buffer, " %c", &ch) == 1 && ch != '#') {
            return true;
        }
    }
}

/* Function: parse_script_line
 * ---------------------------
 * This function parses the provided line from the script and returns info
 * about it as a request_t object filled in with the type of the request,
 * the size, the ID, and the line number.  If the line is malformed, this
 * function throws an error.
 */
static request_t parse_script_line(char *buffer, int lineno, 
    char *script_name) {

    request_t request = { .lineno = lineno, .op = 0, .size = 0};

    char request_char;
    int nscanned = sscanf(buffer, " %c %d %zu", &request_char, 
        &request.id, &request.size);
    if (request_char == 'a' && nscanned == 3) {
        request.op = ALLOC;
    } else if (request_char == 'r' && nscanned == 3) {
        request.op = REALLOC;
    } else if (request_char == 'f' && nscanned == 2) {
        request.op = FREE;
    }

    if (!request.op || request.id < 0 || request.size > MAX_REQUEST_SIZE) {
        error(1, 0, "Line %d of script file '%s' is malformed.", 
            lineno, script_name);
    }

    return request;
}

complete the implicit.c program as required above information 
