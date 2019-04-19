astro
=====

This is an x86-64 simulator designed to autograde C code safely and less
bafflingly. Students should focus on learning C, not making sense of
autograder output.

Dependencies:

 - [Unicorn][1] for x86-64 simulation
 - [elfutils][2] for libelf, used to load the student [ELF][3] into the
   simulator, and libdw, used to parse [DWARF][5] debug symbols in the
   student ELF (for backtraces)

To try out the sample assignment, first build the astro library. This
statically links Unicorn and elfutils together with astro simulator code
to produce `libastro.o`, which you can distribute with a homework (~4
MiB isn't bad in 2019):

    $ make

Now, to try the example:

    $ cd example
    $ make
    $ ./tester

Why?
----

For reference, the Old Way of C autograding works as follows:

 1. Autograder starts up on baremetal
 2. Autograder jumps into student code
 3. Student code jumps back into autograder code
 4. Autograder asserts that student code worked properly
 5. For next test, goto 2

(For checking for memory leaks, repeat the whole process inside [valgrind][4].)

### Problem: Student Can Jump Wherever

When the autograder and student code share an address space, to pass
tests, a student can jump back into the grader past any assertions:
<https://austinjadams.com/blog/acing-a-c-homework/>. With astro, only
the student code runs in the simulator.

### Problem: Student Can Trash Autograder Memory

Imagine you're a freshman and writing C code for the first time. Just to
be safe, you `free()` the same pointer three consecutive times. When you
run the autograder against your code, you see only this message:

    ../../src/check_pack.c:121: Bad message type arg 1937074548

Student code should not be able to corrupt autograder memory; the
results are too confusing. In astro, student code has no access to
autograder memory.

### Problem: Student Can Run Arbitrary Syscalls

This grants too much power to break the autograder and possibly connect
to the network to upload the autograder source or worse. In astro, there
is no support for syscalls.

### Problem: Simulating Memory-Mapped Hardware Features Requires Dark Magic

Whereas currently autograding access to memory-mapped registers requires
dark `mmap()` magic
(<https://austinjadams.com/blog/autograding-gba-dma/>), astro could
simply monitor the special addresses. When a student writes to them,
astro could log the access and then simulate the hardware before
restarting the simulation.

### Problem: Checking for Memory Leaks Is Fundamentally Broken

The Old Way for autograding data structures works as follows:

 1. Inside [`valgrind`][4], start the autograder
 2. Allocate some memory (maybe, depends on the test)
 3. Jump into student code, passing it a pointer to the memory
 4. Student code jumps back into autograder
 5. Autograder asserts that code behaved correctly, and explodes if not
 6. Autograder free()s memory it or the student code allocated
 7. Autograder exits
 8. `valgrind` complains if any memory was not freed

This setup works well enough, but it has several big limitations.

#### Sub-problem: False "Leak" Reports on Assertion Failures

When an assertion fails, the whole autograder exits. This happens before
step #6 happens, since step #5 needs to inspect data structures before
freeing them. This means that when this inspection fails, memory does
not get freed, and valgrind reports a leak. Current autograders mitigate
this by only running valgrind on individual tests that have passed, but
when students use the valgrind task in the Makefile and have failing
tests, they find memory leaks reported for other tests confusing.

#### Sub-problem: `free()`ing Uninitialized Pointers in Data Structures

When testing student functions that allocate data structures, as part of
\#6, the autograder must traverse the data structure allocated by the
student and free the entire thing. However, if the data structure
contains a bogus pointer, namely if a student forgets to initialize the
pointer, then the autograder calling `free()` on it can abort the
autograder. The GNU C library prints a gigantic scary exception which
students don't understand ("what am I freeing wrong?").

#### Solution: Managed Heap

astro will manage the simulated heap outside the simulator, so it knows
what has been allocated and what hasn't.

### Problem: GNU/Linux Error Messages Are Cryptic

A common question from students is "what does 'Segmentation Fault'
mean?" If astro prints a line number and stack trace, that could help
student confusion significantly. Same applies to when `free()` gets an
invalid pointer.


[1]: https://www.unicorn-engine.org/
[2]: https://sourceware.org/elfutils/
[3]: https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
[4]: http://valgrind.org/
[5]: http://dwarfstd.org/
