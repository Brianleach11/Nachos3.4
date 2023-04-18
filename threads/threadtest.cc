#include "copyright.h"
#include "system.h"
#include "synch.h"

// testnum is set in main.cc
int testnum = 1;
int SharedVariable;
Semaphore * sem = new Semaphore("testsemaphore", 1);
void SimpleThread (int which);

//----------------------------------------------------------------------
// SimpleThread
// 	Loop 5 times, yielding the CPU to another ready thread
//	each iteration.
//
//	"which" is simply a number identifying the thread, for debugging
//	purposes.
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// ThreadTest1
// 	Set up a ping-pong between two threads, by forking a thread
//	to call SimpleThread, and then calling SimpleThread ourselves.
//----------------------------------------------------------------------

//----------------------------------------------------------------------
// ThreadTest
// 	Invoke a test routine.
//----------------------------------------------------------------------
#ifdef HW1_SEMAPHORES

int numThreadsActive;

void ThreadTest(int n)
{
    DEBUG('t', "Entering SimpleThread");
    Thread *t;
    numThreadsActive = n;
    printf("Numthreads Active = %d\n", numThreadsActive);

    for (int i = 1; i < n; i++)
    {
        t = new Thread("forked thread");
        t->Fork(SimpleThread, i);
    }
    SimpleThread(0);
}

void SimpleThread(int which)
{
    int num, val;

    for (num = 0; num < 5; num++)
    {
        // entry point (decrement - P)
        sem->P();

        val = SharedVariable;
        printf("*** thread %d sees value %d\n", which, val);
        currentThread->Yield();

        SharedVariable = val + 1;

        // exit point (increment - V)
        sem->V();

        currentThread->Yield();
    }

    // Decrement numThreadsActive

    numThreadsActive--;

    // Check if numThreadsActive is 0
    while (numThreadsActive != 0)
    {
        currentThread->Yield();
    }

    val = SharedVariable;
    printf("Thread %d sees the final value %d\n", which, val);
}

#else

void ThreadTest1()
{
    DEBUG('t', "Entering ThreadTest1");

    Thread *t = new Thread("forked thread");

    t->Fork(SimpleThread, 1);
    SimpleThread(0);
}

void ThreadTest(int n)
{
    switch (testnum)
    {
    case 1:
        ThreadTest1();
        break;
    default:
        printf("No test specified.\n");
        break;
    }
}

void SimpleThread(int which)
{
    int num, val;

    for (num = 0; num < 5; num++)
    {
        // entry point

        val = SharedVariable;
        printf("*** thread %d sees value %d\n", which, val);
        currentThread->Yield();

        SharedVariable = val + 1;

        // exit point
        currentThread->Yield();
    }
}

#endif