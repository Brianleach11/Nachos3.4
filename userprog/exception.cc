// exception.cc 
//	Entry point into the Nachos kernel from user programs.
//	There are two kinds of things that can cause control to
//	transfer back to here from user code:
//
//	syscall -- The user code explicitly requests to call a procedure
//	in the Nachos kernel.  Right now, the only function we support is
//	"Halt".
//
//	exceptions -- The user code does something that the CPU can't handle.
//	For instance, accessing memory that doesn't exist, arithmetic errors,
//	etc.  
//
//	Interrupts (which can also cause control to transfer from user
//	code into the Nachos kernel) are handled elsewhere.
//
// For now, this only handles the Halt() system call.
// Everything else core dumps.
//
// Copyright (c) 1992-1993 The Regents of the University of California.
// All rights reserved.  See copyright.h for copyright notice and limitation 
// of liability and disclaimer of warranty provisions.

#include "copyright.h"
#include "system.h"
#include "syscall.h"

//----------------------------------------------------------------------
// ExceptionHandler
// 	Entry point into the Nachos kernel.  Called when a user program
//	is executing, and either does a syscall, or generates an addressing
//	or arithmetic exception.
//
// 	For system calls, the following is the calling convention:
//
// 	system call code -- r2
//		arg1 -- r4
//		arg2 -- r5
//		arg3 -- r6
//		arg4 -- r7
//
//	The result of the system call, if any, must be put back into r2. 
//
// And don't forget to increment the pc before returning. (Or else you'll
// loop making the same system call forever!
//
//	"which" is the kind of exception.  The list of possible exceptions 
//	are in machine.h.
//----------------------------------------------------------------------
void doExit(int status)
{
    PCB* pcb = currentThread->space->pcb;
    int pid = pcb->pid;

    printf("System call: [%d] invoked [EXIT]\n", pid);
    printf("Process: [%d] exits with [%d]\n", pid, status); //should be status '4'

    pcb->exitStatus = status;

    pcb->DeleteExitedChildrenSetParentNull();

    if(pcb->parent == NULL) pcbManager->DeallocatePCB(pcb);

    delete currentThread->space;
    currentThread->Finish();
}

void incrementPC()
{
    int oldPCReg = machine->ReadRegister(PCReg);

    machine->WriteRegister(PrevPCReg, oldPCReg);
    machine->WriteRegister(PCReg, oldPCReg + 4);
    machine->WriteRegister(NextPCReg, oldPCReg + 8);
}

void childFunction(int pid)
{
    //1. Restore the state of registers
        //currentThread->RestoreUserState();
    currentThread->RestoreUserState();
    //2. Restore the page table for child
        //currentThread->space->RestoreState();
    currentThread->space->RestoreState();
    //PCReg = ReadRegister(PCReg)
    int newPCReg = machine->ReadRegister(PCReg);
    //print message for creation(pid, PCReg, currentThread->space->GetNumPages())
    printf("Process %d Fork: start at address %d with %d pages memory\n", pid, newPCReg, currentThread->space->GetNumPages());
    //machine->Run();
    machine->Run();
}

int doFork(int functionAddr)
{
    //1. Check if sufficient memory exists to create new process
        // currentThread->space->GetNumPages() <= mm->GetFreePageCount()
        // if fails, return -1
    bool enoughSpace = (currentThread->space->GetNumPages() <= mm->GetFreePageCount()) ? true : false;
    if (!enoughSpace) return -1;
    //2. SaveUserState for the parent
    currentThread->SaveUserState();
    //3. Create a new address space for child via copy
        //Parent: currentThread->space
        //ChildAddrSpace: new AddSpace(currentThread->space);
    AddrSpace* childAddrSpace = new AddrSpace(currentThread->space);
    //4. Create a new thread for child and set its addrspace
        //childThread = new Thread("childThread")
        //childThread->space = ChildAddrSpace;
    Thread* childThread = new Thread("childThread");
    childThread->space = childAddrSpace;
    //5. Create a PCB for the child and connect it al up
        //pcb: pcbManager->AllocatePCB();
        //pcb->thread = childThread;

        //set parent for child pcb
        //ad child for parent pcb
    PCB* childPCB = pcbManager->AllocatePCB();
    childPCB->thread = childThread;
    childPCB->parent = currentThread->space->pcb;
    currentThread->space->pcb->AddChild(childPCB);
    childThread->space->pcb = childPCB;
    //6. Set up the machine registers for the child
        //PCReg: functionAddr
        //PrevPCReg: functionAddr - 4
        //NextPCReg: functionAddr + 4
        //childThread->SaveUserState();
    machine->WriteRegister(PCReg, functionAddr);
    machine->WriteRegister(PrevPCReg, functionAddr - 4);
    machine->WriteRegister(NextPCReg, functionAddr + 4);
    childThread->SaveUserState();
    //7. Call fork on child
        //childThread->Fork(childFunction, pcb->pid);
    childThread->Fork(childFunction, childPCB->pid);
    //8. Restore register state of parent ULP
        //currentThread->RestoreUserState();
    currentThread->RestoreUserState();
    //9. return pcb->pid;
    return currentThread->space->pcb->pid;

}

char* translate(int virtualAddr)
{
    unsigned int pageNumber = virtualAddr / 128;
    unsigned int pageOffset = virtualAddr % 128;
    unsigned int frameNumber = machine->pageTable[pageNumber].physicalPage;
    unsigned int physicalAddr = (frameNumber * 128) + pageOffset;
    char* fileName = &(machine->mainMemory[physicalAddr]);
    return fileName;
}

int doExec(char* fileName)
{
    //Use progtest.cc:StartProcess() as a guide
    //1. 
    OpenFile* executable = fileSystem->Open(fileName);
    AddrSpace* space;

    if (executable == NULL) {
	    printf("Unable to open file %s\n", fileName);
	    return -1;
    }

    //2. Create New AddrSpace
    space = new AddrSpace(executable);    
    
    //3. check if space creation was successful
    //printf(could not create address space)
    if(space->valid != true) return -1;

    //4. Createa a new PCB
    PCB* pcb = currentThread->space->pcb;
    space->pcb = pcb;

    //5. Delete the current address space
    delete currentThread->space;

    //6. set the addressspace for current thread
    currentThread->space = space; 

    delete executable;

    space->InitRegisters();
    space->RestoreState();

    machine->Run();
    ASSERT(FALSE); //never reach this point

    return 0;
}

int doJoin(int pid) 
{

    // 1. Check if this is a valid pid and return -1 if not
    PCB* joinPCB = pcbManager->GetPCB(pid);
    if (joinPCB == NULL) return -1;

    // 2. Check if pid is a child of current process
    PCB* pcb = currentThread->space->pcb;
    if (pcb != joinPCB->parent) return -1;

    // 3. Yield until joinPCB has not exited
    while(!joinPCB->HasExited()) currentThread->Yield();

    // 4. Store status and delete joinPCB
    int status = joinPCB->exitStatus;
    delete joinPCB;

    // 5. 
    return status;

}

int doKill (int pid) 
{

    // 1. Check if the pid is valid and if not, return -1
    PCB* killPCB = pcbManager->GetPCB(pid);
    if (killPCB == NULL) return -1;

    // 2. IF pid is self, then just exit the process
    if (killPCB == currentThread->space->pcb) 
    {
        doExit(0);
        return 0;
    }

    // 3. Valid kill, pid exists and not self, do cleanup similar to Exit
    // However, change references from currentThread to the target thread
    // pcb->thread is the target thread

    //killPCB->thread->space->pcb->exitStatus = ?;
    //killPCB->thread->space->pcb->DeleteExitedChildrenSetParentNull();
    killPCB->exitStatus = 0;
    killPCB->DeleteExitedChildrenSetParentNull();

    if (killPCB->parent == NULL) pcbManager->DeallocatePCB(killPCB);

    delete killPCB->thread->space;
    killPCB->thread->Finish();

    scheduler->RemoveThread(killPCB->thread);

    delete killPCB;

    return 0;
}

void doYield() 
{
    currentThread->Yield();
}

char* readString(int virtualAddr) {
    int i = 0;
    char* str = new char[256];
    unsigned int physicalAddr = currentThread->space->Translate(virtualAddr);

    // Need to get one byte at a time since the string may straddle multiple pages that are not guaranteed to be contiguous in the physicalAddr space
    bcopy(&(machine->mainMemory[physicalAddr]),&str[i],1);
    while(str[i] != '\0' && i != 256-1)
    {
        virtualAddr++;
        i++;
        physicalAddr = currentThread->space->Translate(virtualAddr);
        bcopy(&(machine->mainMemory[physicalAddr]),&str[i],1);
    }
    if(i == 256-1 && str[i] != '\0')
    {
        str[i] = '\0';
    }

    return str;
}

void doCreate(char* fileName)
{
    printf("Syscall Call: [%d] invoked Create.\n", currentThread->space->pcb->pid);
    fileSystem->Create(fileName, 0);
}

void
ExceptionHandler(ExceptionType which)
{
    int type = machine->ReadRegister(2);

    if ((which == SyscallException) && (type == SC_Halt)) {
        DEBUG('a', "Shutdown, initiated by user program.\n");
        interrupt->Halt();
    } else  if ((which == SyscallException) && (type == SC_Exit)) {
        // Implement Exit system call
        doExit(machine->ReadRegister(4));
    } else if ((which == SyscallException) && (type == SC_Fork)) {
        printf("System Call: [%d] invoked [Fork]\n", currentThread->space->pcb->pid);
        int ret = doFork(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Yield)) {
        printf("System Call: [%d] invoked [Yield]\n", currentThread->space->pcb->pid);
        doYield();
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Exec)) {
        printf("System Call: [%d] invoked [Exec]\n", currentThread->space->pcb->pid);
        int virtAddr = machine->ReadRegister(4);
        char* fileName = readString(virtAddr);
        printf("Exec Program: [%d] loading [%s]\n", currentThread->space->pcb->pid, fileName);
        int ret = doExec(fileName);
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Join)) {
        printf("System Call: [%d] invoked [Join]\n", currentThread->space->pcb->pid);
        int ret = doJoin(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Kill)) {
        int ret = doKill(machine->ReadRegister(4));
        machine->WriteRegister(2, ret);
        incrementPC();
    } else if ((which == SyscallException) && (type == SC_Yield)) {
        doYield();
        incrementPC();
    } else if((which == SyscallException) && (type == SC_Create)) {
        int virtAddr = machine->ReadRegister(4);
        char* fileName = readString(virtAddr);
        doCreate(fileName);
        incrementPC();
    } else {
        printf("Unexpected user mode exception %d %d\n", which, type);
        ASSERT(FALSE);
    }
}
