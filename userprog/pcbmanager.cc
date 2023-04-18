#include "pcbmanager.h"


PCBManager::PCBManager(int maxProcesses) {

    bitmap = new BitMap(maxProcesses);
    pcbs = new PCB*[maxProcesses];
    printf("pcbs.size() = %d\n", sizeof(pcbs));

    for(int i = 0; i < maxProcesses; i++) {
        pcbs[i] = NULL;
    }
    pcbManagerLock = new Lock("pcbManagerLock");

}


PCBManager::~PCBManager() {

    delete bitmap;

    delete pcbs;

    pcbs[pcb->pid] = NULL;

}


PCB* PCBManager::AllocatePCB() {

    // Aquire pcbManagerLock
    pcbManagerLock->Acquire();

    int pid = bitmap->Find();

    pcbManagerLock->Release();
    // Release pcbManagerLock

    ASSERT(pid != -1);

    pcbs[pid] = new PCB(pid);

    return pcbs[pid];

}


int PCBManager::DeallocatePCB(PCB* pcb) {

    // Check is pcb is valid -- check pcbs for pcb->pid

     // Aquire pcbManagerLock
    pcbManagerLock->Acquire();

    bitmap->Clear(pcb->pid);

    // Release pcbManagerLock
    pcbManagerLock->Release();

    delete pcbs[pcb->pid];

    pcbs[pcb->pid] = NULL;

}

PCB* PCBManager::GetPCB(int pid) {
    return pcbs[pid];
}