#ifdef HW1_ELEVATOR
#include "copyright.h"
#include "system.h"
#include "synch.h"
#include "elevator.h"

int nextPersonID = 1;
Lock *personIDLock = new Lock("PersonID Lock");
Lock *waitingPersons = new Lock("Waiting for Elevator");
bool upward = true;
bool downward = false;
ELEVATOR *e;

int ELEVATOR::totalPersonsWaiting()
{
    elevatorLock->Acquire();
    int totalPersons = 0;
    for (int i = 0; i < numFloors; i++)
    {
        totalPersons += personsWaiting[i];
    }
    elevatorLock->Release();
    return totalPersons;
}


void ELEVATOR::start()
{
    while (true)
    {
        while(totalPersonsWaiting() == 0 && occupancy ==0)
        {
            elevatorLock->Acquire();
            personArrived->Wait(elevatorLock);
            elevatorLock->Release();
        }
        while(totalPersonsWaiting() > 0 || occupancy > 0)
        {
            elevatorLock->Acquire();
            leaving[currentFloor]->Broadcast(elevatorLock);
            elevatorLock->Release();
            currentThread->Yield();
            elevatorLock->Acquire();
            while(occupancy < maxOccupancy && personsWaiting[currentFloor] > 0)
            {
                entering[currentFloor]->Signal(elevatorLock);
                elevatorLock->Release();
                currentThread->Yield();
                elevatorLock->Acquire();
            }
            elevatorLock->Release();
            for(int j = 0; j < 50; j++) 
            {
                currentThread->Yield();
            }
            if(currentFloor + 1 >= numFloors)
            {
                downward = true;
                upward = false;
            }
            if (currentFloor - 1 < 0)
            {
                upward = true;
                downward = false;
            }
            if (downward)currentFloor--;
            if (upward)currentFloor++;
            printf("Elevator arrives on floor %d.\n", currentFloor);
        }
    }
}

void ElevatorThread(int numFloors)
{
    e = new ELEVATOR(numFloors);
    printf("Elevator with %d floors was created.\n", numFloors);

    e->start();
}

ELEVATOR::~ELEVATOR()
{
    delete entering;
    delete leaving;
    delete personsWaiting;
    delete elevatorLock;
}

ELEVATOR::ELEVATOR (int numFLOORS)
{
    occupancy = 0;
    maxOccupancy = 5;
    currentFloor = 0;
    personsWaiting = new int[numFLOORS];
    numFloors = numFLOORS;
    elevatorLock = new Lock("ElevatorLock");
    personArrived = new Condition("PersonArrived");
    entering = new Condition*[numFloors];
    leaving = new Condition*[numFloors];
    for (int i = 0; i < numFloors; i++)
    {
        entering[i] = new Condition("Entering " + i);
        leaving[i] = new Condition("Leaving " + i);
        personsWaiting[i] = 0;
    }
}

void PersonThread (int person)
{
    Person *p = (Person *)person;
    printf("Person %d wants to go from floor %d to floor %d.\n", p->id, p->atFloor, p->toFloor);
    e->hailElevator(p);
}

void ELEVATOR::hailElevator (Person *p)
{
    personsWaiting[p->atFloor] += 1;
    elevatorLock->Acquire();
    personArrived->Signal(elevatorLock);
    entering[p->atFloor]->Wait(elevatorLock);
    printf("Person %d got into the elevator.\n", p->id);
    personsWaiting[p->atFloor] -= 1;
    occupancy += 1;
    leaving[p->toFloor]->Wait(elevatorLock);
    occupancy -= 1;
    elevatorLock->Release();
    printf("Person %d got off the elevator.\n", p->id);
}

void Elevator (int numFloors)
{
    Thread *t = new Thread("Elevator");
    t->Fork(ElevatorThread, numFloors);
}

int getNextPersonID()
{
    int personID = nextPersonID;
    personIDLock->Acquire();
    nextPersonID += 1;
    personIDLock->Release();
    return personID;
}

void ArrivingGoingFromTo(int atFloor, int toFloor)
{
    Person *p = new Person;
    p->id = getNextPersonID();
    p->atFloor = atFloor;
    p->toFloor = toFloor;

    Thread *t = new Thread("Person " + p->id);
    t->Fork(PersonThread,(int)p);
}
#endif
