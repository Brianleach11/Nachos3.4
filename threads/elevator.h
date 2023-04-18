#ifndef ELEVATOR_H
#define ELEVATOR_H

#include "copyright.h"

extern void Elevator(int numFloors);
extern void ArrivingGoingFromTo(int atFloor, int toFloor);

typedef struct Person
{
    int id;
    int atFloor;
    int toFloor;
}Person;

class ELEVATOR 
{
    public:
        ELEVATOR (int numFloors);
        ~ELEVATOR();
        void hailElevator (Person *p);
        void start();
        int totalPersonsWaiting();

    private:
        Lock *elevatorLock;
        Condition **entering;
        Condition **leaving;
        int *personsWaiting;
        Condition *personArrived;
        int currentFloor;
        int occupancy;
        int maxOccupancy;
        int numFloors;
};

#endif