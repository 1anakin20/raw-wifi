//
// Created by System Administrator on 2022-03-25.
//

#ifndef PCAP_MANAGER_OBSERVER_H
#define PCAP_MANAGER_OBSERVER_H
#include <vector>

class Subject;

class Observer {
public:
    virtual ~Observer() = default;
    virtual void Update(Subject&) = 0;
};

class Subject {
public:
    virtual ~Subject() = default;
    void Attach(Observer& o) { observers.push_back(&o); }
    void Detach(Observer& o) {
        observers.erase(std::remove(observers.begin(), observers.end(), &o));
    }
    void Notify() {
        for (auto* o : observers) {
            o->Update(*this);
        }
    }
private:
    std::vector<Observer*> observers;
};


#endif //PCAP_MANAGER_OBSERVER_H
