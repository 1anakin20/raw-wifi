//
// Created by System Administrator on 2022-03-25.
//

#ifndef PCAP_MANAGER_PCAPMANAGER_H
#define PCAP_MANAGER_PCAPMANAGER_H
#include "Observer.h"
#include <pcap/pcap.h>
#include <vector>
#include <string>

class PcapManager : public Subject {
private:
    pcap_t* pPcap;
    bool isPromisc;
    int to_ms;
    int bufferSize;
    char errBuffer[PCAP_ERRBUF_SIZE] = {};
    const u_char *latestPacket;
    struct pcap_pkthdr latestHeader{};
public:
    PcapManager(bool isPromisc, int to_ms, int bufferSize);
    std::vector<std::string> findDevices();
    void createPcap(char* device);
    void setFilter(const char str[]);
    int pcapActivate();
    int radiotapHeader();
    bool checkMonitorModeInterface();
    void setMonitorMode();
    void nextPacket();
    int injectPacket(void *buf, size_t size);
    void close();
    const u_char *getLatestPacket();
    const pcap_pkthdr & getLatestHeader();
};

#endif //PCAP_MANAGER_PCAPMANAGER_H
