//
// Created by System Administrator on 2022-03-25.
//
#include <iostream>
#include <cstring>
#include "PcapManager.h"

#define PAYLOAD_OFFSET 2

class Receive : public Observer {
    void Update(Subject &subject) override {
        auto *pcapManager = (PcapManager*)&subject;
        const u_char *latestPacket = pcapManager->getLatestPacket();
        const pcap_pkthdr &latestHeader = pcapManager->getLatestHeader();
        if (latestPacket[26] == 0x40) {
            std::cout << "Got a packet: ";
            for (int i = 52; i < latestHeader.caplen; ++i) {
                std::cout << (uint8_t)latestPacket[i];
            }
            std::cout << std::endl;
        }
    }
};

int main() {
    PcapManager pcapManager(true, 1000, 2048);

    std::cout << "Devices: ";
    for (std::string& device : pcapManager.findDevices()) {
        std::cout << device << " ";
    }
    std::cout << std::endl;

    std::string deviceName;
    std::cout << "Enter device name: ";
    std::cin >> deviceName;
    std::cout << std::endl;

    char *dev = &deviceName[0];
    pcapManager.createPcap(dev);

    std::cout << "Monitor mode " << (pcapManager.checkMonitorModeInterface() ? "available" : "unavailable") << std::endl;

    Receive receiver;
    pcapManager.Attach(receiver);
    pcapManager.setMonitorMode();
    pcapManager.pcapActivate();
    std::cout << "Radiotap header type: " << pcapManager.radiotapHeader() << std::endl;
    pcapManager.setFilter("wlan host 84:f3:eb:a6:67:43");

    while (true) {
        pcapManager.nextPacket();
    }


//    uint8_t header[] = {
//            0x62, 0x62 // Protocol identification
//    };
//    uint16_t headerLength = sizeof(header);
//
//    char payload[] = "Never gonna give you up";
//    uint16_t payloadLength = sizeof(payload);
//
//    uint8_t buffer[headerLength + payloadLength];
//    std::memcpy(buffer, header, headerLength);
//    std::memcpy(buffer+headerLength, payload, payloadLength);
//
//    while (true) {
//        int bytesSent = pcapManager.injectPacket(buffer, headerLength + payloadLength);
//        std::cout << bytesSent <<std::endl;
//    }
    return 0;
}