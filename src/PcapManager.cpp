//
// Created by System Administrator on 2022-03-24.
//

#include "PcapManager.h"
#include "PcapExceptions.h"
#include <iostream>

PcapManager::PcapManager(bool isPromisc, int to_ms, int bufferSize) {
    this->isPromisc = isPromisc;
    this->to_ms = to_ms;
    this->bufferSize = bufferSize;
    this->latestPacket = nullptr;
}

std::vector<std::string> PcapManager::findDevices() {
    std::vector<std::string> devicesName;

    pcap_if_t *allDevs;

    if (pcap_findalldevs(&allDevs, errBuffer) == -1) {
        throw CantFindDevicesException();
    }

    for (pcap_if_t *device = allDevs; device->next; device = device->next) {
        devicesName.emplace_back(device->name);
    }

    return devicesName;
}

void PcapManager::createPcap(char* device) {
    pcap* tmpPcap = pcap_create(device, errBuffer);

    if (tmpPcap == nullptr) {
        std::cerr << errBuffer;
        throw CantCreateCaptureHandleException();
    }
    pPcap = tmpPcap;

    pcap_set_snaplen(pPcap, BUFSIZ);
    pcap_set_promisc(pPcap, this->isPromisc);
    pcap_set_timeout(pPcap, this->to_ms);
    pcap_set_buffer_size(pPcap, this->bufferSize);
}

void PcapManager::setFilter(const char str[]) {
    struct bpf_program filter{};
    int compileResult = pcap_compile(pPcap, &filter, str, 0, 0);
    if (compileResult == PCAP_ERROR || compileResult != 0) {
        std::cerr << "Error compiling filter";
        pcap_perror(pPcap, errBuffer);
    }

    if (pcap_setfilter(pPcap, &filter) == PCAP_ERROR) {
        std::cerr << "Error setting filter";
        pcap_perror(pPcap, errBuffer);
    }
}

int PcapManager::pcapActivate() {
    int activateResult = pcap_activate(pPcap);
    if (activateResult > 0) {
        // TODO handle couldn't open
        std::cerr << "Warnings while opening pcap";
        pcap_perror(pPcap, "Error >> ");
    } else if(activateResult < 0) {
        std::cerr << "Error while opening pcap" << std::endl;
        pcap_perror(pPcap, "Error >> ");
    }

    return activateResult;
}

int PcapManager::radiotapHeader() {
    return pcap_datalink(pPcap);
}

bool PcapManager::checkMonitorModeInterface() {
	int result = pcap_can_set_rfmon(pPcap);
	if (result == 1) {
        return true;
	}

    std::cout << "Can't set monitor mode. Error: " << result << std::endl;
    if (result == PCAP_ERROR_NO_SUCH_DEVICE) {
        std::cerr << "No device available\n";
    }
    else if (result == PCAP_ERROR_PERM_DENIED) {
        std::cerr << "Permission denied\n";
    }
    else if (result == PCAP_ERROR_ACTIVATED) {
        std::cerr << "Error activated\n";
    }
    else if (result == PCAP_ERROR) {
        std::cerr << "Another error occurred\n";
        pcap_perror(pPcap, "Error >> ");
    }
    return false;
}

void PcapManager::setMonitorMode() {
    if (!checkMonitorModeInterface()) {
        // TODO throw exception, notify the user somehow about monitor mode not being available
        return;
    }

    int setResult = pcap_set_rfmon(pPcap, 1);
    if (setResult == PCAP_ERROR_ACTIVATED) {
        // TODO deal if already activated
    } else if (setResult != 0) {
        std::cerr << "Error setting monitor mode" << std::endl;
        pcap_perror(pPcap, "Error >> ");
    }
}

void PcapManager::nextPacket() {
    latestPacket = pcap_next(pPcap, &latestHeader);
    if (latestPacket != nullptr) {
        Notify();
    }
}

int PcapManager::injectPacket(void *buf, size_t size) {
    int result = pcap_inject(pPcap, buf, size);

    if (result == PCAP_ERROR) {
        throw CouldNotInjectPacket();
    }

    if (result < 0) {
        pcap_perror(pPcap, "Error >> ");
    }

    return result;
}

void PcapManager::close() {
    pcap_close(pPcap);
}

const u_char *PcapManager::getLatestPacket() {
    return latestPacket;
}

const pcap_pkthdr & PcapManager::getLatestHeader() {
    return latestHeader;
}