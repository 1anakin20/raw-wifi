//
// Created by System Administrator on 2022-03-25.
//

#ifndef PCAP_MANAGER_PCAPEXCEPTIONS_H
#define PCAP_MANAGER_PCAPEXCEPTIONS_H

#include <exception>

class CantFindDevicesException : std::exception {
    const char* what() const noexcept override {
        return "Couldn't open devices";
    }
};

class CantCreateCaptureHandleException : std::exception {
private:
    char* message;
//    CantCreateCaptureHandleException(char* message) {
//        this->message = message;
//    }

public:
    const char* what() const noexcept override {
        // TODO Add error message
//        char *errorMessage = (char*) "Couldn't create pcap handle: ";
//        strlcat(errorMessage, message)
        return "Couldn't create pcap handle";
    }

};

class CouldNotInjectPacket : std::exception {
    const char* what() const noexcept override {
        return "Couldn't inject packet";
    }
};

#endif //PCAP_MANAGER_PCAPEXCEPTIONS_H
