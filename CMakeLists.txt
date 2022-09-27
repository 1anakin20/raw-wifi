cmake_minimum_required(VERSION 3.21)
project(pcap_manager)

set(CMAKE_CXX_STANDARD 23)

find_library(pcap libpcap)

#add_library(pcap_manager src/PcapManager.cpp src/Observer.h src/PcapExceptions.h src/PcapManager.h src/main.cpp)

add_executable(pcap_manager src/PcapManager.cpp src/Observer.h src/PcapExceptions.h src/PcapManager.h src/main.cpp)

target_link_libraries(pcap_manager pcap)
