cmake_minimum_required(VERSION 3.10)
project(tls-block)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)



add_executable(tls-block
        tls_block.cpp
        parse.cpp
        mac.h
        ip.h
        ethhdr.h
        iphdr.h
        tcphdr.h
        parse.h)

target_link_libraries(tls-block pcap)