#ifndef PACKET_PROCESSING_HPP
#define PACKET_PROCESSING_HPP

#include "argument_parser.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/udp.h> // For UDP header
#include <time.h>
#include <pcap.h>


class PacketProcessing
{
    public:
        static void parse_frame(u_char *user, const struct pcap_pkthdr *header,const u_char *frame);
        static void print_timestamp(const struct pcap_pkthdr *header);
};

#endif