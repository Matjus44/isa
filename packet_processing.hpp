#ifndef PACKET_PROCESSING_HPP
#define PACKET_PROCESSING_HPP

#include "argument_parser.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <netinet/udp.h> // For UDP header
#include <time.h>
#include <pcap.h>
#include <netinet/ip.h>   // For IPv4 header
#include <netinet/tcp.h>  // For TCP header
#include <netinet/ip6.h>  // For IPv6 header
#include <arpa/inet.h>    // For inet_ntop and ntohs


class PacketProcessing
{
    public:
        static void parse_packet(u_char *user, const struct pcap_pkthdr *header,const u_char *frame);
        static void print_timestamp(const struct pcap_pkthdr *header,parser *parse);
        static void print_ip(const u_char *frame, parser *parse);
        static void print_ports(const u_char *frame);
};

#endif