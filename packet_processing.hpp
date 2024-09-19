#ifndef PACKET_PROCESSING_HPP
#define PACKET_PROCESSING_HPP

#include "argument_parser.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h> // For inet_ntop
#include <netinet/if_ether.h> // For Ethernet header
#include <netinet/ip.h> // For IP header
#include <netinet/tcp.h> // For TCP header
#include <netinet/udp.h> // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <pcap.h>
#include <netinet/igmp.h> // For IGMP header


class PacketProcessing
{
    public:
        static void parse_packet(u_char *user, const struct pcap_pkthdr *header,const u_char *frame);
        static void print_timestamp(const struct pcap_pkthdr *header,parser *parse);
        static void print_ip(const u_char *frame, parser *parse);
        static void print_ports(const u_char *frame, parser *parse);
        static void process_ipv4(const u_char *frame, parser *parse);
        static void process_ipv6(const u_char *frame, parser *parse);
};

#endif