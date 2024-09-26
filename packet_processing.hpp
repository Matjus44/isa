#ifndef PACKET_PROCESSING_HPP
#define PACKET_PROCESSING_HPP

#include "argument_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h> // For inet_ntop
#include <netinet/if_ether.h> // For Ethernet header
#include <netinet/ip.h> // For IP header
#include <netinet/udp.h> // For UDP header
#include <netinet/ip_icmp.h> // For ICMP header
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <pcap.h>

class PacketProcessing
{
    public:
        static void parse_packet(u_char *user, const struct pcap_pkthdr *header,const u_char *frame);
        static void print_timestamp(const struct pcap_pkthdr *header,parser *parse);
        static void print_ip(const u_char *frame, parser *parse);
        static void print_information(const u_char *frame, parser *parse);
        static void process_ipv4_port(const u_char *frame);
        static void process_ipv6_port(const u_char *frame);
        static std::pair<const u_char*, uint8_t> print_identifier_and_flags(const u_char *frame, u_int16_t type, parser *parse);
        static void print_dns_information(const u_char *frame, const u_char *pointer, parser *parse, uint8_t qr);
        static const u_char *  print_question_sections(const u_char *pointer, Utils &utility_functions, const u_char *frame, uint16_t qd_count, parser *parse);
        static const u_char * print_other_sections(const u_char *authority_pointer, Utils &utility_functions, const u_char *question_pointer,  uint16_t count, std::string section_type, parser *parse);
};

#endif