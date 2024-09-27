/*
 * Program: DNS monitor
 * Description: Header file for utils.cpp
 * Author: Matúš Janek
 * Date: 27.09.2024
 */

#ifndef PACKET_PROCESSING_HPP
#define PACKET_PROCESSING_HPP

#include "argument_parser.hpp"
#include "utils.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <time.h>
#include <pcap.h>

/**
 * @class PacketProcessing
 * @brief Class that processes packet.
 */
class PacketProcessing
{
    public:
        /**
         * @brief Entry function from sniffer.
         * 
         * @param user User-specific data passed through pcap_loop.
         * @param header Packet header containing metadata such as timestamp.
         * @param frame Raw packet.
         */
        static void parse_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *frame);

        /**
         * @brief Prints the timestamp of the captured packet.
         * 
         * @param header Packet header containing the timestamp.
         * @param parse Parser object containing user configurations.
         */
        static void print_timestamp(const struct pcap_pkthdr *header, parser *parse);

        /**
         * @brief Prints the IP addresses.
         * 
         * @param frame Raw packet.
         * @param parse Parser object containing user configurations.
         */
        static void print_ip(const u_char *frame, parser *parse);

        /**
         * @brief Contains order of function calling for packet parsing, finding out whether the packet is IPv4 or IPv6.
         * 
         * @param frame Raw packet.
         * @param parse Parser object containing user configurations.
         */
        static void print_information(const u_char *frame, parser *parse);

        /**
         * @brief Processes the source and destination ports of an IPv4 packet.
         * 
         * @param frame Raw packet.
         */
        static void process_ipv4_port(const u_char *frame);

        /**
         * @brief Processes the source and destination ports of an IPv6 packet.
         * 
         * @param frame Raw packet.
         */
        static void process_ipv6_port(const u_char *frame);

        /**
         * @brief Prints the DNS identifier and flags from the packet and returns the pointer right after DNS_header.
         * 
         * @param frame Raw packet.
         * @param type IPv4 or IPv6.
         * @param parse Parser object containing user configurations.
         * @return Pair of Q/R flag and pointer to first section.
         */
        static std::pair<const u_char*, uint8_t> print_identifier_and_flags(const u_char *frame, u_int16_t type, parser *parse);

        /**
         * @brief Prints DNS query and response information from the packet.
         * 
         * @param frame Raw packet.
         * @param pointer Pointer to the first section.
         * @param parse Parser object containing user configurations.
         * @param qr The QR flag indicating if the packet is a query or a response.
         */
        static void print_dns_information(const u_char *frame, const u_char *pointer, parser *parse, uint8_t qr);

        /**
         * @brief Prints the DNS question section of the packet.
         * 
         * @param pointer Pointer to the start of the DNS question section.
         * @param utility_functions Utility object that has helping functions.
         * @param frame Raw packet.
         * @param qd_count Number of questions in the DNS question section.
         * @param parse Parser object containing user configurations.
         * @return Pointer to the start of the next DNS section.
         */
        static const u_char* print_question_sections(const u_char *pointer, Utils &utility_functions, const u_char *frame, uint16_t qd_count, parser *parse);

        /**
         * @brief Prints the DNS answer, authority, and additional sections of the packet.
         * 
         * @param beggining_of_section Pointer to start od DNS section.
         * @param utility_functions Utility object that has helping functions.
         * @param question_pointer Pointer to the start of the DNS question section.
         * @param count Number of records in the section.
         * @param section_type String containing section type for printing.
         * @param parse Parser object containing user configurations.
         * @return Pointer to the start of the next section, if any.
         */
        static const u_char* print_other_sections(const u_char *beggining_of_section, Utils &utility_functions, const u_char *question_pointer, uint16_t count, std::string section_type, parser *parse);
};

#endif