/*
 * Program: DNS monitor
 * Description: Header file for packet_capturing.cpp
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#ifndef PACKET_CAPTURING_HPP
#define PACKET_CAPTURING_HPP

#include "argument_parser.hpp"
#include "packet_processing.hpp"

/**
 * @class Sniffer
 * @brief Class for intialization and building of sniffer 
 * for packet capturing.
 */
class Sniffer
{  
    public:
        /**
         * @brief Starts live packet sniffing.
         * 
         * @param parser For user input data.
         */
        void run_sniffer(parser& parser);

        /**
         * @brief Processes packets from a pcap file and captures them based on the parser's configuration.
         * 
         * @param parser For user input data.
         */
        void run_pcap(parser &parser);

    private:
        /**
         * @brief Initializes the sniffer on a given network interface or pcap file.
         * 
         * @param parser For user input data.
         * @return A pointer to a pcap_t handle, which is used for packet capturing.
         */
        pcap_t* init_sniffer(parser& parser);

        /**
         * @brief Builds and applies a packet filter based on the parser's filter criteria.
         * 
         * @param parser For user input data.
         * @param handle A pointer to a pcap_t handle, which is used for packet capturing (Added filter).
         */
        void build_filter(parser& parser, pcap_t* handle);

        /**
         * @brief Captures packets using the provided pcap handle.
         * 
         * @param parser TFor user input data.
         * @param handle The pcap_t handle used for capturing packets.
         */
        void capture_packets(parser &parser, pcap_t *handle);
};

#endif
