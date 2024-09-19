#ifndef PACKET_CAPTURING_HPP
#define PACKET_CAPTURING_HPP

#include "pcap.h"
#include "argument_parser.hpp"
#include "packet_processing.hpp"

class Sniffer
{  
    public:
        void run_sniffer(parser& parser);

    private:
        pcap_t* init_sniffer(parser& parser);
        void build_filter(parser& parser, pcap_t* handle);
        void capture_packets(pcap_t *handle);
};

#endif