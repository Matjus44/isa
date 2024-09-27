/*
 * Program: DNS monitor
 * Description: Implementation of methods from Sniffer class.
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#include "packet_capturing.hpp"

static char errbuf[PCAP_ERRBUF_SIZE];

void Sniffer::run_sniffer(parser &parser)
{
    pcap_t* handle = init_sniffer(parser);
    build_filter(parser, handle);
    capture_packets(parser, handle);
}

void Sniffer::run_pcap(parser &parser)
{
    pcap_t *handle;
    // Open pcap file
    handle = pcap_open_offline(parser.pcap.c_str(), errbuf);
    if (handle == nullptr) 
    {
        std::cerr << "Error: Could not open PCAP file: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    build_filter(parser,handle);
    capture_packets(parser, handle);
}

pcap_t* Sniffer::init_sniffer(parser &parser)
{
    // Open interface
    auto handle = pcap_open_live(parser.interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr)
    {
        std::cerr << "Error: Could not open interface: " << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }
    // Check whether its supported.
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        std::cerr << "Error: Ethernet not supported on specified interface" << std::endl;
        exit(EXIT_FAILURE);
    }
    return handle;
}

void Sniffer::build_filter(parser &parser, pcap_t *handle)
{
    // Filter expression for DNS over UDP (port 53)
    std::string filter = "udp port 53";
    
    bpf_u_int32 net;
    bpf_u_int32 mask;
    struct bpf_program bpf_prog;

    if(!parser.interface.empty())
    {
        // Lookup network details (netmask, IP range, etc.) for the given interface
        if (pcap_lookupnet(parser.interface.c_str(), &net, &mask, errbuf) == PCAP_ERROR)
        {
            std::cerr << "Error: Looking up network: " << errbuf << std::endl;
            exit(EXIT_FAILURE);
        }
    }

    // Compile the filter expression
    if (pcap_compile(handle, &bpf_prog, filter.c_str(), 0, mask) == PCAP_ERROR)
    {
        std::cerr << "Error: Filter compiling: " << pcap_geterr(handle) << std::endl;
        exit(EXIT_FAILURE);
    }

    // Set the compiled filter
    if (pcap_setfilter(handle, &bpf_prog) == PCAP_ERROR)
    {
        std::cerr << "Error: Setting filter: " << pcap_geterr(handle) << std::endl;
        pcap_freecode(&bpf_prog); // Free the filter code if an error occurs
        exit(EXIT_FAILURE);
    }

    // Free the compiled filter after it's set
    pcap_freecode(&bpf_prog); 
}


void Sniffer::capture_packets(parser &parser , pcap_t *handle)
{
    if (pcap_loop(handle, 0 , PacketProcessing::parse_packet, reinterpret_cast<u_char*>(&parser)) < 0) // Loop for capturing packets
    {
        std::cerr << "Error: Issue while capturing packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        exit(EXIT_FAILURE);
    }
    // Close sniffer
    pcap_close(handle);
}