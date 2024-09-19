#include "packet_processing.hpp"

void PacketProcessing::parse_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    // Cast the user parameter back to a parser object
    parser *parse = reinterpret_cast<parser *>(user);

    std::cout << parse->domains_file << std::endl;
    print_timestamp(header,parse);
    print_ip(frame,parse);
    print_ports(frame);
}

void PacketProcessing::print_timestamp(const struct pcap_pkthdr *header, parser *parse)
{
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);

    // Buffer for storing
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::string timestamp = std::string(buffer);

    parse->verbose ? std::cout << "Timestamp: " << timestamp << std::endl : std::cout << timestamp << " ";
}


void PacketProcessing::print_ip(const u_char *frame, parser *parse)
{
    // Treat the start of the frame as the IP header
    const struct ip *ip_header = (struct ip *)frame;

    // Buffers to store the IP addresses in human-readable form
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    // Convert IP addresses from binary to text
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

    // Print source and destination IP addresses

    if(parse->verbose)
    {
        std::cout << "SrcIP: " << src_ip << std::endl;
        std::cout << "DstIP: " << dst_ip << std::endl;
    }
    else
    {
        std::cout << "SrcIP: " << src_ip << "  " << "DstIP: " << dst_ip << " ";
    }
    
}

void PacketProcessing::print_ports(const u_char *frame)
{
    uint8_t version = (frame[0] >> 4);
    // IPv4 packet
    if (version == 4)
    {
        const struct ip *ip_header = (struct ip *)frame;
        // Check if the protocol is UDP or TCP
        if (ip_header->ip_p == IPPROTO_UDP)
        {
            const struct udphdr *udp_header = (struct udphdr *)(frame + (ip_header->ip_hl * 4));

            std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
        }
        else if (ip_header->ip_p == IPPROTO_TCP)
        {
            const struct tcphdr *tcp_header = (struct tcphdr *)(frame + (ip_header->ip_hl * 4));

            std::cout << "SrcPort: TCP/" << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "DstPort: TCP/" << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
    else
    { 
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)frame;

        // Check if the next header is UDP or TCP
        if (ip6_header->ip6_nxt == IPPROTO_UDP)
        {
            const struct udphdr *udp_header = (struct udphdr *)(frame + sizeof(struct ip6_hdr));

            std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
        }
        else if (ip6_header->ip6_nxt == IPPROTO_TCP)
        {
            const struct tcphdr *tcp_header = (struct tcphdr *)(frame + sizeof(struct ip6_hdr));

            std::cout << "SrcPort: TCP/" << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "DstPort: TCP/" << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
}
