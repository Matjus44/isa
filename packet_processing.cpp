#include "packet_processing.hpp"

void PacketProcessing::parse_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    // Cast the user parameter back to a parser object
    parser *parse = reinterpret_cast<parser *>(user);

    std::cout << parse->domains_file << std::endl;
    print_timestamp(header, parse);
    print_ip(frame, parse);
    print_ports(frame, parse);
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
    // Buffers to store the IP addresses in human-readable form
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    uint8_t ip_version = (frame[0] >> 4); // First 4 bits represent the IP version

    if (ip_version == 4)
    {
        const struct ip *ip_header = (struct ip *)frame;
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    }
    else if (ip_version == 6)
    {
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)frame;
        inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip, INET6_ADDRSTRLEN);
    }

    if (parse->verbose)
    {
        std::cout << "SrcIP: " << src_ip << std::endl;
        std::cout << "DstIP: " << dst_ip << std::endl;
    }
    else
    {
        std::cout << "SrcIP: " << src_ip << "  " << "DstIP: " << dst_ip << " ";
    }
}

void PacketProcessing::process_ipv4(const u_char *frame, parser *parse)
{
    auto ip4 = reinterpret_cast<const struct ip *>(frame + sizeof(struct ether_header));

    // Check if the protocol is UDP or TCP
    if (ip4->ip_p == IPPROTO_UDP)
    {
        const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + (ip4->ip_hl * 4));
        if (parse->verbose)
        {
            std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
        }
    }
}

void PacketProcessing::process_ipv6(const u_char *frame, parser *parse)
{
    auto ip6 = reinterpret_cast<const struct ip6_hdr *>(frame + sizeof(struct ether_header)); // Get IPv6 header

    // Check the next header field to determine the protocol
    uint8_t next_header = ip6->ip6_nxt;

    if (next_header == IPPROTO_TCP)
    {
        const struct tcphdr *tcp_header = reinterpret_cast<const struct tcphdr *>(frame + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        if (parse->verbose)
        {
            std::cout << "src port: " << ntohs(tcp_header->th_sport) << std::endl;
            std::cout << "dst port: " << ntohs(tcp_header->th_dport) << std::endl;
        }
    }
}

void PacketProcessing::print_ports(const u_char *frame, parser *parse)
{
    const struct ether_header *eth_header = reinterpret_cast<const struct ether_header *>(frame);
    // Get the Ethernet type
    auto ether_type = ntohs(eth_header->ether_type);

    // Check the Ethernet type and print corresponding information
    if (ether_type == ETHERTYPE_IP)
    {
        process_ipv4(frame, parse);
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        process_ipv6(frame, parse);
    }

    print_identifier(frame, parse, ether_type);
}

void PacketProcessing::print_identifier(const u_char *frame, parser *parse, uint16_t type)
{
    const u_char *dns_header;

    if (type == ETHERTYPE_IP)
    {
        const struct ip *ip_header = (struct ip *)frame;
        int ip_header_len = ip_header->ip_hl * 4; // ip_hl is in 4-byte words
        int udp_header_len = 8; // UDP header length is always 8 bytes
        dns_header = frame + ip_header_len + udp_header_len;
    }
    else if (type == ETHERTYPE_IPV6)
    {
        int ip6_header_len = 40; // IPv6 header is always 40 bytes
        int udp_header_len = 8; // UDP header length is always 8 bytes
        dns_header = frame + ip6_header_len + udp_header_len;
    }

    uint16_t dns_identifier = ntohs(*(uint16_t *)dns_header);

    // Print the DNS identifier
    if (parse->verbose)
    {
        std::cout << "Identifier: 0x" << std::hex << dns_identifier << std::dec << std::endl;
    }
    else
    {
        std::cout << "Identifier: 0x" << std::hex << dns_identifier << std::dec << " ";
    }
}