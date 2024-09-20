#include "packet_processing.hpp"

void PacketProcessing::parse_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    // Cast the user parameter back to a parser object
    parser *parse = reinterpret_cast<parser *>(user);

    std::cout << parse->domains_file << std::endl;
    print_timestamp(header, parse);
    print_ip(frame, parse);
    print_information(frame, parse);
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
    // Lokální kopie ukazatele
    const u_char *ip_frame = frame + 14; // Přeskočení Ethernetové hlavičky (14 bajtů)

    // Buffery pro uložení IP adres ve čitelné podobě
    char src_ip[INET6_ADDRSTRLEN] = {0};
    char dst_ip[INET6_ADDRSTRLEN] = {0};

    // Získání verze IP (4 nebo 6)
    uint8_t ip_version = (ip_frame[0] >> 4); // První 4 bity představují verzi IP

    if (ip_version == 4)
    {
        const struct ip *ip_header = (struct ip *)ip_frame;
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
    }
    else if (ip_version == 6)
    {
        const struct ip6_hdr *ip6_header = (struct ip6_hdr *)ip_frame;
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

void PacketProcessing::process_ipv4_port(const u_char *frame)
{
    auto ip4 = reinterpret_cast<const struct ip *>(frame + sizeof(struct ether_header));

    // Check if the protocol is UDP or TCP
    if (ip4->ip_p == IPPROTO_UDP)
    {
        const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + (ip4->ip_hl * 4));
        std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
    }
}

void PacketProcessing::process_ipv6_port(const u_char *frame)
{
    auto ip6 = reinterpret_cast<const struct ip6_hdr *>(frame + sizeof(struct ether_header)); // Get IPv6 header

    // Check the next header field to determine the protocol
    uint8_t next_header = ip6->ip6_nxt;

    if (next_header == IPPROTO_UDP)
    {
        const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
        std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
        std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
    }
}

void PacketProcessing::print_information(const u_char *frame, parser *parse)
{
    const struct ether_header *eth_header = reinterpret_cast<const struct ether_header *>(frame);
    // Get the Ethernet type
    auto ether_type = ntohs(eth_header->ether_type);
    // const u_char *dns_header = nullptr;

    // Check the Ethernet type and print corresponding information
    if (ether_type == ETHERTYPE_IP && parse->verbose == true)
    {
        process_ipv4_port(frame);
    }
    else if (ether_type == ETHERTYPE_IPV6 && parse->verbose == true)
    {
        process_ipv6_port(frame);
    }
    else
    {
        std::cout << "Error" << std::endl;
    }
    if (parse->verbose)
    {
        // dns_header = 
        print_identifier_and_flags(frame, ether_type);
    }
}

const u_char *PacketProcessing::print_identifier_and_flags(const u_char *frame, uint16_t type)
{
    const u_char *dns_header;

    if (type == ETHERTYPE_IP)
    {
        const struct ip *ip_header = (struct ip *)frame;
        int ip_header_len = ip_header->ip_hl * 4; // ip_hl is in 4-byte words
        int udp_header_len = 8;                   // UDP header length is always 8 bytes
        dns_header = frame + ip_header_len + udp_header_len;
    }
    else if (type == ETHERTYPE_IPV6)
    {
        int ip6_header_len = 40; // IPv6 header is always 40 bytes
        int udp_header_len = 8;  // UDP header length is always 8 bytes
        dns_header = frame + ip6_header_len + udp_header_len;
    }

    uint16_t dns_identifier = ntohs(*(uint16_t *)dns_header);

    // Print the DNS identifier
    std::cout << "Identifier: 0x" << std::hex << dns_identifier << std::dec << std::endl;

    // Extract the flags from the DNS header (it's 16 bits starting at byte 2)
    uint16_t flags = ntohs(*(uint16_t *)(dns_header + 2));

    uint8_t qr = (flags >> 15) & 0x01;     // QR: 1 bit
    uint8_t opcode = (flags >> 11) & 0x0F; // Opcode: 4 bits
    uint8_t aa = (flags >> 10) & 0x01;     // AA: 1 bit
    uint8_t tc = (flags >> 9) & 0x01;      // TC: 1 bit
    uint8_t rd = (flags >> 8) & 0x01;      // RD: 1 bit
    uint8_t ra = (flags >> 7) & 0x01;      // RA: 1 bit
    uint8_t ad = (flags >> 5) & 0x01;      // AD: 1 bit
    uint8_t cd = (flags >> 4) & 0x01;      // CD: 1 bit
    uint8_t rcode = flags & 0x0F;          // RCODE: 4 bits

    // Print the flags
    std::cout << "Flags: QR=" << (int)qr << ", OPCODE=" << (int)opcode << ", AA=" << (int)aa << ", TC=" << (int)tc
              << ", RD=" << (int)rd << ", RA=" << (int)ra << ", AD=" << (int)ad << ", CD=" << (int)cd << ", RCODE=" << (int)rcode
              << std::endl << std::endl;

    return dns_header;
}
