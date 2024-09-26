#include "packet_processing.hpp"

void PacketProcessing::parse_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    // Cast the user parameter back to a parser object
    parser *parse = reinterpret_cast<parser *>(user);
    print_timestamp(header, parse);
    print_ip(frame, parse);
    print_information(frame, parse);
}

void PacketProcessing::print_timestamp(const struct pcap_pkthdr *header, parser *parse)
{
    char buffer[80];
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    std::string timestamp = std::string(buffer);
    parse->verbose ? std::cout << "Timestamp: " << timestamp << std::endl : std::cout << timestamp << " ";
}

void PacketProcessing::print_ip(const u_char *frame, parser *parse)
{
    const u_char *ip_frame = frame + 14; 

    char src_ip[INET6_ADDRSTRLEN] = {0};
    char dst_ip[INET6_ADDRSTRLEN] = {0};

    uint8_t ip_version = (ip_frame[0] >> 4); 

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
        std::cout << "SrcIP: " << src_ip << " -> " << "DstIP: " << dst_ip << " ";
    }
}

void PacketProcessing::process_ipv4_port(const u_char *frame)
{
    auto ip4 = reinterpret_cast<const struct ip *>(frame + sizeof(struct ether_header));
    const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + (ip4->ip_hl * 4));
    std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
    std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
    
}

void PacketProcessing::process_ipv6_port(const u_char *frame)
{
    const struct udphdr *udp_header = reinterpret_cast<const struct udphdr *>(frame + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
    std::cout << "SrcPort: UDP/" << ntohs(udp_header->uh_sport) << std::endl;
    std::cout << "DstPort: UDP/" << ntohs(udp_header->uh_dport) << std::endl;
    
}

void PacketProcessing::print_information(const u_char *frame, parser *parse)
{
    const struct ether_header *eth_header = reinterpret_cast<const struct ether_header *>(frame);
    // Get the Ethernet type
    auto ether_type = ntohs(eth_header->ether_type);

    // Check the Ethernet type and print corresponding information
    if (ether_type == ETHERTYPE_IP && parse->verbose == true)
    {
        process_ipv4_port(frame);
    }
    else if (ether_type == ETHERTYPE_IPV6 && parse->verbose == true)
    {
        process_ipv6_port(frame);
    }

    auto result = print_identifier_and_flags(frame, ether_type, parse);
    print_dns_information(frame,result.first,parse,result.second);
}

std::pair<const u_char*, uint8_t> PacketProcessing::print_identifier_and_flags(const u_char *frame, uint16_t type, parser *parse)
{
    const u_char *dns_header;

    // Skip the Ethernet header 
    const u_char *ip_frame = frame + 14;

    if (type == ETHERTYPE_IP)
    {
        const struct ip *ip_header = (struct ip *)ip_frame;
        int ip_header_len = ip_header->ip_hl * 4; // ip_hl is in 4-byte words
        int udp_header_len = 8;                   // UDP header length is always 8 bytes
        dns_header = ip_frame + ip_header_len + udp_header_len;
    }
    else if (type == ETHERTYPE_IPV6)
    {
        int ip6_header_len = 40; // IPv6 header is always 40 bytes
        int udp_header_len = 8;  // UDP header length is always 8 bytes
        dns_header = ip_frame + ip6_header_len + udp_header_len;
    }

    uint16_t flags = ntohs(*(uint16_t *)(dns_header + 2));
    uint8_t qr = (flags >> 15) & 0x01;     // QR: 1 bit

    if(parse->verbose)
    {
        uint16_t dns_identifier = ntohs(*(uint16_t *)dns_header);
        uint8_t opcode = (flags >> 11) & 0x0F; // Opcode: 4 bits
        uint8_t aa = (flags >> 10) & 0x01;     // AA: 1 bit
        uint8_t tc = (flags >> 9) & 0x01;      // TC: 1 bit
        uint8_t rd = (flags >> 8) & 0x01;      // RD: 1 bit
        uint8_t ra = (flags >> 7) & 0x01;      // RA: 1 bit
        uint8_t ad = (flags >> 5) & 0x01;      // AD: 1 bit
        uint8_t cd = (flags >> 4) & 0x01;      // CD: 1 bit
        uint8_t rcode = flags & 0x0F;          // RCODE: 4 bits
        
        std::cout << "Identifier: 0x" << std::hex << std::setw(4) << std::setfill('0') << dns_identifier << std::dec << std::endl;
        std::cout << "Flags: QR=" << (int)qr << ", OPCODE=" << (int)opcode << ", AA=" << (int)aa << ", TC=" << (int)tc
                << ", RD=" << (int)rd << ", RA=" << (int)ra << ", AD=" << (int)ad << ", CD=" << (int)cd << ", RCODE=" << (int)rcode
                << std::endl;
    }
    return std::make_pair(dns_header, qr);
}

void PacketProcessing::print_dns_information(const u_char *frame, const u_char *pointer, parser *parse, uint8_t qr )
{
    Utils utility_functions;
    uint16_t qd_count = ntohs(*(uint16_t *)(pointer + 4));  // specifying the number of entries in the question section.
    uint16_t an_count = ntohs(*(uint16_t *)(pointer + 6));  // specifying the number of resource records in the answer section.
    uint16_t ns_count = ntohs(*(uint16_t *)(pointer + 8));  // specifying the number of name server resource records in the authority records section.
    uint16_t ar_count = ntohs(*(uint16_t *)(pointer + 10)); // specifying the number of resource records in the additional records section
    if(!parse->verbose)
    {
        char qr_char = (qr == 0) ? 'Q' : 'R';
        std::cout << "(" <<  qr_char  << " " << an_count << "/" << qd_count << "/" << ns_count << "/" << ar_count << ")" << std::endl;
    }

    const u_char* next_section = nullptr;
    if(qd_count != 0)
    {
        next_section = print_question_sections(pointer + 10, utility_functions, frame, qd_count, parse);
    }
    if(an_count != 0)
    {
        next_section = print_other_sections(next_section,utility_functions,pointer+ 10,an_count,"[Answer Section]", parse);
    }
    if(ns_count != 0)
    {
        next_section = print_other_sections(next_section,utility_functions,pointer + 10,ns_count, "[Authority Section]", parse);
    }
    if(ar_count != 0)
    {
        print_other_sections(next_section,utility_functions,pointer + 10,ar_count, "[Additional Section]", parse);
    }

    if(parse->verbose)
    {
        std::cout << "=====================================" << std::endl;
    }
}

const u_char * PacketProcessing::print_question_sections(const u_char *question_pointer, Utils &utility_functions, const u_char *frame, uint16_t qd_count, parser *parse)
{
    const u_char *next_question = question_pointer;

    while(qd_count > 0 )
    {
        auto result = utility_functions.parse_auth_info(next_question + 2, frame);
        const u_char *qtype_ptr = next_question + result.second;
        uint16_t q_type = ntohs(*(uint16_t *)(qtype_ptr + 2));
        uint16_t q_class = ntohs(*(uint16_t *)(qtype_ptr + 4));

        std::string type_str = utility_functions.get_record_type(q_type);
        std::string class_str = utility_functions.get_class_type(q_class);

        if(parse->verbose && utility_functions.get_record_type(q_type) != "Unknown")
        {
            std::cout << std::endl;
            std::cout << "[Question Section]" << std::endl;
            std::cout << result.first << " " << class_str << " " << type_str << std::endl;
        }

        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(parse->domain,result.first);
        }

        next_question = qtype_ptr + 6;
        qd_count = qd_count - 1;
    }

    const u_char *answer_pointer = next_question;
    return answer_pointer;
}


const u_char * PacketProcessing::print_other_sections(const u_char *answer_pointer, Utils &utility_functions, const u_char *question_pointer, uint16_t count, std::string section_type, parser *parse)
{   
    const u_char *local_pointer = answer_pointer;
    const u_char * authority_pointer = nullptr;
    int lenght = 0;
    bool first_loop = false;

    while(count > 0)
    {
        auto result2 = utility_functions.parse_auth_info(local_pointer, question_pointer -10);
        lenght = result2.second;
        uint16_t a_type = ntohs(*(uint16_t *)(local_pointer + lenght));
        uint16_t a_class = ntohs(*(uint16_t *)(local_pointer + lenght + 2));
        uint32_t a_ttl = ntohl(*(uint32_t *)(local_pointer + lenght + 4));
        uint16_t a_lenght = ntohs(*(uint16_t *)(local_pointer + lenght + 8));
        
        if(utility_functions.get_record_type(a_type)  != "Unknown")
        {
            if(first_loop == false && parse->verbose == true)
            {
                std::cout << std::endl;
                std::cout << section_type << std::endl;
                first_loop = true;
            }
            const u_char* data_pointer = local_pointer + lenght + 10;
            utility_functions.get_rdata_string(result2.first,a_ttl,a_class,a_type,data_pointer,  question_pointer - 10,utility_functions, parse , parse->domain);
        }

        local_pointer = local_pointer + a_lenght + 12;
        count = count - 1;
    }

    authority_pointer = local_pointer;
    return authority_pointer;
}