#include "utils.hpp"

std::string Utils::parse_domain_name(const u_char *pointer, const u_char *packet_start)
{
    std::string domain_name;
    const u_char *current_ptr = pointer;
    
    // Debug: Print raw bytes in hexadecimal format before parsing
    std::cout << "Raw domain name bytes in hex: ";
    while (*current_ptr != 0)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)(*current_ptr) << " ";
        current_ptr++;
    }
    std::cout << "00" << std::endl; // Print the null terminator (0x00) for clarity

    // Reset the pointer to start parsing the domain name
    current_ptr = pointer;
    
    bool is_compressed = false; // Flag to check if name is compressed
    while (*current_ptr != 0)
    {
        if ((*current_ptr & 0xC0) == 0xC0)
        {
            // Handle compressed name
            uint16_t offset = ntohs(*(uint16_t *)current_ptr) & 0x3FFF; // Extract the 14-bit offset
            current_ptr = packet_start + offset; // Jump to the offset within the packet
            is_compressed = true;

            // Parse the domain name at the new location
            domain_name.append(parse_domain_name(current_ptr, packet_start));
            break; // Stop after compression is resolved
        }
        else
        {
            int label_length = *current_ptr; // First byte is the length of the label
            current_ptr++;

            domain_name.append((const char *)current_ptr, label_length);
            current_ptr += label_length;

            if (*current_ptr != 0)  // Add a dot if this is not the end of the name
            {
                domain_name.append(".");
            }
        }
    }

    // If it was a compressed name, just return the parsed result
    if (is_compressed)
    {
        return domain_name;
    }

    return domain_name;
}

std::string Utils::get_record_type(uint16_t q_type)
{
    switch (q_type)
    {
        case 1:
            return "A";       // IPv4 Address
        case 28:
            return "AAAA";    // IPv6 Address
        case 2:
            return "NS";      // Name Server
        case 5:
            return "CNAME";   // Canonical Name
        case 15:
            return "MX";      // Mail Exchange
        case 6:
            return "SOA";     // Start of Authority
        case 33:
            return "SRV";     // Service
        default:
            return "Unknown";
    }
}

std::string Utils::get_class_type(uint16_t q_class)
{
    switch (q_class)
    {
        case 1:
            return "IN";       // Internet
        case 3:
            return "CH";       // Chaosnet
        case 4:
            return "HS";       // Hesiod
        case 255:
            return "ANY";      // Wildcard
        default:
            return "Unknown";
    }
}

std::string Utils::get_rdata_string(const u_char *rdata_ptr, uint16_t a_length, uint16_t a_type)
{
    std::stringstream rdata_stream;

    if (a_type == 1)  // Type A (IPv4)
    {
        // Convert RDATA from binary to a human-readable IPv4 address
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, rdata_ptr, ipv4, INET_ADDRSTRLEN);
        rdata_stream << ipv4;
    }
    else if (a_type == 28)  // Type AAAA (IPv6)
    {
        // Convert RDATA from binary to a human-readable IPv6 address
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, rdata_ptr, ipv6, INET6_ADDRSTRLEN);
        rdata_stream << ipv6;
    }
    else
    {
        // If it's not an IP address, just return the raw RDATA in hexadecimal
        for (int i = 0; i < a_length; ++i)
        {
            rdata_stream << std::hex << std::setw(2) << std::setfill('0') << (int)rdata_ptr[i];
            if (i < a_length - 1)
            {
                rdata_stream << " ";
            }
        }
    }
    return rdata_stream.str();  // Return the final RDATA string
}
