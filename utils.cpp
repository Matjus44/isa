#include "utils.hpp"

std::string Utils::parse_domain_name(const u_char *pointer)
{
    std::string domain_name;
    const u_char *current_ptr = pointer;

    while (*current_ptr != 0)
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