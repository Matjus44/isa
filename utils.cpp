#include "utils.hpp"

// Print the entire section in hexadecimal
    // std::cout << "Hex dump of the section: ";
    // for (const u_char *ptr = beginning_of_section; *ptr != 0; ++ptr)
    // {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)*ptr << " ";
    // }

std::pair<std::string, int> Utils::parse_domain_name(const u_char *beginning_of_section, const u_char *packet_start)
{
    std::string domain_name;
    const u_char *current_ptr = beginning_of_section;
    int lenght = 0;

    bool first_reference = true;

    while (*current_ptr != 0)
    {
        if (*current_ptr == 0xc0)
        {
            const u_char *offset = current_ptr + 1;

            // Add offset with the beginning of the raw packet
            current_ptr = packet_start + *offset;
            
            if(first_reference)
            {
                lenght = lenght + 2;
                first_reference = false;
            }
        }
        else
        {
            int label_length = *current_ptr;
            current_ptr++;
            domain_name.append((const char *)current_ptr, label_length);
            current_ptr += label_length;
            if(first_reference)
            {
                lenght = lenght + label_length;
            }
            if (*current_ptr != 0)
            {
                domain_name.append(".");
            }
        }
    }

    return std::make_pair(domain_name, lenght);
}

std::pair<std::string, int> Utils::parse_auth_info(const u_char *beginning_of_section, const u_char *packet_start)
{
    std::string domain_name;
    const u_char *current_ptr = beginning_of_section;
    int lenght = 0;
    
    lenght = get_domain_name_length(current_ptr);

    while (*current_ptr != 0)
    {
        if (*current_ptr == 0xc0)
        {
            const u_char *offset = current_ptr + 1;

            // Add offset with the beginning of the raw packet
            current_ptr = packet_start + *offset;
        }
        else
        {
            int label_length = *current_ptr;
            current_ptr++;
            domain_name.append((const char *)current_ptr, label_length);
            current_ptr += label_length;
            if (*current_ptr != 0)
            {
                domain_name.append(".");
            }
        }
    }
    return std::make_pair(domain_name, lenght);
}

std::string Utils::get_record_type(uint16_t q_type)
{
    switch (q_type)
    {
        case 1:
            return "A";       // IPv4 Address SUPPORTED
        case 28:
            return "AAAA";    // IPv6 Address SUPPORTED
        case 2:
            return "NS";      // Name Server SUPPORTED (only auth section)
        case 5:
            return "CNAME";   // Canonical Name SUPPORTED
        case 15:
            return "MX";      // Mail Exchange SUPPORTED
        case 6:
            return "SOA";     // Start of Authority SUPPORTED (only auth section)
        case 33:
            return "SRV";     // Service (auth and answer section )
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

std::string Utils::get_rdata_string(std::string name,uint16_t a_lenght,uint32_t a_ttl,uint16_t a_class,uint16_t a_type,const u_char *rdata_ptr, const u_char *frame, Utils utility_functions)
{
    std::stringstream rdata_stream;
    const u_char * local_pointer = rdata_ptr;
    (void)a_lenght;

    if (a_type == 1)  // Type A (IPv4)
    {
        // Convert RDATA from binary to a human-readable IPv4 address
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, rdata_ptr, ipv4, INET_ADDRSTRLEN);
        rdata_stream << ipv4;

        std::cout << name << " " << std::dec << a_ttl << std::hex << " " <<utility_functions.get_record_type(a_type) << " " << utility_functions.get_class_type(a_class) << " " << rdata_stream.str() << std::endl;
    }
    else if (a_type == 28)  // Type AAAA (IPv6)
    {
        // Convert RDATA from binary to a human-readable IPv6 address
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, rdata_ptr, ipv6, INET6_ADDRSTRLEN);
        rdata_stream << ipv6;

        std::cout << name << " " << std::dec << a_ttl << std::hex << " " <<utility_functions.get_record_type(a_type) << " " << utility_functions.get_class_type(a_class) << " " << rdata_stream.str() << std::endl;
    }
    else if(a_type == 15)
    {
        uint16_t preference = ntohs(*(uint16_t *)(local_pointer));
        auto domain_name_and_length = parse_auth_info(local_pointer, frame); 
        rdata_stream << domain_name_and_length.first;

        std::cout << name << " " << std::dec << a_ttl << std::hex << " " << utility_functions.get_record_type(a_type) << " " << utility_functions.get_class_type(a_class) << " " <<  std::dec << preference << std::hex << " " << rdata_stream.str() << std::endl;
        
    }
    else if (a_type == 5 || a_type == 2 || a_type == 15)  // Type CNAME (5), NS (2), MX (15)
    {
        auto domain_name_and_length = parse_auth_info(rdata_ptr, frame); 
        rdata_stream << domain_name_and_length.first;

        std::cout << name << " " << std::dec << a_ttl << std::hex << " " <<utility_functions.get_record_type(a_type) << " " << utility_functions.get_class_type(a_class) << " " << rdata_stream.str() << std::endl;
    }
    else
    {
        rdata_stream << "Not supported record type";
    }

    return rdata_stream.str();  // Return the final RDATA string
}

int Utils::get_domain_name_length(const u_char *beginning_of_section)
{
    const u_char *current_ptr = beginning_of_section;
    int length = 0; 

    while (*current_ptr != 0)
    {
        if ((*current_ptr & 0xC0) == 0xC0) 
        {
            length += 2; 
            break; 
        }
        else
        {
            int label_length = *current_ptr; 
            length += label_length + 1;
            current_ptr += label_length + 1; 
        }
    }

    if ((*current_ptr & 0xC0) != 0xC0)
    {
        length += 1;
    }

    return length;
}