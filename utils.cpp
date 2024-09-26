#include "utils.hpp"

// Print the entire section in hexadecimal
    // std::cout << "Hex dump of the section: ";
    // for (const u_char *ptr = beginning_of_section; *ptr != 0; ++ptr)
    // {
    //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)*ptr << " ";
    // }

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

void Utils::get_rdata_string(std::string name,uint32_t a_ttl,uint16_t a_class,uint16_t a_type,const u_char *rdata_ptr, const u_char *frame, Utils &utility_functions, parser *parse, FILE* file)
{
    std::stringstream rdata_stream;
    const u_char * local_pointer = rdata_ptr;

    if (a_type == 1)  // Type A (IPv4)
    {
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, rdata_ptr, ipv4, INET_ADDRSTRLEN);
        rdata_stream << ipv4;
        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << std::hex << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type)  << " " << rdata_stream.str() << std::endl;
        }

        if(parse->domains_file != "")
        {
            utility_functions.add_string_to_file(file,name);
        }
    }
    else if (a_type == 28)  // Type AAAA (IPv6)
    {
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, rdata_ptr, ipv6, INET6_ADDRSTRLEN);
        rdata_stream << ipv6;

        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << std::hex << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type)  << " " << rdata_stream.str() << std::endl;
        }

        if(parse->domains_file != "")
        {
            utility_functions.add_string_to_file(file,name);
        }
    }
    else if(a_type == 15) // MX
    {
        uint16_t preference = ntohs(*(uint16_t *)(local_pointer));
        auto domain_name_and_length = parse_auth_info(local_pointer + 2, frame); 
        rdata_stream << domain_name_and_length.first;

        if(rdata_stream.str() == "") // Check for root
        {
            rdata_stream << "<root>";
        }

        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << std::hex << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type) << " " <<  std::dec << preference << std::hex << " " << rdata_stream.str() << std::endl;
        }

        if(parse->domains_file != "")
        {
            if(rdata_stream.str() != "<root>")
            {
                utility_functions.add_string_to_file(file,rdata_stream.str());
            }
            utility_functions.add_string_to_file(file,name);
        }
        
    }
    else if (a_type == 5 || a_type == 2)  // CNAME, NS 
    {
        auto domain_name_and_length = parse_auth_info(rdata_ptr, frame); 
        rdata_stream << domain_name_and_length.first;

        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << std::hex << " " << utility_functions.get_class_type(a_class)  << " " << utility_functions.get_record_type(a_type) << " " << rdata_stream.str() << std::endl;
        }

        if(parse->domains_file != "")
        {
            utility_functions.add_string_to_file(file,name);
            utility_functions.add_string_to_file(file,rdata_stream.str());
        }
    }
    else if(a_type == 6) // SOA
    {
        auto mname_result = utility_functions.parse_auth_info(local_pointer, frame);
        int mname_length = mname_result.second;
        std::string mname = mname_result.first;

        local_pointer = local_pointer + mname_length;

        auto mname_result2 = utility_functions.parse_auth_info(local_pointer, frame);
        int mname_length_2 = mname_result2.second;
        std::string mname2 = mname_result2.first;

        local_pointer = local_pointer + mname_length_2;

        uint32_t serial_number = ntohl(*(uint32_t *)(local_pointer));
        uint32_t refresh_interval = ntohl(*(uint32_t *)(local_pointer + 4));
        uint32_t retry_interval = ntohl(*(uint32_t *)(local_pointer + 8));
        uint32_t expire_limit = ntohl(*(uint32_t *)(local_pointer + 12));
        uint32_t minimum = ntohl(*(uint32_t *)(local_pointer + 16));

        if(name == "") // check for roots
        {
            name = "<root>";
        }

        if(parse->domains_file != "")
        {
            if(name != "<root>")
            {
                utility_functions.add_string_to_file(file,name);
            }
            utility_functions.add_string_to_file(file,mname);
            utility_functions.add_string_to_file(file,mname2);
        }

        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << " IN " << utility_functions.get_record_type(a_type) << " " << mname << " " << mname2 << " (" << std::endl;
            std::cout << "    " << serial_number << " ; Serial" << std::endl;
            std::cout << "    " << refresh_interval << " ; Refresh" << std::endl;
            std::cout << "    " << retry_interval << " ; Retry" << std::endl;
            std::cout << "    " << expire_limit << " ; Expire" << std::endl;
            std::cout << "    " << minimum << " ; Minimum TTL" << std::endl;
            std::cout << ")" << std::endl;
        }
    }
    else if (a_type == 33)  // SRV
    {
        uint16_t priority = ntohs(*(uint16_t *)(local_pointer));
        uint16_t weight = ntohs(*(uint16_t *)(local_pointer + 2));
        uint16_t port = ntohs(*(uint16_t *)(local_pointer + 4));

        auto target_result = utility_functions.parse_auth_info(local_pointer + 6, frame);
        std::string target = target_result.first;

        if(parse->domains_file != "")
        {
            utility_functions.add_string_to_file(file,name);
            utility_functions.add_string_to_file(file,target);
        }

        if(parse->verbose)
        {
            std::cout << name << " " << std::dec << a_ttl << std::hex << " " 
                    << utility_functions.get_record_type(a_type) << " " 
                    << utility_functions.get_class_type(a_class) << " " 
                    << std::dec << priority << " " 
                    << weight << " " 
                    << port << " " 
                    << target << std::endl;
        }
    }
    else
    {
        rdata_stream << "Not supported record type";
    }

    
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

std::string Utils::trim(const std::string& str) 
{
    size_t first = str.find_first_not_of(' ');
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

bool Utils::name_exists_in_file(FILE *file, const std::string &name) 
{
    char line[500];

    rewind(file);

    while (fgets(line, sizeof(line), file)) 
    {
        line[strcspn(line, "\r\n")] = 0;
        std::string fileLine = line;

        if (fileLine == trim(name)) 
        {
            return true; 
        }
    }
    return false; 
}

void Utils::add_string_to_file(FILE *file, std::string str) 
{
    if (file == nullptr) 
    {
        std::cerr << "Error: file pointer is null!" << std::endl;
        return;
    }
    // Check if the name is already in the file
    if (!name_exists_in_file(file, str)) 
    {
        // Move to the end of the file to append the new str
        fputs((str + "\n").c_str(), file);
        fflush(file); // Ensure the name is written to the file immediately
    }
}