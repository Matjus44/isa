/*
 * Program: DNS monitor
 * Description: Implementation of methods for Utils class.
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#include "utils.hpp"

std::pair<std::string, int> Utils::parse_data(const u_char *beginning_of_section, const u_char *packet_start)
{
    std::string data;
    const u_char *current_ptr = beginning_of_section;
    int lenght = 0;
    int offset = 0;
    // Get lenght of data that is goin to be parsed
    lenght = get_domain_name_length(current_ptr);

    // Loop till 0 value is occured
    while (*current_ptr != 0)
    {
        // Found reference
        if ((*current_ptr & 0xC0) == 0xC0)
        {
            // Get the next byte for the offset
            offset = ((*current_ptr & 0x3F) << 8);
            current_ptr += 1;
            offset |= *current_ptr; 
            current_ptr = packet_start + offset; 
        }
        else // Append the bytes into domain_name
        {
            int label_length = *current_ptr;
            current_ptr++;
            data.append((const char *)current_ptr, label_length);
            current_ptr += label_length;
            if (*current_ptr != 0)
            {
                data.append(".");
            }
        }
    }

    // Add the final dot if it's not there yet
    if (data.back() != '.')
    {
        data.append(".");
    }
    return std::make_pair(data, lenght);
}

std::string Utils::get_record_type(uint16_t q_type)
{
    switch (q_type)
    {
        case 1:
            return "A";       // IPv4
        case 28:
            return "AAAA";    // IPv6
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
        default:
            return "Unknown";
    }
}

void Utils::parse_rdata_and_print(std::string name,uint32_t a_ttl,uint16_t a_class,uint16_t a_type,const u_char *rdata_ptr, const u_char *frame, Utils &utility_functions, parser *parse, FILE* file)
{

    std::stringstream rdata_stream;
    // Store pointer into local
    const u_char * local_pointer = rdata_ptr;

    if (a_type == 1)  // Type A (IPv4)
    {
        // Get rdata
        char ipv4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, rdata_ptr, ipv4, INET_ADDRSTRLEN);
        rdata_stream << ipv4;
        if(parse->verbose)
        {
            std::cout << name << " " <<  std::to_string(a_ttl) << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type)  << " " << rdata_stream.str() << std::endl;
        }
        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(file,name);
        }
        // If -t argument -> print into file
        if(!parse->translations_file.empty())
        {
            std::string cleaned_name = remove_trailing_dot(name);
            std::string name_and_addr = cleaned_name + " " +rdata_stream.str();
            utility_functions.add_string_to_file(parse->translation,name_and_addr);
        }
    }
    else if (a_type == 28)  // Type AAAA (IPv6)
    {
        // Get rdata
        char ipv6[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, rdata_ptr, ipv6, INET6_ADDRSTRLEN);
        rdata_stream << ipv6;

        if(parse->verbose)
        {
            std::cout << name << " " <<  std::to_string(a_ttl) << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type)  << " " << rdata_stream.str() << std::endl;
        }
        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(file,name);
        }
        // If -t argument -> print into file
        if(!parse->translations_file.empty())
        {
            std::string cleaned_name = remove_trailing_dot(name);
            std::string name_and_addr = cleaned_name + " " +rdata_stream.str();
            utility_functions.add_string_to_file(parse->translation,name_and_addr);
        }
    }
    else if(a_type == 15) // MX
    {
        // Get rdata
        uint16_t preference = ntohs(*(uint16_t *)(local_pointer));
        auto domain_name_and_length = parse_data(local_pointer + 2, frame); 
        rdata_stream << domain_name_and_length.first;

        if(parse->verbose)
        {
            std::cout << name << " " << std::to_string(a_ttl) << " " << utility_functions.get_class_type(a_class) << " " << utility_functions.get_record_type(a_type) << " " <<  std::dec << preference << std::hex << " " << rdata_stream.str() << std::endl;
        }
        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(file,name);
        }
        
    }
    else if (a_type == 5 || a_type == 2)  // CNAME, NS 
    {
        // Get rdata
        auto domain_name_and_length = parse_data(rdata_ptr, frame); 
        rdata_stream << domain_name_and_length.first;

        if(parse->verbose)
        {
            std::cout << name << " " << std::to_string(a_ttl) << " " << utility_functions.get_class_type(a_class)  << " " << utility_functions.get_record_type(a_type) << " " << rdata_stream.str() << std::endl;
        }
        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(file,name);
            if(rdata_stream.str() != ".")
            {
                utility_functions.add_string_to_file(file,rdata_stream.str());
            }
        }
    }
    else if(a_type == 6) // SOA
    {   
        auto mname_result = utility_functions.parse_data(local_pointer, frame);
        int mname_length = mname_result.second;
        std::string mname = mname_result.first;

        local_pointer = local_pointer + mname_length;

        auto mname_result2 = utility_functions.parse_data(local_pointer, frame);
        int mname_length_2 = mname_result2.second;
        std::string mname2 = mname_result2.first;

        local_pointer = local_pointer + mname_length_2;

        // Extract additional rdata
        uint32_t serial_number = ntohl(*(uint32_t *)(local_pointer));
        uint32_t refresh_interval = ntohl(*(uint32_t *)(local_pointer + 4));
        uint32_t retry_interval = ntohl(*(uint32_t *)(local_pointer + 8));
        uint32_t expire_limit = ntohl(*(uint32_t *)(local_pointer + 12));
        uint32_t minimum = ntohl(*(uint32_t *)(local_pointer + 16));

        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
             // Check whether there is legit name to add into file
            if(name != ".")
            {
                utility_functions.add_string_to_file(file,name);
            }
            if(mname != ".")
            {
                utility_functions.add_string_to_file(file,mname);
            }
        }

        if(parse->verbose)
        {
            std::cout << name << " " << std::to_string(a_ttl) << " IN " << utility_functions.get_record_type(a_type) << " " << mname << " " << mname2
            << " " << serial_number << " " << refresh_interval << " " << retry_interval << " " << expire_limit << " " << minimum << std::endl;
        }
    }
    else if (a_type == 33)  // SRV
    {
        // Extract additional information from rdata
        uint16_t priority = ntohl(*(uint16_t *)(local_pointer));
        uint16_t weight = ntohs(*(uint16_t *)(local_pointer + 2));
        uint16_t port = ntohs(*(uint16_t *)(local_pointer + 4));

        auto target_result = utility_functions.parse_data(local_pointer + 6, frame);
        std::string target = target_result.first;
        // If -d argument -> print into file
        if(!parse->domains_file.empty())
        {
            utility_functions.add_string_to_file(file,name);
            if(target != ".")
            {
                utility_functions.add_string_to_file(file,target);
            }
        }

        if(parse->verbose)
        {
            std::cout << name << " " << std::to_string(a_ttl) << " " 
                    << utility_functions.get_record_type(a_type) << " " 
                    << utility_functions.get_class_type(a_class) << " " 
                    << std::to_string(priority) << " " 
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
            // Add 2 because of reference and offset
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

std::string Utils::remove_trailing_dot(const std::string& domain) 
{
    if (!domain.empty() && domain.back() == '.') 
    {
        return domain.substr(0, domain.size() - 1);
    }
    return domain;
}

bool Utils::name_exists_in_file(FILE *file, const std::string &name) 
{
    char line[500]; // Buffer for storing data

    rewind(file);

    while (fgets(line, sizeof(line), file)) 
    {
        line[strcspn(line, "\r\n")] = 0;
        std::string fileLine = line;

        // Compare trimmed domain name without the trailing dot
        if (fileLine == trim(remove_trailing_dot(name))) 
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

    // Remove the trailing dot from the domain name
    str = remove_trailing_dot(str);

    // Check if the name is already in the file
    if (!name_exists_in_file(file, str)) 
    {
        // Move to the end of the file to append the new str
        fputs((str + "\n").c_str(), file);
        fflush(file); // Ensure the name is written to the file immediately
    }
}