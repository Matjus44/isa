#include "argument_parser.hpp"
#include "packet_capturing.hpp"

int main(int argc, char* argv[]) 
{
    parser parse;
    parse.parse_arguments(argc,argv);

    Sniffer network_sniffer;

    if(!parse.domains_file.empty())
    {
        parse.domain = fopen(parse.domains_file.c_str(), "a+");
        if (!parse.domain) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.domains_file << std::endl;
        }
    }
    if(!parse.translations_file.empty())
    {
        parse.translation = fopen(parse.translations_file.c_str(), "a+");
        if (!parse.translation) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.translation << std::endl;
        }
    }
    if(!parse.interface.empty()) 
    {
        network_sniffer.run_sniffer(parse);
    } 
    else if(!parse.pcap.empty())
    {
        network_sniffer.run_pcap(parse);
    } 

    // Close the file if it was opened
    if (parse.domain)
    {
        fclose(parse.domain);
        parse.domain = nullptr; // Set the pointer to nullptr to avoid invalid access later
    }
    // Close the file if it was opened
    if (parse.translation)
    {
        fclose(parse.translation);
        parse.translation = nullptr; // Set the pointer to nullptr to avoid invalid access later
    }

    return 0;
}