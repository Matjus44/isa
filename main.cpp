#include "argument_parser.hpp"
#include "packet_capturing.hpp"

int main(int argc, char* argv[]) 
{
    parser parse;
    parse.parse_arguments(argc,argv);

    Sniffer network_sniffer;

    if(parse.domains_file != "")
    {
        parse.domain = fopen(parse.domains_file.c_str(), "a+");
        if (!parse.domain) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.domains_file << std::endl;
        }
    }
    if(parse.translations_file != "")
    {
        parse.translation = fopen(parse.translations_file.c_str(), "a+");
        if (!parse.translation) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.translation << std::endl;
        }
    }
    if(parse.interface != "") 
    {
        network_sniffer.run_sniffer(parse);
    } 
    else if(parse.pcap != "")
    {
        network_sniffer.run_pcap(parse);
    } 
    else
    {
        exit(EXIT_FAILURE);
    }

    exit(0);
}