/*
 * Program: DNS monitor
 * Description: main.cpp
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#include "argument_parser.hpp"
#include "packet_capturing.hpp"
#include "terminators.hpp"

// Global parser pointer for cleanup
parser* global_parser = nullptr;

int main(int argc, char* argv[]) 
{
    // Structure for signals
    signal(SIGINT, Terminators::sigint_handle);
    signal(SIGQUIT, Terminators::sigint_handle);
    signal(SIGTERM, Terminators::sigint_handle);

    // Set up signal handler for SIGSEGV
    struct sigaction sa;
    sa.sa_handler = Terminators::segfault_handle;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV, &sa, nullptr);
    parser parse;
    global_parser = &parse; // Assign parser instance to global pointer
    int result = parse.parse_arguments(argc,argv);
    if(result != 0)
    {
        return 1;
    }

    Sniffer network_sniffer;

    // Open or create file for priting out domains names.
    if(!parse.domains_file.empty())
    {
        parse.domain = fopen(parse.domains_file.c_str(), "a+");
        if (!parse.domain) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.domains_file << std::endl;
            return 1;
        }
    }
    // Open or create file for priting out domains names with their adress.
    if(!parse.translations_file.empty())
    {
        parse.translation = fopen(parse.translations_file.c_str(), "a+");
        if (!parse.translation) 
        {
            std::cerr << "Error: Failed to open the file: " << parse.translation << std::endl;
            return 1;
        }
    }
    // If interface is not empty then we process by running live sniffer
    if(!parse.interface.empty()) 
    {
        network_sniffer.run_sniffer(parse);
    } 
    // If there is input .pcap file, then we run offline sniffer.
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