#include "argument_parser.hpp"

void parser::parse_arguments(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc)  // Interface
        {
            interface = argv[++i];  // Add into atribute
        }
        else if (arg == "-r" && i + 1 < argc)  // PCAP
        {
            pcap = argv[++i];
        }
        else if (arg == "-v")  // Verbous
        {
            verbose = true; 
        }
        else if (arg == "-d" && i + 1 < argc)  // File for storing domains names
        {
            domains_file = argv[++i];
        }
        else if (arg == "-t" && i + 1 < argc)  // File for storing domains names with their adress
        {
            translations_file = argv[++i];
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << std::endl;
            exit(1);
        }
    }

    // If none of the interface or pcap is in input then exit with and error message
    if (interface.empty() && pcap.empty())
    {
        std::cerr << "Error: Either interface (-i) or pcap file (-r) must be specified." << std::endl;
        exit(1);
    }
}

