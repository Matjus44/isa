#include "argument_parser.hpp"

void parser::parse_arguments(int argc, char *argv[])
{

    for (int i = 1; i < argc; i++)
    {

        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc && pcap.empty() && interface.empty())
        {
            interface = argv[++i];
        }
        else if (arg == "-r" && i + 1 < argc && interface.empty() && pcap.empty())
        {
            pcap = argv[++i];
        }
        else if (arg == "-v")
        {
            verbose = true;
        }
        else if (arg == "-d" && i + 1 < argc)
        {
            domains_file = argv[++i];
        }
        else if (arg == "-t" && i + 1 < argc)
        {
            translations_file = argv[++i];
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << std::endl;
            exit(1);
        }
    }
}
