#include "argument_parser.hpp"

void parser::parse_arguments(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc)  // Argument pro rozhraní
        {
            interface = argv[++i];  // Nastav rozhraní
        }
        else if (arg == "-r" && i + 1 < argc)  // Argument pro soubor PCAP
        {
            pcap = argv[++i];  // Nastav PCAP soubor
        }
        else if (arg == "-v")  // Verbose mód
        {
            verbose = true;  // Zapni verbose mód
        }
        else if (arg == "-d" && i + 1 < argc)  // Soubor pro ukládání domén
        {
            domains_file = argv[++i];  // Nastav soubor pro domény
        }
        else if (arg == "-t" && i + 1 < argc)  // Soubor pro překlady
        {
            translations_file = argv[++i];  // Nastav soubor pro překlady
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << std::endl;
            exit(1);
        }
    }

    // Základní kontrola, že alespoň jeden z parametrů je nastaven
    if (interface.empty() && pcap.empty())
    {
        std::cerr << "Error: Either interface (-i) or pcap file (-r) must be specified." << std::endl;
        exit(1);
    }
}

