/*
 * Program: DNS monitor
 * Description: Implementation of methods for Parse class.
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#include "argument_parser.hpp"

int parser::parse_arguments(int argc, char *argv[])
{
    if (argc == 2 && std::string(argv[1]) == "-help")
    {
        std::cout << "./dns-monitor (-i <interface> | -p <pcapfile>) [-v] [-d <domainsfile>] [-t <translationsfile>]\n";
        std::cout << "Parametry:\n";
        std::cout << "-i <interface> - název rozhraní, na kterém bude program naslouchat, nebo\n";
        std::cout << "-p <pcapfile> - název souboru PCAP, který program zpracuje;\n";
        std::cout << "-v - režim \"verbose\": kompletní výpis detailů o zprávách DNS;\n";
        std::cout << "-d <domainsfile> - název souboru s doménovými jmény;\n";
        std::cout << "-t <translationsfile> - název souboru s překladem doménových jmen na IP.\n";
        return 0;
    }

    for (int i = 1; i < argc; i++)
    {
        std::string arg = argv[i];

        if (arg == "-i" && i + 1 < argc && interface.empty() && pcap.empty())   // Interface
        {
            interface = argv[++i];  // Add into atribute
        }
        else if (arg == "-p" && i + 1 < argc && interface.empty() && pcap.empty())  // PCAP
        {
            pcap = argv[++i];
        }
        else if (arg == "-v" && verbose == false)  // Verbous
        {
            verbose = true; 
        }
        else if (arg == "-d" && i + 1 < argc && domains_file.empty())  // File for storing domains names
        {
            domains_file = argv[++i];
        }
        else if (arg == "-t" && i + 1 < argc && translations_file.empty())  // File for storing domains names with their adress
        {
            translations_file = argv[++i];
        }
        else
        {
            std::cerr << "Unknown argument: " << arg << std::endl;
            return 1;
        }
    }

    // If none of the interface or pcap is in input then exit with and error message
    if (interface.empty() && pcap.empty())
    {
        std::cerr << "Error: Either interface (-i) or pcap file (-p) must be specified." << std::endl;
        return 1;
    }

    return 0;
}

