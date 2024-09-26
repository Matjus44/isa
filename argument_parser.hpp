#ifndef ARGUMENT_PARSER_CPP
#define ARGUMENT_PARSER_CPP

#include <iostream>
#include <string.h>
#include "stdio.h"
#include "stdlib.h"

class parser 
{
    public:
        std::string interface = "";
        std::string pcap = "";
        bool verbose = false;
        std::string domains_file = "";
        std::string translations_file = "";
        FILE *domain = nullptr;

    public:
        void parse_arguments(int argc, char* argv[]);
};

#endif