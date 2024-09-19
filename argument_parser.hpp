#ifndef ARGUMENT_PARSER_CPP
#define ARGUMENT_PARSER_CPP

#include <iostream>
#include <string.h>

class parser {

    public:
        std::string interface = "";
        std::string pcap = "";
        bool verbose = false;
        std::string domains_file = "";
        std::string translations_file = "";

    public:
        void parse_arguments(int argc, char* argv[]);
};

#endif