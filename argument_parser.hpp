/*
 * Program: DNS monitor
 * Description: Header file for argument_parser.cpp
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#ifndef ARGUMENT_PARSER_CPP
#define ARGUMENT_PARSER_CPP

#include <iostream>
#include <string.h>
#include "stdio.h"
#include "stdlib.h"
#include <csignal>
#include <cstring>

/**
 * @class parser
 * @brief Class responsible for parsing command-line arguments and storing those informations.
 */
class parser 
{
    public:
        /**
         * @brief The network interface to be used for live packet sniffing.
         */
        std::string interface;

        /**
         * @brief The pcap file to be processed for offline packet analysis.
         */
        std::string pcap;

        /**
         * @brief A flag indicating whether verbose mode is enabled.
         */
        bool verbose = false;

        /**
         * @brief The path to the file where domain names are stored.
         */
        std::string domains_file;

        /**
         * @brief The path to the file where translation mappings are stored.
         */
        std::string translations_file;

        /**
         * @brief File pointer for the domain names file.
         */
        FILE *domain = nullptr;

        /**
         * @brief File pointer for the translation file.
         */
        FILE *translation = nullptr;

        /**
         * @brief Parses command-line arguments and sets atributes.
         * @param argc The number of arguments passed to the program.
         * @param argv The array of arguments passed to the program.
         */
        void parse_arguments(int argc, char* argv[]);
};

#endif
