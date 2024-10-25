/*
 * Program: DNS monitor
 * Description: Header file for utils.cpp
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>    
#include <string>       
#include <cstdint>     
#include <cstring>      
#include <sstream>
#include <arpa/inet.h>
#include <iomanip>
#include "argument_parser.hpp"
#include <sys/socket.h> // Pridané pre definíciu AF_INET a AF_INET6

/**
 * @class Utils
 * @brief Utility class that provides various helper functions for DNS packet processing.
 */
class Utils
{
    public:
        /**
         * @brief Signal handler.
         * @param pid The process ID or signal number received.
         */
        static void sigint_handle(int pid);

        /**
         * @brief Signal handler for SIGSEGV.
         * This function is called when the program encounters a segmentation fault.
         * @param sig The signal number.
         */
        static void segfault_handle(int sig);

        /**
         * @brief Retrieves the class type as a string based on the DNS query class.
         * @param q_class The query class as a 16-bit unsigned integer.
         * @return A string representing the class type (e.g., "IN" for Internet).
         */
        std::string get_class_type(uint16_t q_class);

        /**
         * @brief Retrieves the record type as a string based on the DNS query type.
         * @param q_type 16 bit intiger that represents type.
         * @return Record type.
         */
        std::string get_record_type(uint16_t q_type);

        /**
         * @brief Processes and writes the RDATA (resource data) section of a DNS record to a file.
         * 
         * @param name The domain name.
         * @param a_ttl The Time to Live.
         * @param a_class The DNS class.
         * @param a_type The DNS record.
         * @param rdata_ptr A pointer to the start of the RDATA section in the DNS packet.
         * @param frame A pointer to the start of the network frame containing the DNS packet.
         * @param utility_functions Reference to the utility functions for helping functions.
         * @param parse Pointer to parser that has information given from user.
         * @param file File where data will be extracted in case of -d or -t parameter.
         */
        void parse_rdata_and_print(std::string name, uint32_t a_ttl, uint16_t a_class, uint16_t a_type, const u_char *rdata_ptr, const u_char *frame, Utils &utility_functions, parser *parse, FILE *file);

        /**
         * @brief Function for parsing domain name as well as adress and domain in rdata.
         * 
         * @param beginning_of_section Pointer to beggining of specific section (name,..).
         * @param packet_start A pointer to the start of the DNS packet (After header).
         * @return Pair of processed data (mail-server, name, adress) and its lenght.
         */
        std::pair<std::string, int> parse_data(const u_char *beginning_of_section, const u_char *packet_start);

        /**
         * @brief Adds string to file.
         * 
         * @param file File pointer where the data will be printed.
         * @param str String that will be printed.
         */
        void add_string_to_file(FILE *file, std::string str);

    private:
        /**
         * @brief Checks if string already exists in file.
         * 
         * @param file The file pointer to search within.
         * @param name The string to search for in the file.
         * @return True or false.
         */
        bool name_exists_in_file(FILE *file, const std::string &name);

        /**
         * @brief Calculates the length of the data that will be used for parsing in parse_auth_info.
         * 
         * @param beginning_of_section A pointer to the beginning of parsed data.
         * @return The length of the domain name in bytes.
         */
        int get_domain_name_length(const u_char *beginning_of_section);

        /**
         * @brief Remove . at the end of name.
         * 
         * @param domain String which is goin to be striped off . at the end.
         * @return Domain name without .
         */
        std::string remove_trailing_dot(const std::string& domain); 
        /**
         * @brief Removes leading and trailing whitespace from a string.
         * 
         * @param str The string to trim.
         * @return String without whitespaces.
         */
        std::string trim(const std::string& str);
};

#endif
