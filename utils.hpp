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

class Utils
{
    public:
        std::string get_class_type(uint16_t q_class);
        std::string get_record_type(uint16_t q_type);
        void get_rdata_string(std::string name,uint32_t a_ttl,uint16_t a_class,uint16_t a_type,const u_char *rdata_ptr, const u_char *frame, Utils utility_functions, parser *parse);
        std::pair<std::string, int> parse_auth_info(const u_char *beginning_of_section, const u_char *packet_start);
        
    private:
        bool string_exists_in_file(FILE *file, const std::string &str);
        int get_domain_name_length(const u_char *beginning_of_section);
        void add_string_to_file(FILE *file, const std::string &str); 
};

#endif