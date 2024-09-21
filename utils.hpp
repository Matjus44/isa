#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>    
#include <string>       
#include <cstdint>     
#include <cstring>      
#include <sstream>
#include <arpa/inet.h>
#include <iomanip>

class Utils
{
    public:
        std::string get_class_type(uint16_t q_class);
        std::string get_record_type(uint16_t q_type);
        std::string parse_domain_name(const u_char *pointer, const u_char *frame);
        std::string get_rdata_string(const u_char *rdata_ptr, uint16_t a_length, uint16_t a_type);
};

#endif