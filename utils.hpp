#ifndef UTILS_HPP
#define UTILS_HPP

#include <iostream>    
#include <string>       
#include <cstdint>     
#include <cstring>      

class Utils
{
    public:
        std::string get_class_type(uint16_t q_class);
        std::string get_record_type(uint16_t q_type);
        std::string parse_domain_name(const u_char *pointer);
};

#endif