#include "stdio.h"
#include "stdlib.h"
#include "argument_parser.hpp"
#include "packet_capturing.hpp"

int main(int argc, char* argv[])
{
    parser parse;
    
    parse.parse_arguments(argc,argv);

    Sniffer network_sniffer;

    network_sniffer.run_sniffer(parse);
    
    exit(0);
}