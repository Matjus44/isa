#include "stdio.h"
#include "stdlib.h"
#include "argument_parser.hpp"
#include "packet_capturing.hpp"

int main(int argc, char* argv[]) 
{
    parser parse;
    parse.parse_arguments(argc,argv);

    Sniffer network_sniffer;
    
    if(parse.interface != "") 
    {
        network_sniffer.run_sniffer(parse);
    } 
    else if(parse.pcap != "")
    {
        network_sniffer.run_pcap(parse);
    } 
    else
    {
        exit(EXIT_FAILURE);
    }

    exit(0);
}