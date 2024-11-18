/*
 * Program: DNS monitor
 * Description: Implementation of methods for Terminators class.
 * Author: Matúš Janek
 * Date: 26.09.2024
 */

#include "terminators.hpp"

// Global parser pointer for cleanup
extern parser* global_parser;

// Function for capturing terminators
void Terminators::sigint_handle(int pid)
{
    (void)pid;
    // Check if handle is different from null, if yes then break the loop.
    if (Sniffer::hanlder_for_dealoc != nullptr) 
    {
        pcap_breakloop(Sniffer::hanlder_for_dealoc);
    }
    // Check if bpf_prog_for_dealoc is different from null, if yes then dealloc.
    if (Sniffer::bpf_prog_for_dealoc != nullptr) 
    {
        pcap_freecode(Sniffer::bpf_prog_for_dealoc);
        Sniffer::bpf_prog_for_dealoc = nullptr;
    }
    // Check if hanlder_for_dealoc is different from null, if yes then dealloc.
    if (Sniffer::hanlder_for_dealoc != nullptr) 
    {
        pcap_close(Sniffer::hanlder_for_dealoc);
        Sniffer::hanlder_for_dealoc = nullptr;
    }

     // Close any open files in the global parser
    if (global_parser != nullptr) 
    {
        if (global_parser->domain) 
        {
            fclose(global_parser->domain);
            global_parser->domain = nullptr;
        }
        if (global_parser->translation) 
        {
            fclose(global_parser->translation);
            global_parser->translation = nullptr;
        }
    }

    exit(0);
}

// Function to handle segmentation fault
void Terminators::segfault_handle(int sig)
{
    (void)sig;
    // Check if handle is different from null, if yes then break the loop.
    if (Sniffer::hanlder_for_dealoc != nullptr) 
    {
        pcap_breakloop(Sniffer::hanlder_for_dealoc);
    }
    // Check if bpf_prog_for_dealoc is different from null, if yes then dealloc.
    if (Sniffer::bpf_prog_for_dealoc != nullptr) 
    {
        pcap_freecode(Sniffer::bpf_prog_for_dealoc);
        Sniffer::bpf_prog_for_dealoc = nullptr;
    }
    // Check if hanlder_for_dealoc is different from null, if yes then dealloc.
    if (Sniffer::hanlder_for_dealoc != nullptr) 
    {
        pcap_close(Sniffer::hanlder_for_dealoc);
        Sniffer::hanlder_for_dealoc = nullptr;
    }

    // Close any open files in the global parser
    if (global_parser != nullptr) 
    {
        if (global_parser->domain) 
        {
            fclose(global_parser->domain);
            global_parser->domain = nullptr;
        }
        if (global_parser->translation) 
        {
            fclose(global_parser->translation);
            global_parser->translation = nullptr;
        }
    }
    
    std::cerr << "Unexpected error occured" << std::endl;
    exit(EXIT_FAILURE);
}