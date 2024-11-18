/*
 * Program: DNS monitor
 * Description: Implementation of methods from Terminators class.
 * Author: Matúš Janek (237464)
 * Date: 26.09.2024
 */

#ifndef TERMINATORS_HPP
#define TERMINATORS_HPP

#include "packet_capturing.hpp"
#include "argument_parser.hpp"

/**
 * @class Terminators
 * @brief Class with static methods that are used when
 * any terminators are detected for cleaning memory
 */
class Terminators
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
};

#endif