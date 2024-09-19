#include "packet_processing.hpp"

void PacketProcessing::parse_frame(u_char *user, const struct pcap_pkthdr *header, const u_char *frame)
{
    (void) user;
    (void) frame;
    print_timestamp(header);
}

void PacketProcessing::print_timestamp(const struct pcap_pkthdr *header)
{
    time_t timer = header->ts.tv_sec;
    struct tm *timeinfo = localtime(&timer);

    // Buffer for storing
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%S", timeinfo);
    char tzbuffer[6];
    strftime(tzbuffer, sizeof(tzbuffer), "%z", timeinfo);
    std::string tzformatted = std::string(tzbuffer).insert(3, ":");
    std::string timestamp = std::string(buffer) + tzformatted;
    std::cout << "timestamp: " << timestamp << std::endl;
}
