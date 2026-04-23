#pragma once
#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>
#include "pcap_reader.h"
#include "utils.h"

namespace stats {

    using LengthCounts = std::map<uint32_t, uint32_t>;
    using MacPairCounts = std::unordered_map<std::string, uint32_t>;
    using EtherTypeCounts = std::unordered_map<uint16_t, uint32_t>;
    class PacketStats {
    public:
        void add_packet(const pcap::Packet& pkt, const uint32_t linktype);
        void print() const;
        EtherTypeCounts get_ethertype_stats () const;
    private:
        LengthCounts length_counts_;
        MacPairCounts mac_pair_counts_;
        EtherTypeCounts ethertype_counts_;
    };

    void print_length_stats(const LengthCounts& counts);

    std::vector<std::pair<uint32_t, uint32_t>> sort_by_count(const std::map<uint32_t, uint32_t>& counts);

    void print_mac_pair_stats(const MacPairCounts& counts);

    void print_ethertype_stats(const EtherTypeCounts& counts);

    void print_checksum_stats(const uint32_t correct, const uint32_t total);

}
