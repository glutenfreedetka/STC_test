#include "stats.h"
#include <iostream>
#include <algorithm>
#include "ethernet.h"
namespace stats {


    void PacketStats::add_packet(const pcap::Packet& pkt, const uint32_t linktype) {
        // длина
        length_counts_[pkt.header.orig_len]++;

        // MAC-пара
        if (ethernet::has_eth_header(pkt, linktype)) {
            auto src = ethernet::src_mac(pkt);
            auto dst = ethernet::dst_mac(pkt);
            mac_pair_counts_[ethernet::mac_pair_to_string(src, dst)]++;

            // EtherType
            uint16_t etype = ethernet::ethertype(pkt);
            if (etype != 0) {
                ethertype_counts_[etype]++;
            }
        }
    }

    void PacketStats::print() const {
        print_length_stats(length_counts_);
        print_mac_pair_stats(mac_pair_counts_);
        print_ethertype_stats(ethertype_counts_);
    }

    EtherTypeCounts PacketStats::get_ethertype_stats() const {
        return ethertype_counts_;
    }


    // вывод статистики по пакетам
    void print_length_stats(const LengthCounts& counts) {
        // 1. по возрастанию длин (ключ map уже отсортирован)
        std::cout << "\n=== Packet length statistics (by length ascending) ===" << std::endl;
        for (const auto& entry : counts) {
            std::cout << "length " << entry.first << ": count " << entry.second << std::endl;
        }

        // 2. по возрастанию количества
        std::cout << "\n=== Packet length statistics (by count ascending) ===" << std::endl;
        auto sorted_by_count = sort_by_count(counts);
        for (const auto& entry : sorted_by_count) {
            std::cout << "length " << entry.first << ": count " << entry.second << std::endl;
        }
    }


    // сортировка пакетов по возрастанию количества (по значению в map)
    std::vector<std::pair<uint32_t, uint32_t>> sort_by_count(const LengthCounts& counts) {
        std::vector<std::pair<uint32_t, uint32_t>> vec(counts.begin(), counts.end());
        std::sort(vec.begin(), vec.end(),
            [](const std::pair<uint32_t, uint32_t>& a, const std::pair<uint32_t, uint32_t>& b) {
                return a.second == b.second ? a.first < b.first : a.second < b.second;
            });
        return vec;
    }

    void print_mac_pair_stats(const MacPairCounts& counts) {
        std::cout << "\n=== MAC address pair statistics (src -> dst) ===" << std::endl;
        for (const auto& mac_pair : counts) {
            std::cout << mac_pair.first << ": " << mac_pair.second << std::endl;
        }
    }

    void print_ethertype_stats(const EtherTypeCounts& counts) {
        std::cout << "\n=== EtherType statistics ===" << std::endl;
        for (const auto& entry : counts) {
            std::cout << ethernet::ethertype_to_string(entry.first)
                      << " : " << entry.second << std::endl;
        }
    }

    void print_checksum_stats(const uint32_t correct, const uint32_t total) {
        std::cout << "\n=== IPv4 checksum statistics ===" << std::endl
        << "Number of IPv4 packets: " << total << ", with correct checksum: " << correct << std::endl;
    }


}
