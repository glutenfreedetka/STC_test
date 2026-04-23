#include <algorithm>
#include "ethernet.h"
#include <cstdint>
#include <cstdio>

namespace ethernet {
    // извлечь MAC получателя
    mac_address dst_mac(const pcap::Packet& pkt) {
        mac_address mac{};
        std::copy_n(pkt.data.begin(), MAC_ADDR_LEN, mac.bytes);
        return mac;
    }

    // извлечь MAC отправителя
    mac_address src_mac(const pcap::Packet& pkt) {
        mac_address mac{};
        std::copy_n(pkt.data.begin() + MAC_ADDR_LEN, MAC_ADDR_LEN, mac.bytes);
        return mac;
    }

    std::string to_string(const mac_address& mac) {
        char buf[18];
        snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
                 mac.bytes[0], mac.bytes[1], mac.bytes[2], mac.bytes[3], mac.bytes[4], mac.bytes[5]);
        return buf;
    }

    std::string ethertype_to_string(uint16_t etype) {
        switch (etype) {
            case e_ipv4:     return "IPv4 (0x0800)";
            case e_arp:      return "ARP (0x0806)";
            case e_atalk:    return "AppleTalk DDP (0x809B)";
            case e_aarp:     return "AppleTalk AARP (0x80F3)";
            case e_8021_q:   return "802.1Q VLAN (0x8100)";
            case e_ipv6:     return "IPv6 (0x86DD)";
            case e_pause:    return "IEEE Pause (0x8808)";
            case e_slow:     return "Slow Protocols (0x8809)";
            case e_mpls_uc:  return "MPLS Unicast (0x8847)";
            case e_mpls_mc:  return "MPLS Multicast (0x8848)";
            case e_ppp_disc: return "PPPoE Discovery (0x8863)";
            case e_ppp_ses:  return "PPPoE Session (0x8864)";
            case e_pae:      return "802.1X PAE (0x888E)";
            default: {
                char buf[11];
                snprintf(buf, sizeof(buf), "0x%04X", etype);
                return buf;
            }
        }
    }


}