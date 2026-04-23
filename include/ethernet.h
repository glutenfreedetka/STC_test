#pragma once
#include "utils.h"
#include "pcap_reader.h"
#include <cstdint>
#include <iostream>
#include <string>

namespace ethernet {


    enum ether_types : uint16_t {

    e_ipv4 = 0x0800,		/* Internet Protocol packet	*/
    e_arp = 0x0806,		/* Address Resolution packet	*/
    e_atalk = 0x809B,		/* Appletalk DDP		*/
    e_aarp = 0x80F3,		/* Appletalk AARP		*/
    e_8021_q = 0x8100,          /* 802.1Q VLAN Extended Header  */
    e_ipv6 = 0x86DD,		/* IPv6 over bluebook		*/
    e_pause = 0x8808,		/* IEEE Pause frames. See 802.3 31B */
    e_slow = 0x8809,		/* Slow Protocol. See 802.3ad 43B */
    e_mpls_uc = 0x8847,		/* MPLS Unicast traffic		*/
    e_mpls_mc = 0x8848,		/* MPLS Multicast traffic	*/
    e_ppp_disc = 0x8863,		/* PPPoE discovery messages     */
    e_ppp_ses = 0x8864,		/* PPPoE session messages	*/
    e_pae = 0x888E,		/* Port Access Entity (IEEE 802.1X) */
};
    // проверка наличия Ethernet-заголовка: всегда не меньше 14 байт, linktype только Ethernet (1)
    inline bool has_eth_header(const pcap::Packet& pkt, uint32_t linktype) { return linktype == 1 && pkt.data.size() >= 14; }

    mac_address dst_mac(const pcap::Packet& pkt);

    mac_address src_mac(const pcap::Packet& pkt);

    std::string to_string(const mac_address& mac);

    inline std::string mac_pair_to_string(const mac_address& src, const mac_address& dst) {
        return to_string(src) + " -> " + to_string(dst);
    }

    // Извлечь EtherType
    inline uint16_t ethertype(const pcap::Packet& pkt) {
        const uint8_t* eth = pkt.data.data();
        return read_be16(eth + 2 * MAC_ADDR_LEN);
    }

    std::string ethertype_to_string(uint16_t etype);


}

