#include <iostream>
#include "pcap_reader.h"

namespace pcap {

    bool PcapReader::open(const std::string& filename) {
        file_.open(filename, std::ios::binary);
        if (!file_) {
            std::cerr << "Error opening file: " << filename << std::endl;
            return false;
        }

        file_.read(reinterpret_cast<char*>(&global_header_), sizeof(GlobalHeader));
        if (!file_) return false;

        // определяем порядок байт по magic_number
        if (global_header_.magic_number == 0xa1b23c4d || global_header_.magic_number == 0xa1b2c3d4) {
            byte_swap_ = false;  // big-endian
        } else if (global_header_.magic_number == 0xd4c3b2a1 || global_header_.magic_number == 0x4d3cb2a1) {
            byte_swap_ = true;   // little-endian
        } else {
            std::cerr << "Unknown magic number" << std::endl;
            return false;
        }

        fix_header_endianness();
        return true;
    }

    bool PcapReader::read_next_packet(Packet& pkt) {
        if (!file_ || file_.peek() == EOF) return false;

        // чтение заголовка пакета
        file_.read(reinterpret_cast<char*>(&pkt.header), sizeof(PacketHeader));
        if (file_.gcount() != sizeof(PacketHeader)) return false;

        fix_packet_header_endianness(pkt.header);

        // чтение данных пакета
        pkt.data.resize(pkt.header.incl_len);
        file_.read(reinterpret_cast<char*>(pkt.data.data()), pkt.header.incl_len);
        if (file_.gcount() != pkt.header.incl_len) return false;

        return true;
    }

    uint16_t PcapReader::read_u16(const uint8_t* data) const {
        if (byte_swap_)
            return (static_cast<uint16_t>(data[1]) << 8) | data[0];
        return (static_cast<uint16_t>(data[0]) << 8) | data[1];
    }
    // перевод в big-endian
    uint32_t PcapReader::read_u32(const uint8_t* data) const {
        if (byte_swap_)
            return (static_cast<uint32_t>(data[3]) << 24) |
                   (static_cast<uint32_t>(data[2]) << 16) |
                   (static_cast<uint32_t>(data[1]) << 8)  |
                   data[0];
        return (static_cast<uint32_t>(data[0]) << 24) |
               (static_cast<uint32_t>(data[1]) << 16) |
               (static_cast<uint32_t>(data[2]) << 8)  |
               data[3];
    }



    void PcapReader::fix_header_endianness() {
        if (!byte_swap_) return;
        global_header_.version_major = read_u16(reinterpret_cast<uint8_t*>(&global_header_.version_major));
        global_header_.version_minor = read_u16(reinterpret_cast<uint8_t*>(&global_header_.version_minor));
        global_header_.thiszone      = static_cast<int32_t>(read_u32(reinterpret_cast<uint8_t*>(&global_header_.thiszone)));
        global_header_.sigfigs       = read_u32(reinterpret_cast<uint8_t*>(&global_header_.sigfigs));
        global_header_.snaplen       = read_u32(reinterpret_cast<uint8_t*>(&global_header_.snaplen));
        global_header_.network       = read_u32(reinterpret_cast<uint8_t*>(&global_header_.network));
    }



    void PcapReader::fix_packet_header_endianness(PacketHeader& ph) const {
        if (!byte_swap_) return;
        ph.ts_sec   = read_u32(reinterpret_cast<uint8_t*>(&ph.ts_sec));
        ph.ts_usec  = read_u32(reinterpret_cast<uint8_t*>(&ph.ts_usec));
        ph.incl_len = read_u32(reinterpret_cast<uint8_t*>(&ph.incl_len));
        ph.orig_len = read_u32(reinterpret_cast<uint8_t*>(&ph.orig_len));
    }

    void PcapReader::close() {
        if (file_.is_open()) {
            file_.close();
        }
        packets_.clear();
    }


    std::string linktype_to_string(uint32_t ltype) {
        switch (ltype) {
            case lt_null:               return "BSD loopback (0x00000000)";
            case lt_ethernet:           return "Ethernet (0x00000001)";
            case lt_ax25:               return "AX.25 (0x00000003)";
            case lt_ieee802_5:          return "Token Ring (0x00000006)";
            case lt_arcnet_bsd:         return "ARCNET BSD (0x00000007)";
            case lt_slip:               return "SLIP (0x00000008)";
            case lt_ppp:                return "PPP (0x00000009)";
            case lt_fddi:               return "FDDI (0x0000000A)";
            case lt_ppp_hdlc:           return "PPP HDLC (0x00000032)";
            case lt_ppp_ether:          return "PPPoE (0x00000033)";
            case lt_atm_rfc1483:        return "ATM RFC1483 (0x00000064)";
            case lt_raw:                return "Raw IP (0x00000065)";
            case lt_c_hdlc:             return "Cisco HDLC (0x00000068)";
            case lt_ieee802_11:         return "802.11 Wireless (0x00000069)";
            case lt_frelay:             return "Frame Relay (0x0000006B)";
            case lt_loop:               return "OpenBSD loopback (0x0000006C)";
            case lt_linux_sll:          return "Linux cooked (0x00000071)";
            case lt_ltalk:              return "LocalTalk (0x00000072)";
            case lt_pflog:              return "OpenBSD pflog (0x00000075)";
            case lt_ieee802_11_prism:   return "Prism header (0x00000077)";
            case lt_ieee802_11_radiotap:return "Radiotap header (0x0000007F)";
            case lt_arcnet_linux:       return "ARCNET Linux (0x00000081)";
            case lt_pppi:               return "PPI (0x000000C0)";
            case lt_can_socketcan:      return "CAN SocketCAN (0x000000E3)";
            case lt_ipv4:               return "Raw IPv4 (0x000000E4)";
            case lt_ipv6:               return "Raw IPv6 (0x000000E5)";
            case lt_ieee802_15_4:       return "802.15.4 (0x000000E6)";
            case lt_nflog:              return "NFLOG (0x000000EF)";
            case lt_usbpcap:            return "USB pcap (0x000000F9)";
            case lt_bluetooth_le_ll:    return "Bluetooth LE LL (0x000000FB)";
            case lt_netlink:            return "Netlink (0x000000FD)";
            case lt_linux_sll2:         return "Linux cooked v2 (0x00000114)";
            case lt_ethernet_mpacket:   return "Ethernet mpacket (0x00000112)";
            default: {
                char buf[13];
                snprintf(buf, sizeof(buf), "0x%08X", ltype);
                return buf;
            }
        }
    }

}