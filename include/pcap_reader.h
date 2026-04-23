#pragma once
#include <fstream>
#include <vector>
#include <cstdint>


#pragma pack(1)
namespace pcap {

    enum link_types : uint32_t {
        lt_null          = 0,    /* BSD loopback encapsulation */
        lt_ethernet      = 1,    /* IEEE 802.3 Ethernet */
        lt_ax25          = 3,    /* AX.25 amateur radio */
        lt_ieee802_5     = 6,    /* IEEE 802.5 Token Ring */
        lt_arcnet_bsd    = 7,    /* ARCNET Data Packets (BSD) */
        lt_slip          = 8,    /* SLIP */
        lt_ppp           = 9,    /* PPP */
        lt_fddi          = 10,   /* FDDI */
        lt_ppp_hdlc      = 50,   /* PPP in HDLC-like framing */
        lt_ppp_ether     = 51,   /* PPPoE */
        lt_atm_rfc1483   = 100,  /* RFC 1483 ATM AAL5 */
        lt_raw           = 101,  /* Raw IP */
        lt_c_hdlc        = 104,  /* Cisco HDLC */
        lt_ieee802_11    = 105,  /* IEEE 802.11 wireless */
        lt_frelay        = 107,  /* Frame Relay */
        lt_loop          = 108,  /* OpenBSD loopback */
        lt_linux_sll     = 113,  /* Linux "cooked" capture */
        lt_ltalk         = 114,  /* Apple LocalTalk */
        lt_pflog         = 117,  /* OpenBSD pflog */
        lt_ieee802_11_prism = 119, /* Prism monitor mode header */
        lt_ieee802_11_radiotap = 127, /* Radiotap header */
        lt_arcnet_linux  = 129,  /* ARCNET Data Packets (Linux) */
        lt_pppi          = 192,  /* Per-Packet Information (PPI) */
        lt_can_socketcan = 227,  /* Controller Area Network (CAN) */
        lt_ipv4          = 228,  /* Raw IPv4 */
        lt_ipv6          = 229,  /* Raw IPv6 */
        lt_ieee802_15_4  = 230,  /* IEEE 802.15.4 without FCS */
        lt_nflog         = 239,  /* Linux netfilter log */
        lt_usbpcap       = 249,  /* USB with pcap header */
        lt_bluetooth_le_ll = 251, /* Bluetooth Low Energy Link Layer */
        lt_netlink       = 253,  /* Linux Netlink */
        lt_linux_sll2    = 276,  /* Linux "cooked" capture v2 */
        lt_ethernet_mpacket = 274 /* Ethernet mpacket */
    };




    struct GlobalHeader {
        uint32_t magic_number;
        uint16_t version_major;
        uint16_t version_minor;
        int32_t  thiszone;
        uint32_t sigfigs;
        uint32_t snaplen;
        uint32_t network;
    };

    struct PacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    };
#pragma pack()

    struct Packet {
        PacketHeader header;
        std::vector<uint8_t> data;  // сырые данные пакета (incl_len байт)
    };

    class PcapReader {
    public:
        PcapReader() = default;

        explicit PcapReader(const std::string& filename) {
            open(filename);
        }

        ~PcapReader() { close(); }

        PcapReader(const PcapReader&) = delete;
        PcapReader& operator=(const PcapReader&) = delete;

        // присваивание через move
        PcapReader& operator=(PcapReader&& other) noexcept {
            if (this != &other) {
                close();
                file_ = std::move(other.file_);
                global_header_ = other.global_header_;
                packets_ = std::move(other.packets_);
                byte_swap_ = other.byte_swap_;
            }
            return *this;
        }

        bool open(const std::string& filename);
        bool is_open() const { return static_cast<bool>(file_); }
        void close();

        const GlobalHeader& get_global_header() const { return global_header_; }
        const std::vector<Packet>& get_packets() const { return packets_; }
        size_t packet_count() const { return packets_.size(); }

        bool needs_byte_swap() const { return byte_swap_; }

        bool read_next_packet(Packet& pkt);

    private:
        std::ifstream file_{};
        GlobalHeader global_header_{};
        std::vector<Packet> packets_{};
        bool byte_swap_ {false};

        // Функции для учёта порядка байт
        uint16_t read_u16(const uint8_t* data) const;
        uint32_t read_u32(const uint8_t* data) const;
        void fix_header_endianness();
        void fix_packet_header_endianness(PacketHeader& ph) const;
    };

    std::string linktype_to_string(uint32_t ltype);

}
