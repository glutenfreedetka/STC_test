#include <iostream>
#include <string>
#include "pcap_reader.h"
#include "utils.h"
#include "ethernet.h"
#include "stats.h"
#include "ip_file_writer.h"

using PacketStats = stats::PacketStats;

ParseResult parse_args(char* argv[]) {
    ParseResult res;
    std::string arg = argv[1];
    if (arg == "-h" || arg == "--help") {
        res.help = true;
        res.ok = true;
        return res;
    }

    if (!arg.empty() && arg[0] == '-') {
        res.error = "Unknown flag: " + arg;
        return res;
    }

    res.filename = arg;
    res.ok = true;
    return res;
}

void print_help() {
    std::cout << R"(Usage:
    ./STC_test <path_to_PCAP_file>

    Options:
        -h, --help   to show this message
    )";
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "Invalid number of parameters" << std::endl;
        print_help();
        return 1;
    }

    auto args = parse_args(argv);
    if (!args.ok) {
        std::cerr << "Error: " << args.error << std::endl;
        print_help();
        return 1;
    }

    if (args.help) {
        print_help();
        return 0;
    }

    pcap::PcapReader reader;
    if (!reader.open(args.filename)) {
        std::cerr << "File opening error " << std::endl;
        return 1;
    }

    std::cout << "PCAP linktype: " << pcap::linktype_to_string(reader.get_global_header().network) << std::endl;
    const auto& linktype = reader.get_global_header().network;

    PacketStats stats;

    ip::IpFileWriter ip_writer;
    std::string ts = current_datetime_string();
    ip_writer.set_output_paths("ipv4_files/ipv4_" + ts + ".bin", "ipv6_files/ipv6_" + ts + ".bin");

    std::ofstream hdlc_file;
    bool hdlc_opened = false;
    auto open_hdlc = [&]() {
        if (!hdlc_opened) {
            hdlc_file.open("hdlc_files/hdlc_" + ts + ".bin", std::ios::binary);
            hdlc_opened = hdlc_file.is_open();
        }
    };

    pcap::Packet pkt;
    size_t total_packets = 0;
    size_t ok_checksum = 0;
    while (reader.read_next_packet(pkt)) {
        ++total_packets;
        stats.add_packet(pkt, linktype);

        // проверка наличия Ethernet-заголовка
        if (!ethernet::has_eth_header(pkt, linktype))
            continue;

        uint16_t etype = ethernet::ethertype(pkt);

        if (etype == ethernet::e_ipv4 || etype == ethernet::e_ipv6) {

            const uint8_t* ip_data = pkt.data.data() + 14; // фиксированное смещение
            size_t ip_len_avail = pkt.data.size() - 14;
            auto info = ip::parse_ip(ip_data, ip_len_avail);
            if (!info.valid)
                continue;

            uint16_t full_ip_len = info.version == 4 ? info.total_length : 40 + info.payload_length;

            // запись в выходные IPv4/IPv6 файлы (создание файлов по наличию пакетов)
            ip_writer.write_packet(info.version, ip_data, full_ip_len);

            // проверка контрольной суммы IPv4 (только если IPv4)
            if (info.version == 4) {
                ok_checksum += ip::verify_ipv4_checksum(ip_data, info.ihl);
            }
        }
        uint16_t crc = crc16::crc16_ccitt(pkt.data.data(), pkt.data.size());

        // формируем буфер: пакет + CRC (2 байта, big-endian)
        std::vector<uint8_t>  frame_with_crc;
        frame_with_crc.reserve(pkt.data.size() + 2);
        frame_with_crc.assign(pkt.data.begin(), pkt.data.end());
        frame_with_crc.push_back(static_cast<uint8_t>((crc >> 8) & 0xFF));
        frame_with_crc.push_back(static_cast<uint8_t>(crc & 0xFF));

        // HDLC-кодирование
        auto hdlc_frame = hdlc::encode_frame(frame_with_crc.data(), frame_with_crc.size());

        // HDLC-файл
        open_hdlc();
        if (hdlc_opened) {
            hdlc_file.write(reinterpret_cast<const char*>(hdlc_frame.data()),hdlc_frame.size());
        }

    }

    std::cout << "Packets read: " << total_packets << std::endl;
    stats.print();
    stats::print_checksum_stats(ok_checksum, stats.get_ethertype_stats()[ethernet::e_ipv4]);
    return 0;
}