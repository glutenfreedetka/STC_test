#include <iostream>
#include "ip_file_writer.h"

namespace ip {

    void IpFileWriter::set_output_paths(const std::string& ipv4_path, const std::string& ipv6_path) {
        close(); // если пути меняются, закрываем уже открытые файлы
        ipv4_path_ = ipv4_path;
        ipv6_path_ = ipv6_path;
    }

    void IpFileWriter::write_packet(int version, const uint8_t* ip_data, uint16_t ip_len) {
        if (version == 4) {
            if (!ipv4_opened_) {
                ipv4_file_.open(ipv4_path_, std::ios::binary);
                ipv4_opened_ = ipv4_file_.is_open();
                if (!ipv4_opened_) {
                    std::cerr << "Error opening IPv4 file" << std::endl;
                    return; // не удалось открыть – пропускаем
                }
            }
            // 2 байта размера в big-endian
            uint16_t size_be = static_cast<uint16_t>((ip_len >> 8) & 0xFF) |
                               static_cast<uint16_t>((ip_len & 0xFF) << 8);
            ipv4_file_.write(reinterpret_cast<const char*>(&size_be), sizeof(size_be));
            ipv4_file_.write(reinterpret_cast<const char*>(ip_data), ip_len);
        } else if (version == 6) {
            if (!ipv6_opened_) {
                ipv6_file_.open(ipv6_path_, std::ios::binary);
                ipv6_opened_ = ipv6_file_.is_open();
                if (!ipv6_opened_) {
                    std::cerr << "Error opening IPv6 file" << std::endl;
                    return; // не удалось открыть – пропускаем
                }
            }
            // 4 байта размера в big-endian
            uint32_t size_be = ((ip_len >> 24) & 0xFF) |
                               (((ip_len >> 16) & 0xFF) << 8) |
                               (((ip_len >> 8) & 0xFF) << 16) |
                               ((ip_len & 0xFF) << 24);
            ipv6_file_.write(reinterpret_cast<const char*>(&size_be), sizeof(size_be));
            ipv6_file_.write(reinterpret_cast<const char*>(ip_data), ip_len);
        }
    }

    void IpFileWriter::close() {
        if (ipv4_opened_) {
            ipv4_file_.close();
            ipv4_opened_ = false;
        }
        if (ipv6_opened_) {
            ipv6_file_.close();
            ipv6_opened_ = false;
        }
    }

}