#pragma once
#include <fstream>
#include <string>
#include <cstdint>

namespace ip {

    class IpFileWriter {
    public:
        IpFileWriter() = default;

        IpFileWriter(const IpFileWriter&) = delete;
        IpFileWriter& operator=(const IpFileWriter&) = delete;

        ~IpFileWriter() { close(); }

        void set_output_paths(const std::string& ipv4_path, const std::string& ipv6_path);

        // Записывает IP-пакет. Файл открывается при первом вызове для данной версии.
        // version: 4 или 6.
        // ip_data: указатель на начало IP-заголовка.
        // ip_len: полная длина IP-пакета в байтах.
        void write_packet(int version, const uint8_t* ip_data, uint16_t ip_len);

        void close();

        // узнать, был ли записан хотя бы один пакет (и создан ли файл).
        bool has_ipv4() const { return ipv4_opened_; }
        bool has_ipv6() const { return ipv6_opened_; }

    private:
        std::string ipv4_path_;
        std::string ipv6_path_;
        std::ofstream ipv4_file_;
        std::ofstream ipv6_file_;
        bool ipv4_opened_ = false;
        bool ipv6_opened_ = false;
    };

}
