#include <chrono>
#include <iomanip>
#include "utils.h"
#include <iostream>
#include <sstream>


namespace ip {

    IpInfo parse_ip(const uint8_t* data, size_t len) {
        IpInfo info{};
        if (len < 20) {
            std::cerr << "Parse IP: invalid packet length" << std::endl;
            return info; // минимальная длина IP-заголовка
        }

        uint8_t version = (data[0] >> 4) & 0x0F;
        if (version == 4) {
            info.version = 4;
            info.ihl = data[0] & 0x0F;
            if (info.ihl < 5) {
                std::cerr << "Parse IP: invalid IPv4-header length" << std::endl;
                return info;
            }
            size_t header_size = info.ihl * 4;
            if (len < header_size) {
                std::cerr << "Parse IP: invalid packet length" << std::endl;
                return info; // длина заголовка больше длины пакета
            }

            info.total_length = read_be16(data + 2);
            if (info.total_length < header_size) {
                std::cerr << "Parse IP: invalid total length" << std::endl;
                return info; // некорректный total length
            }

            info.valid = true;
        } else if (version == 6) {
            if (len < 40) {
                std::cerr << "Parse IP: invalid IPv6 packet length" << std::endl;
                return info; // минимальная длина IPv6-заголовка
            }
            info.version = 6;
            info.payload_length = read_be16(data + 4);
            info.total_length = 40 + info.payload_length;
            info.valid = true;
        }
        return info;
    }

    bool verify_ipv4_checksum(const uint8_t* data, uint8_t ihl) {
        uint32_t sum = 0;
        // сумма всех 16-битных слов заголовка
        for (uint8_t i = 0; i < ihl * 2; ++i) {
            uint16_t word = read_be16(data + i * 2);
            sum += word;
        }
        // Учёт переносов
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // корректная сумма даёт 0xFFFF после сложения всех полей, включая само поле checksum.
        // после инвертирования проверка: (~sum) == 0
        return static_cast<uint16_t>(~sum) == 0;
    }

}

std::string current_datetime_string() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::localtime(&now_time);   // локальное время
    char buf[20];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm);
    return buf;
}

namespace crc16 {
    uint16_t crc16_ccitt(const uint8_t* data, size_t len) {
        uint16_t crc = 0xFFFF;
        for (size_t i = 0; i < len; ++i) {
            crc ^= static_cast<uint16_t>(data[i]) << 8;
            for (int j = 0; j < 8; ++j) {
                if (crc & 0x8000)
                    crc = (crc << 1) ^ 0x1021; // XOR с порождающим полиномом 0x1021
                else
                    crc <<= 1;
            }
        }
        return crc;
    }
}

namespace hdlc {
    std::vector<uint8_t> encode_frame(const uint8_t* data, size_t len) {
        std::vector<uint8_t> out;
        const uint8_t flag = 0x7E;
        out.push_back(flag); // начальный флаг

        int bit_count = 0;
        uint8_t out_byte = 0;
        int bits_in_byte = 0;

        auto flush_byte = [&]() {
            if (bits_in_byte > 0) {
                out.push_back(out_byte);
                out_byte = 0;
                bits_in_byte = 0;
            }
        };

        auto add_bit = [&](uint8_t bit) {
            out_byte = (out_byte << 1) | (bit & 1);
            ++bits_in_byte;
            if (bits_in_byte == 8)
                flush_byte();
        };

        for (size_t i = 0; i < len; ++i) {
            for (int b = 7; b >= 0; --b) {
                uint8_t bit = (data[i] >> b) & 1;
                add_bit(bit);
                if (bit == 1) {
                    ++bit_count;
                    if (bit_count == 5) {
                        add_bit(0);        // stuffing
                        bit_count = 0;
                    }
                } else {
                    bit_count = 0;
                }
            }
        }
        flush_byte();          // дописываем неполный байт
        out.push_back(flag);   // конечный флаг
        return out;
    }
}

