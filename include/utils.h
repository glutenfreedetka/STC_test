#pragma once

#include <string>
#include <cstdint>
#include <vector>

struct ParseResult {
    bool help = false;
    std::string filename;
    bool ok = false;
    std::string error;
};

constexpr size_t MAC_ADDR_LEN = 6;

struct mac_address {
    uint8_t bytes[6];
};

namespace ip {

    struct IpInfo {
        uint8_t version = 0;
        uint8_t ihl = 0;           // для IPv4: длина заголовка в 32-битных словах (min 5)
        uint16_t total_length = 0; // для IPv4: Total Length; для IPv6: 40 + payload_length
        uint16_t payload_length = 0; // для IPv6
        bool valid = false;
    };

    // Распарсить IP-пакет. data – указатель на начало IP-заголовка, len – доступная длина
    IpInfo parse_ip(const uint8_t* data, size_t len);

    // Проверка контрольной суммы IPv4-заголовка (RFC 791)
    bool verify_ipv4_checksum(const uint8_t* data, uint8_t ihl);

}

// функция для записи 2 байт поля в big-endian
inline uint16_t read_be16(const uint8_t* ptr) {
    return (static_cast<uint16_t>(ptr[0]) << 8) | ptr[1];
}

std::string current_datetime_string();

namespace crc16 {
    uint16_t crc16_ccitt(const uint8_t* data, size_t len);
}

namespace hdlc {
    // Возвращает байтовый поток – один HDLC-кадр: флаг 0x7E, данные с бит-стаффингом, флаг 0x7E
    std::vector<uint8_t> encode_frame(const uint8_t* data, size_t len);
}
