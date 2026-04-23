// test.cpp
#include <cassert>
#include <iostream>
#include <vector>
#include <string>
#include "utils.h"
#include "ethernet.h"
#include "stats.h"
#include "pcap_reader.h"

#define TEST(name) std::cout << "Test: " << #name << " ... "
#define OK() std::cout << "OK" << std::endl;
#define FAIL(msg) std::cout << "FAIL: " << msg << std::endl;

// 1. Тест функции read_be16
void test_read_be16() {
    TEST(read_be16);
    uint8_t data[] = {0x08, 0x00};
    uint16_t val = read_be16(data);
    assert(val == 0x0800);
    OK();
}

// 2. Тест parse_ip для IPv4
void test_parse_ipv4_valid() {
    TEST(parse_ipv4_valid);
    // минимальный IPv4-заголовок (IHL=5, total_length=20)
    uint8_t ipv4_header[] = {
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02
    };
    auto info = ip::parse_ip(ipv4_header, sizeof(ipv4_header));
    assert(info.valid);
    assert(info.version == 4);
    assert(info.ihl == 5);
    assert(info.total_length == 0x14); // 20
    OK();
}

void test_parse_ipv4_invalid_short_header() {
    TEST(parse_ipv4_invalid_short_header);
    uint8_t short_data[] = {0x45}; // меньше 20 байт
    auto info = ip::parse_ip(short_data, sizeof(short_data));
    assert(!info.valid);
    OK();
}

void test_parse_ipv4_invalid_ihl() {
    TEST(parse_ipv4_invalid_ihl);
    uint8_t bad_ihl[] = {
        0x44, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xC0, 0xA8, 0x01, 0x01,
        0xC0, 0xA8, 0x01, 0x02
    }; // IHL=4 < 5
    auto info = ip::parse_ip(bad_ihl, sizeof(bad_ihl));
    assert(!info.valid);
    OK();
}

// 3. Тест parse_ip для IPv6
void test_parse_ipv6_valid() {
    TEST(parse_ipv6_valid);
    // Минимальный IPv6-заголовок (40 байт)
    uint8_t ipv6_header[40] = {0x60, 0x00, 0x00, 0x00, 0x00, 0x14, 0x11, 0x01}; // payload_length=20
    auto info = ip::parse_ip(ipv6_header, sizeof(ipv6_header));
    assert(info.valid);
    assert(info.version == 6);
    assert(info.payload_length == 0x14);
    assert(info.total_length == 40 + 0x14);
    OK();
}

void test_parse_ipv6_too_short() {
    TEST(parse_ipv6_too_short);
    uint8_t short_data[30] = {};
    auto info = ip::parse_ip(short_data, sizeof(short_data));
    assert(!info.valid);
    OK();
}
// 4. Тест проверки контрольной суммы IPv4
void test_verify_ipv4_checksum_correct() {
    TEST(verify_ipv4_checksum_correct);
    // пример заголовка:
    // 4500 003c 1c46 4000 4006 b1e6 ac10 0a63 ac10 0a0c
    // Контрольная сумма b1e6 вычислена правильно
    uint8_t header[] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63,
        0xac, 0x10, 0x0a, 0x0c
    };
    assert(ip::verify_ipv4_checksum(header, 5)); // IHL=5
    OK();
}

void test_verify_ipv4_checksum_incorrect() {
    TEST(verify_ipv4_checksum_incorrect);
    uint8_t header[] = {
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0x00, 0x00, 0xac, 0x10, 0x0a, 0x63,
        0xac, 0x10, 0x0a, 0x0c
    }; // контрольная сумма обнулена, проверка должна провалиться
    assert(!ip::verify_ipv4_checksum(header, 5));
    OK();
}

// 5. Тест CRC-16-CCITT
void test_crc16_ccitt() {
    TEST(crc16_ccitt);
    uint8_t data[] = {'1','2','3','4','5','6','7','8','9'};
    uint16_t crc = crc16::crc16_ccitt(data, 9);
    // ожидаемое значение для CRC-CCITT (0xFFFF init, 0x1021 poly) - 0x29B1
    assert(crc == 0x29B1);
    OK();
}

// 6. Тест HDLC-кодирования
void test_hdlc_encode_frame() {
    TEST(hdlc_encode_frame);
    uint8_t data[] = {0b11111000}; // 5 единиц подряд в начале байта
    auto encoded = hdlc::encode_frame(data, sizeof(data));
    // проверка наличия флагов 0x7E в начале и конце
    assert(encoded.front() == 0x7E);
    assert(encoded.back() == 0x7E);

    // размер > исходного из-за стаффинга и флагов
    assert(encoded.size() > sizeof(data) + 2); // +2 флага + stuffing
    OK();
}

// 7. Тест функций Ethernet
void test_ethernet() {
    TEST(ethernet);
    // Создаём искусственный пакет с Ethernet-заголовком
    std::vector<uint8_t> raw = {
        0x00,0x11,0x22,0x33,0x44,0x55, // dst MAC
        0x66,0x77,0x88,0x99,0xAA,0xBB, // src MAC
        0x08,0x00                       // EtherType IPv4
    };
    pcap::Packet pkt;
    pkt.data = raw;
    assert(ethernet::has_eth_header(pkt, 1));
    assert(ethernet::ethertype(pkt) == 0x0800);
    std::string mac_str = ethernet::to_string(ethernet::src_mac(pkt));
    assert(mac_str == "66:77:88:99:AA:BB");
    std::string pair = ethernet::mac_pair_to_string(ethernet::src_mac(pkt), ethernet::dst_mac(pkt));
    assert(pair == "66:77:88:99:AA:BB -> 00:11:22:33:44:55");
    OK();
}

// 8. Тест статистики (сортировка по количеству)
void test_stats_sort_by_count() {
    TEST(stats_sort_by_count);
    stats::LengthCounts counts = {{100, 5}, {64, 10}, {1500, 2}};
    auto sorted = stats::sort_by_count(counts);
    assert(sorted.size() == 3);
    assert(sorted[0].first == 1500 && sorted[0].second == 2);
    assert(sorted[1].first == 100 && sorted[1].second == 5);
    assert(sorted[2].first == 64 && sorted[2].second == 10);
    OK();
}
// Точка входа для тестов
int main() {
    test_read_be16();
    test_parse_ipv4_valid();
    test_parse_ipv4_invalid_short_header();
    test_parse_ipv4_invalid_ihl();
    test_parse_ipv6_valid();
    test_parse_ipv6_too_short();
    test_verify_ipv4_checksum_correct();
    test_verify_ipv4_checksum_incorrect();
    test_crc16_ccitt();
    test_hdlc_encode_frame();
    test_ethernet();
    test_stats_sort_by_count();
    std::cout << "\nAll tests passed." << std::endl;
    return 0;
}