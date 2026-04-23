cmake_minimum_required(VERSION 3.11)
project(STC_test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Создаём выходные папки при конфигурации
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/ipv4_files)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/ipv6_files)
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/hdlc_files)

if(WIN32)
    message(STATUS "Configuring for Windows")
elseif(UNIX)
    message(STATUS "Configuring for Linux")
endif()

# CPP Sources
set(SOURCE_MAIN ${CMAKE_CURRENT_SOURCE_DIR}/source/main.cpp)

set(SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/source/pcap_reader.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/stats.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/ethernet.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/ip_file_writer.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/source/utils.cpp
)

set(TESTS ${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cpp)

add_executable(
        ${PROJECT_NAME}
        ${SOURCE_MAIN}
        ${SOURCES}
)


target_include_directories(
        ${PROJECT_NAME}
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_executable(
        tests
        ${TESTS}
        ${SOURCES}
)

target_include_directories(
        tests
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Предупреждения
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W4)
    target_compile_options(tests PRIVATE /W4)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(tests PRIVATE -Wall -Wextra -Wpedantic)
endif()
