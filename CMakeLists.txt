cmake_minimum_required(VERSION 3.10)
project(Timings C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

file(GLOB_RECURSE ALL_SRCS "${CMAKE_SOURCE_DIR}/src/*.c")

# remove files that are target-specific.
list(REMOVE_ITEM ALL_SRCS
    "${CMAKE_SOURCE_DIR}/src/mininet_setup/c_switch_handle_S1.c"
    "${CMAKE_SOURCE_DIR}/src/mininet_setup/c_switch_handle_S2.c"
    "${CMAKE_SOURCE_DIR}/src/rpi/rp.c"  # We'll add rp.c manually for rpswitch.
)

set(ENCRYPTION_SRCS ${ALL_SRCS})

set(SWITCH_1_SRCS "${CMAKE_SOURCE_DIR}/src/mininet_setup/c_switch_handle_S1.c"
    ${ENCRYPTION_SRCS})
set(SWITCH_2_SRCS "${CMAKE_SOURCE_DIR}/src/mininet_setup/c_switch_handle_S2.c"
    ${ENCRYPTION_SRCS})

add_executable(switch1 ${SWITCH_1_SRCS})
add_executable(switch2 ${SWITCH_2_SRCS})

add_executable(rpswitch "${CMAKE_SOURCE_DIR}/src/rpi/rp.c")

file(GLOB ENCRYPTION_TIMINGS_SRCS "${CMAKE_SOURCE_DIR}/src/encryption_timings/*.c")
target_sources(rpswitch PRIVATE ${ENCRYPTION_TIMINGS_SRCS})

target_link_libraries(switch1 PRIVATE pcap sodium crypto)
target_link_libraries(switch2 PRIVATE pcap sodium crypto)
target_link_libraries(rpswitch PRIVATE pcap sodium crypto)

target_include_directories(switch1 PRIVATE src/encryption_timings)
target_include_directories(switch2 PRIVATE src/encryption_timings)
target_include_directories(rpswitch PRIVATE src/encryption_timings)

add_custom_target(clean_mac_files
    COMMAND find ${CMAKE_SOURCE_DIR} -name "._*" -delete
)

add_custom_target(prebuild ALL DEPENDS clean_mac_files)
