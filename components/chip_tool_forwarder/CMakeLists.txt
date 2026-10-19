# SPDX-License-Identifier: Apache-2.0

# A forwarder for chip-tool-remote (include/chip_tool_forwarder.h).
# core/ is shared with chip-tool-remote (../../chip-tool-remote/BUILD.gn).
set(srcs "chip_tool_forwarder.cpp" "ctf_cmd.c" "forwarder.cpp" "forwarder_ca.cpp" "forwarder_secret.cpp"
         "controller.cpp" "controller_icd.cpp" "controller_queue_filter.cpp" "thread_cmds.c" "thread_dataset.c"
         "core/ctf_keys.cpp" "core/ctf_listener.cpp" "core/ctf_proto.cpp" "core/ctf_relay.cpp" "core/ctf_server.cpp"
         "core/ctf_tls_mbedtls.cpp")
set(ldfragments)
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    configure_file(linker.lf.in "${CMAKE_CURRENT_BINARY_DIR}/linker.lf" @ONLY)
    set(ldfragments "${CMAKE_CURRENT_BINARY_DIR}/linker.lf")
endif()

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "include"
    PRIV_INCLUDE_DIRS "." "core"
    REQUIRES espressif__cjson
    PRIV_REQUIRES espressif__esp_matter bt esp_event esp_hw_support esp_netif esp_timer esp_wifi lwip mbedtls
                  nvs_flash
    LDFRAGMENTS ${ldfragments}
)

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    target_compile_options(${COMPONENT_LIB} PRIVATE "-DCHIP_HAVE_CONFIG_H")
    # The chip-tool-remote release this forwarder matches (matter.connect's "client"):
    # the component's version, which each release is tagged with.
    file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/idf_component.yml" version_line REGEX "^version:")
    string(REGEX REPLACE "^version: *\"?([^\"]*)\"?.*$" "\\1" component_version "${version_line}")
    target_compile_definitions(${COMPONENT_LIB} PRIVATE "CTF_CLIENT_RELEASE=\"v${component_version}\"")
    # esp-matter's own projects build CHIP with these (their project
    # CMakeLists); here they apply to esp-matter's sources only.
    idf_component_get_property(esp_matter_lib espressif__esp_matter COMPONENT_LIB)
    # -Os as esp-matter builds CHIP: at the firmware's -O2, GCC raises
    # stringop warnings inside CHIP, which builds with -Werror.
    target_compile_options(${esp_matter_lib} PRIVATE
        "$<$<COMPILE_LANGUAGE:CXX>:-Wno-error=unused-result;-Wno-overloaded-virtual>"
        "-Wno-format-nonliteral;-Wno-format-security" "-Os")
    idf_component_get_property(esp_matter_dir espressif__esp_matter COMPONENT_DIR)
    set_source_files_properties(
        "${esp_matter_dir}/components/esp_matter_controller/commands/esp_matter_controller_pairing_command.cpp"
        TARGET_DIRECTORY ${esp_matter_lib}
        PROPERTIES COMPILE_OPTIONS "-include;${CMAKE_CURRENT_LIST_DIR}/esp_matter_compat.h")
endif()
