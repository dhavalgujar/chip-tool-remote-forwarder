# SPDX-License-Identifier: Apache-2.0

# The forwarder on its own: Wi-Fi from menuconfig, chip-tool-remote connecting
# from the local network, and a console for the stream's endpoint and secret.
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(chip_tool_forwarder_example)
