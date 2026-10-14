# SPDX-License-Identifier: Apache-2.0

# The Matter gateway on its own: Wi-Fi from menuconfig, chip-tool-gw connecting
# from the local network, and a console for the stream's endpoint and secret.
cmake_minimum_required(VERSION 3.16)
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/../../components")
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(matter_gateway_example)
