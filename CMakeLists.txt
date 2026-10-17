cmake_minimum_required(VERSION 3.22)
project(TickRateController LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT ANDROID)
    message(FATAL_ERROR "This mod must be built for Android.")
endif()

if(NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a")
    message(FATAL_ERROR "Only Android ARM64 is supported.")
endif()

include(FetchContent)

FetchContent_Declare(
    LeviLauncherSDK
    GIT_REPOSITORY https://github.com/LiteLDev/preloader-android.git
    GIT_TAG 0.2.2
)

FetchContent_MakeAvailable(LeviLauncherSDK)

add_library(tick_rate_controller SHARED
    src/TickRateController.cpp
)

find_library(ANDROID_LOG_LIB log REQUIRED)

target_link_libraries(tick_rate_controller PRIVATE
    preloader
    ${ANDROID_LOG_LIB}
)

target_compile_options(tick_rate_controller PRIVATE
    -Wall
    -Wextra
    -fvisibility=hidden
)

set_target_properties(tick_rate_controller PROPERTIES
    OUTPUT_NAME "tick_rate_controller"
)