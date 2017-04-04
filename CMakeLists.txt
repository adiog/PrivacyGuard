cmake_minimum_required(VERSION 3.7)
project(PrivacyGuard)

set(CMAKE_CXX_STANDARD 11)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})

set(SOURCE_FILES PrivacyGuard.cc PrivacyGuard.h)
add_library(PrivacyGuard ${SOURCE_FILES})

FILE(GLOB_RECURSE UNIT_TESTS ${CMAKE_CURRENT_SOURCE_DIR}/unit_test/**.cc)
ADD_EXECUTABLE(privacy_guard_unit_test ${UNIT_TESTS})
TARGET_LINK_LIBRARIES(privacy_guard_unit_test PrivacyGuard gtest gmock pthread dl gpgme)
