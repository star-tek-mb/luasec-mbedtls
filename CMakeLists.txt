cmake_minimum_required(VERSION 3.10)

project(luasec-mbedtls)

file(GLOB MBEDTLS_SOURCE ${PROJECT_SOURCE_DIR}/mbedtls/library/*.c)

add_library(mbedtls STATIC ${MBEDTLS_SOURCE})
target_include_directories(mbedtls PUBLIC "${PROJECT_SOURCE_DIR}/mbedtls/include" "${PROJECT_SOURCE_DIR}/mbedtls/library")

if (WIN32)
    target_link_libraries(mbedtls ws2_32)
endif()

find_package(Lua REQUIRED)

add_library(luasec-mbedtls SHARED context.c tls.c)
set_target_properties(luasec-mbedtls PROPERTIES OUTPUT_NAME "tls") 
target_link_libraries(luasec-mbedtls mbedtls ${LUA_LIBRARIES})
target_include_directories(luasec-mbedtls PUBLIC ${LUA_INCLUDE_DIR})
