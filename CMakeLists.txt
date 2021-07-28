cmake_minimum_required(VERSION 3.10)

project(luasec-mbedtls)

file(GLOB MBEDTLS_SOURCE ${PROJECT_SOURCE_DIR}/../mbedtls/library/*.c)

add_library(mbedtls STATIC ${MBEDTLS_SOURCE})
target_include_directories(mbedtls PUBLIC "${PROJECT_SOURCE_DIR}/../mbedtls/include" "${PROJECT_SOURCE_DIR}/../mbedtls/library")
if (WIN32)
    target_link_libraries(mbedtls ws2_32)
endif()

add_library(lua51 SHARED IMPORTED)
set_property(TARGET lua51 PROPERTY
            IMPORTED_LOCATION "D:/Lua/lua-5.1.5/src")
set_property(TARGET lua51 PROPERTY
             IMPORTED_IMPLIB "D:/Lua/lua-5.1.5/src/lua51.lib")

add_library(luasec-mbedtls SHARED context.c tls.c)
set_target_properties(luasec-mbedtls PROPERTIES OUTPUT_NAME "tls") 
target_link_libraries(luasec-mbedtls mbedtls lua51)
target_include_directories(luasec-mbedtls PUBLIC "D:/Lua/lua-5.1.5/src")
