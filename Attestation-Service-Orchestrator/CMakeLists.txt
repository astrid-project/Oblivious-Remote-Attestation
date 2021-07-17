cmake_minimum_required(VERSION 3.10)
project(orchestrator)

# find_package(Boost REQUIRED COMPONENTS system thread log program_options chrono)
find_package(Boost COMPONENTS system thread log program_options chrono)
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(ZLIB)

add_definitions(-DTPM_TPM20)
add_definitions(-DVERBOSE)
#add_definitions(-DHWTPM)
#add_definitions(-DHIGHLEVELTIMINGS)
#add_definitions(-DLOWLEVELTIMINGS)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(COMPILE_FLAGS "-Wall -Wno-sign-compare -O3 -Wno-comment -Wno-unused-function -Wno-write-strings -fexceptions -fpermissive -no-pie -std=c++0x")
set(CMAKE_CXX_FLAGS "${COMPILE_FLAGS} -std=gnu++14 -DBOOST_LOG_DYN_LINK")
set(CPPFLAGS -stdlib=libc++ LDFLAGS -lcpprest -lssl -lcrypto -lboost_system -lboost_thread-mt -lboost_chrono-mt -lpthread -pthread -lz)
set(CMAKE_CXX_STANDARD 14)

add_executable(orchestrator
        include/cryptoutils.h
        include/handler.h
        include/objecttemplates.h
        include/orchestrator.h
        include/stdafx.h
        include/timing.h
        include/tpm.h
        src/cryptoutils.c
        src/handler.cpp
        src/orchestrator.cpp
        src/tpm.cpp
        main.cpp)

set(ORCHESTRATOR_INCLUDE_DIR "include")

if (WIN32)
        link_directories(libs)
        add_definitions(-DTPM_WINDOWS)
        set(IBMTSS_UTILS_DIR "C:\\opt\\ibmtss1.6.0\\utils")
        set(CPPRESTSDK_INCLUDE_DIR "C:\\opt\\vcpkg\\packages\\cpprestsdk_x64-windows\\include")
endif (WIN32)

if (UNIX)
        add_definitions(-DTPM_POSIX)
        set(IBMTSS_UTILS_DIR "/opt/ibmtss/utils")
        set(CPPRESTSDK_INCLUDE_DIR "./libs/cpprestsdk/Release/include")
endif(UNIX)

if (EXISTS Boost AND EXISTS ZLIB)
        set(HEADER_SEARCH_PATHS ${CPPRESTSDK_INCLUDE_DIR} ${ORCHESTRATOR_INCLUDE_DIR} ${IBMTSS_UTILS_DIR} ${Boost_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${ZLIB_INCLUDE_DIRS})
else()
        set(HEADER_SEARCH_PATHS ${CPPRESTSDK_INCLUDE_DIR} ${ORCHESTRATOR_INCLUDE_DIR} ${IBMTSS_UTILS_DIR} ${OPENSSL_INCLUDE_DIR})
endif()

set(OPENSSL_LIBS "${OPENSSL_LIBRARIES}")
set(CPPRESTSDK_LIBRARY "${PROJECT_SOURCE_DIR}/libs/cpprestsdk/build.release/Binaries/libcpprest.a")
set(LIBRARIES_SEARCH_PATHS ${CPPRESTSDK_LIBRARY} ${OPENSSL_LIBS} ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})
include_directories(${HEADER_SEARCH_PATHS})

target_link_libraries(${PROJECT_NAME} ibmtss ${LIBRARIES_SEARCH_PATHS})
