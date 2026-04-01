cmake_minimum_required(VERSION 3.22)

project(vonr_ims
  VERSION 0.1.0
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(IMS_WITH_EXOSIP "Build with osip2/eXosip2 SIP stack" ON)
option(IMS_WITH_NGHTTP2 "Build with nghttp2 for HTTP/2 support (N5 interface)" ON)

include(FetchContent)
include(ExternalProject)

find_package(OpenSSL REQUIRED)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG v1.14.1
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
  yaml_cpp
  GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
  GIT_TAG 0.8.0
)
FetchContent_MakeAvailable(yaml_cpp)

FetchContent_Declare(
  gtest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(gtest)

# nghttp2 for HTTP/2 support (N5 interface)
if(IMS_WITH_NGHTTP2)
  FetchContent_Declare(
    nghttp2
    GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
    GIT_TAG v1.58.0
  )
  set(ENABLE_LIB_ONLY ON CACHE BOOL "" FORCE)
  set(ENABLE_STATIC_LIB ON CACHE BOOL "" FORCE)
  set(ENABLE_SHARED_LIB OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(nghttp2)
endif()

add_library(ims_lib)
target_sources(ims_lib PRIVATE
  src/core/config.cpp
  src/core/log.cpp
  src/core/time.cpp
  src/sip/sdp.cpp
  src/sip/sip_message.cpp
  src/sip/sip_stack.cpp
  src/sip/b2bua_relay.cpp
  src/sip/proxy_router.cpp
  src/sip/pani_parser.cpp
  src/ipsec/xfrm_manager.cpp
  src/policy/qos_hook.cpp
  src/storage/location_service.cpp
  src/auth/auth_provider.cpp
  src/cx/cx_stub_client.cpp
  src/scscf/registration_sm.cpp
  src/scscf/call_session.cpp
  src/scscf/scscf_service.cpp
  src/icscf/icscf_service.cpp
  src/pcscf/pcscf_service.cpp
  src/media/rtpengine_client.cpp
  src/media/sdp_rewriter.cpp
  src/dhcp/dhcp_server.cpp
  src/dns/dns_resolver.cpp
  src/storage/subscription_service.cpp
  src/scscf/subscription_sm.cpp
)
target_include_directories(ims_lib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/src/core/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/sip/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/auth/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/cx/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/storage/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/scscf/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/icscf/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/pcscf/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/media/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/ipsec/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/policy/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dhcp/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/dns/
  ${CMAKE_CURRENT_SOURCE_DIR}/src/n5/
)
target_link_libraries(ims_lib PUBLIC
  spdlog::spdlog
  yaml-cpp::yaml-cpp
  OpenSSL::Crypto
)

# nghttp2 link and definitions
if(IMS_WITH_NGHTTP2)
  target_compile_definitions(ims_lib PUBLIC IMS_HAS_NGHTTP2=1)
  target_sources(ims_lib PRIVATE
    src/n5/n5_client.cpp
    src/n5/n5_models.cpp
    src/n5/qos_policy.cpp
  )
  target_include_directories(ims_lib PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/n5/
  )
  target_link_libraries(ims_lib PUBLIC nghttp2_static)
else()
  target_compile_definitions(ims_lib PUBLIC IMS_HAS_NGHTTP2=0)
endif()

# c-ares for DNS resolution (use older version for NAPTR/SRV query support)
FetchContent_Declare(
  c-ares
  GIT_REPOSITORY https://github.com/c-ares/c-ares.git
  GIT_TAG cares-1_19_0
)
set(CARES_BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CARES_BUILD_STATIC ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(c-ares)
target_link_libraries(ims_lib PUBLIC c-ares::cares)


add_executable(imsd
  apps/imsd/main.cpp
)
target_link_libraries(imsd PRIVATE ims_lib)

add_executable(pcscfd
  apps/pcscfd/main.cpp
)
target_link_libraries(pcscfd PRIVATE ims_lib)

add_executable(icscfd
  apps/icscfd/main.cpp
)
target_link_libraries(icscfd PRIVATE ims_lib)

add_executable(scscfd
  apps/scscfd/main.cpp
)
target_link_libraries(scscfd PRIVATE ims_lib)
