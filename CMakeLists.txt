cmake_minimum_required(VERSION 3.22)

project(vonr_ims
  VERSION 0.1.0
  LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(IMS_WITH_EXOSIP "Build with osip2/eXosip2 SIP stack" ON)

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

add_library(ims_lib)
target_sources(ims_lib PRIVATE
  ims/core/src/config.cpp
  ims/core/src/log.cpp
  ims/core/src/time.cpp
  ims/sip/src/sdp.cpp
  ims/sip/src/sip_message.cpp
  ims/sip/src/sip_stack.cpp
  ims/sip/src/b2bua_relay.cpp
  ims/sip/src/proxy_router.cpp
  ims/ipsec/src/xfrm_manager.cpp
  ims/policy/src/qos_hook.cpp
  ims/storage/src/location_service.cpp
  ims/auth/src/auth_provider.cpp
  ims/scscf/src/registration_sm.cpp
  ims/scscf/src/call_session.cpp
  ims/scscf/src/scscf_service.cpp
  ims/icscf/src/icscf_service.cpp
  ims/pcscf/src/pcscf_service.cpp
  ims/media/src/rtpengine_client.cpp
  ims/media/src/sdp_rewriter.cpp
)
target_include_directories(ims_lib PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/core/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/sip/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/auth/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/storage/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/scscf/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/icscf/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/pcscf/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/media/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/ipsec/include
  ${CMAKE_CURRENT_SOURCE_DIR}/ims/policy/include
)
target_link_libraries(ims_lib PUBLIC
  spdlog::spdlog
  yaml-cpp::yaml-cpp
  OpenSSL::Crypto
)

if (NOT IMS_WITH_EXOSIP)
  message(FATAL_ERROR "IMS_WITH_EXOSIP=OFF is not supported (no stubs/mocks allowed). Please build with IMS_WITH_EXOSIP=ON.")
endif()

if (IMS_WITH_EXOSIP)
  # 强制下载并构建 osip2/exosip2（避免依赖系统包）
  set(THIRD_PARTY_PREFIX ${CMAKE_BINARY_DIR}/third_party)
  set(OSIP_PREFIX ${THIRD_PARTY_PREFIX}/osip)
  set(EXOSIP_PREFIX ${THIRD_PARTY_PREFIX}/exosip)
  set(OSIP_INSTALL_DIR ${THIRD_PARTY_PREFIX}/install/osip)
  set(EXOSIP_INSTALL_DIR ${THIRD_PARTY_PREFIX}/install/exosip)

  # 优先使用本地已下载的 tar.gz（更稳定、离线可用）
  set(OSIP_TARBALL ${CMAKE_CURRENT_SOURCE_DIR}/libosip2-5.3.0.tar.gz)
  set(EXOSIP_TARBALL ${CMAKE_CURRENT_SOURCE_DIR}/libexosip2-5.3.0.tar.gz)
  set(OSIP_HAS_LOCAL_TARBALL OFF)
  set(EXOSIP_HAS_LOCAL_TARBALL OFF)
  if (EXISTS ${OSIP_TARBALL})
    set(OSIP_HAS_LOCAL_TARBALL ON)
  endif()
  if (EXISTS ${EXOSIP_TARBALL})
    set(EXOSIP_HAS_LOCAL_TARBALL ON)
  endif()

  if (OSIP_HAS_LOCAL_TARBALL)
    message(STATUS "Using local osip2 tarball: ${OSIP_TARBALL}")
    ExternalProject_Add(osip2_ep
      PREFIX ${OSIP_PREFIX}
      URL ${OSIP_TARBALL}
      INSTALL_DIR ${OSIP_INSTALL_DIR}
      CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && (test -f ./configure || autoreconf -fi) && ./configure --prefix=<INSTALL_DIR>"
      BUILD_COMMAND $(MAKE)
      INSTALL_COMMAND $(MAKE) install
      BUILD_IN_SOURCE 1
    )
  else()
    message(STATUS "Using osip2 from git (Savannah)")
    ExternalProject_Add(osip2_ep
      PREFIX ${OSIP_PREFIX}
      GIT_REPOSITORY https://git.savannah.gnu.org/git/osip.git
      GIT_TAG master
      UPDATE_COMMAND ""
      INSTALL_DIR ${OSIP_INSTALL_DIR}
      CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && autoreconf -fi && ./configure --prefix=<INSTALL_DIR>"
      BUILD_COMMAND $(MAKE)
      INSTALL_COMMAND $(MAKE) install
      BUILD_IN_SOURCE 1
    )
  endif()

  if (EXOSIP_HAS_LOCAL_TARBALL)
    message(STATUS "Using local exosip2 tarball: ${EXOSIP_TARBALL}")
    ExternalProject_Add(exosip2_ep
      PREFIX ${EXOSIP_PREFIX}
      URL ${EXOSIP_TARBALL}
      INSTALL_DIR ${EXOSIP_INSTALL_DIR}
      CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && (test -f ./configure || autoreconf -fi) && PKG_CONFIG_PATH=${OSIP_INSTALL_DIR}/lib/pkgconfig CPPFLAGS=-I${OSIP_INSTALL_DIR}/include LDFLAGS=-L${OSIP_INSTALL_DIR}/lib ./configure --prefix=<INSTALL_DIR> --with-osip=${OSIP_INSTALL_DIR}"
      BUILD_COMMAND $(MAKE)
      INSTALL_COMMAND $(MAKE) install
      BUILD_IN_SOURCE 1
      DEPENDS osip2_ep
    )
  else()
    message(STATUS "Using exosip2 from git (Savannah)")
    ExternalProject_Add(exosip2_ep
      PREFIX ${EXOSIP_PREFIX}
      GIT_REPOSITORY https://git.savannah.nongnu.org/git/exosip.git
      GIT_TAG master
      UPDATE_COMMAND ""
      INSTALL_DIR ${EXOSIP_INSTALL_DIR}
      CONFIGURE_COMMAND sh -c "cd <SOURCE_DIR> && autoreconf -fi && PKG_CONFIG_PATH=${OSIP_INSTALL_DIR}/lib/pkgconfig CPPFLAGS=-I${OSIP_INSTALL_DIR}/include LDFLAGS=-L${OSIP_INSTALL_DIR}/lib ./configure --prefix=<INSTALL_DIR> --with-osip=${OSIP_INSTALL_DIR}"
      BUILD_COMMAND $(MAKE)
      INSTALL_COMMAND $(MAKE) install
      BUILD_IN_SOURCE 1
      DEPENDS osip2_ep
    )
  endif()

  add_dependencies(ims_lib osip2_ep exosip2_ep)
  target_compile_definitions(ims_lib PUBLIC IMS_HAS_EXOSIP=1)
  target_include_directories(ims_lib PRIVATE
    ${OSIP_INSTALL_DIR}/include
    ${EXOSIP_INSTALL_DIR}/include
  )
  target_link_directories(ims_lib PUBLIC
    ${OSIP_INSTALL_DIR}/lib
    ${EXOSIP_INSTALL_DIR}/lib
  )
  target_link_libraries(ims_lib PUBLIC
    osip2
    osipparser2
    eXosip2
  )
else()
  target_compile_definitions(ims_lib PUBLIC IMS_HAS_EXOSIP=0)
endif()

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

enable_testing()
add_executable(ims_tests
  ims/tests/test_registration_sm.cpp
  ims/tests/test_sdp_rewriter.cpp
  ims/tests/test_location_service.cpp
)
target_link_libraries(ims_tests PRIVATE ims_lib GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(ims_tests)

