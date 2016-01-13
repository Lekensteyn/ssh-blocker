cmake_minimum_required(VERSION 3.0)
project(ssh-blocker VERSION 0.2 LANGUAGES C)

option(ENABLE_SYSTEMD "Support for systemd as log provider")

set(check_cflags
    -pie
    -fPIE
    -fstack-protector-all
    -Wall -Wextra -Wlogical-op -Wunused-macros -Wstack-protector -Wformat-security
)
# _FORTIFY_SOURCE requires optimization
if(CMAKE_BUILD_TYPE MATCHES ".*[Rr][Ee][Ll].*")
    list(APPEND check_cflags -D_FORTIFY_SOURCE=2)
endif()

list(REVERSE check_cflags)
foreach(_flag IN LISTS check_cflags)
    set(CMAKE_C_FLAGS "${_flag} ${CMAKE_C_FLAGS}")
endforeach()

set(ssh-blocker_SOURCES
    ssh-blocker-pcre.c
    iplist.c
    ipset.c
    regex.c
)


# Find external libraries
find_package(PkgConfig REQUIRED)
pkg_check_modules(cap   REQUIRED libcap)
pkg_check_modules(ipset REQUIRED libipset)
pkg_check_modules(pcre  REQUIRED libpcre)
set(ssh-blocker_LIBS
    ${cap_LIBRARIES}
    ${pcre_LIBRARIES}
    ${ipset_LIBRARIES}
)

if(ENABLE_SYSTEMD)
    pkg_check_modules(systemd REQUIRED libsystemd-journal)
    set(HAVE_SYSTEMD 1)
    list(APPEND ssh-blocker_SOURCES log-systemd.c)
    list(APPEND ssh-blocker_LIBS ${systemd_LIBRARIES})
else()
    list(APPEND ssh-blocker_SOURCES log-pipe.c)
endif()


# program ssh-blocker
add_executable(ssh-blocker ${ssh-blocker_SOURCES})
target_link_libraries(ssh-blocker ${ssh-blocker_LIBS})
set_target_properties(ssh-blocker PROPERTIES
    COMPILE_DEFINITIONS HAVE_CONFIG_H)

# Make definitions such as HAVE_SYSTEMD available.
include_directories("${CMAKE_CURRENT_BINARY_DIR}")
configure_file(config.h.cmake config.h)
