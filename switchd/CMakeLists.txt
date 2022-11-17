project(switchd)

set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-but-set-variable")
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(TOFINO_INSTALL $ENV{SDE_INSTALL})

set(TOFINO_LIBS
    bf_switch
    bfsys
    bfutils
    thrift
    # tofinopdfixed_thrift
    clish
    grpc
    avago
    driver
    piall
    piprotogrpc
    piprotobuf
    pifeproto
    pthread
    )

include_directories(
    ${TOFINO_INSTALL}/include
    ../common/cpp
    src)
link_directories(${TOFINO_INSTALL}/lib)

aux_source_directory(src SRC_LIST)
aux_source_directory(../common/cpp COMMON_LIST)
add_executable(countmin_drv countmin.cpp ${SRC_LIST} ${COMMON_LIST})
add_executable(ToyDrvServer test/ToyDrvServer.cc ${SRC_LIST} ${COMMON_LIST})

set(SwitchdTargets
    countmin_drv
    ToyDrvServer)

foreach(_target ${SwitchdTargets})
    target_link_libraries(${_target} PUBLIC
        ${TOFINO_LIBS}
        grpc_proto)
endforeach()

add_executable(err_filter err_filter.cpp)
