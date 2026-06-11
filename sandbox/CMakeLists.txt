cmake_minimum_required(VERSION 3.16)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TON_SANDBOX_SOURCE sandbox.cpp)
add_executable(ton-sandbox ${TON_SANDBOX_SOURCE})
target_compile_features(ton-sandbox PRIVATE cxx_std_20)
target_include_directories(ton-sandbox PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../)
target_link_libraries(ton-sandbox PUBLIC tdutils ton_crypto adnl dht tl_api quic)
