LOCAL_PATH := $(call my-dir)/..

include $(CLEAR_VARS)
LOCAL_MODULE := libancillary
LOCAL_C_INCLUDES := $(LOCAL_PATH)/third_party/libancillary
LOCAL_SRC_FILES := \
    third_party/libancillary/fd_recv.c \
    third_party/libancillary/fd_send.c
include $(BUILD_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := tun2socks
LOCAL_CFLAGS := -std=gnu99
LOCAL_CFLAGS += -DBADVPN_THREADWORK_USE_PTHREAD -DBADVPN_LINUX
LOCAL_CFLAGS += -DBADVPN_BREACTOR_BADVPN -D_GNU_SOURCE
LOCAL_CFLAGS += -DBADVPN_USE_SIGNALFD -DBADVPN_USE_EPOLL
LOCAL_CFLAGS += -DBADVPN_LITTLE_ENDIAN -DBADVPN_THREAD_SAFE
LOCAL_CFLAGS += -DNDEBUG -DANDROID
LOCAL_STATIC_LIBRARIES := libancillary
LOCAL_C_INCLUDES := \
    $(LOCAL_PATH)/third_party/badvpn/lwip/src/include/ipv4 \
    $(LOCAL_PATH)/third_party/badvpn/lwip/src/include/ipv6 \
    $(LOCAL_PATH)/third_party/badvpn/lwip/src/include \
    $(LOCAL_PATH)/third_party/badvpn/lwip/custom \
    $(LOCAL_PATH)/third_party/badvpn \
    $(LOCAL_PATH)/third_party/libancillary
LOCAL_SRC_FILES := \
    third_party/badvpn/base/BLog_syslog.c \
    third_party/badvpn/system/BReactor_badvpn.c \
    third_party/badvpn/system/BSignal.c \
    third_party/badvpn/system/BConnection_common.c \
    third_party/badvpn/system/BConnection_unix.c \
    third_party/badvpn/system/BTime.c \
    third_party/badvpn/system/BUnixSignal.c \
    third_party/badvpn/system/BNetwork.c \
    third_party/badvpn/system/BDatagram_common.c \
    third_party/badvpn/system/BDatagram_unix.c \
    third_party/badvpn/flow/StreamRecvInterface.c \
    third_party/badvpn/flow/PacketRecvInterface.c \
    third_party/badvpn/flow/PacketPassInterface.c \
    third_party/badvpn/flow/StreamPassInterface.c \
    third_party/badvpn/flow/SinglePacketBuffer.c \
    third_party/badvpn/flow/BufferWriter.c \
    third_party/badvpn/flow/PacketBuffer.c \
    third_party/badvpn/flow/PacketStreamSender.c \
    third_party/badvpn/flow/PacketPassConnector.c \
    third_party/badvpn/flow/PacketProtoFlow.c \
    third_party/badvpn/flow/PacketProtoEncoder.c \
    third_party/badvpn/flow/PacketProtoDecoder.c \
    third_party/badvpn/socksclient/BSocksClient.c \
    third_party/badvpn/tuntap/BTap.c \
    third_party/badvpn/lwip/src/core/udp.c \
    third_party/badvpn/lwip/src/core/memp.c \
    third_party/badvpn/lwip/src/core/init.c \
    third_party/badvpn/lwip/src/core/pbuf.c \
    third_party/badvpn/lwip/src/core/tcp.c \
    third_party/badvpn/lwip/src/core/tcp_out.c \
    third_party/badvpn/lwip/src/core/netif.c \
    third_party/badvpn/lwip/src/core/def.c \
    third_party/badvpn/lwip/src/core/ip.c \
    third_party/badvpn/lwip/src/core/mem.c \
    third_party/badvpn/lwip/src/core/tcp_in.c \
    third_party/badvpn/lwip/src/core/stats.c \
    third_party/badvpn/lwip/src/core/inet_chksum.c \
    third_party/badvpn/lwip/src/core/timeouts.c \
    third_party/badvpn/lwip/src/core/ipv4/icmp.c \
    third_party/badvpn/lwip/src/core/ipv4/igmp.c \
    third_party/badvpn/lwip/src/core/ipv4/ip4_addr.c \
    third_party/badvpn/lwip/src/core/ipv4/ip4_frag.c \
    third_party/badvpn/lwip/src/core/ipv4/ip4.c \
    third_party/badvpn/lwip/src/core/ipv4/autoip.c \
    third_party/badvpn/lwip/src/core/ipv6/ethip6.c \
    third_party/badvpn/lwip/src/core/ipv6/inet6.c \
    third_party/badvpn/lwip/src/core/ipv6/ip6_addr.c \
    third_party/badvpn/lwip/src/core/ipv6/mld6.c \
    third_party/badvpn/lwip/src/core/ipv6/dhcp6.c \
    third_party/badvpn/lwip/src/core/ipv6/icmp6.c \
    third_party/badvpn/lwip/src/core/ipv6/ip6.c \
    third_party/badvpn/lwip/src/core/ipv6/ip6_frag.c \
    third_party/badvpn/lwip/src/core/ipv6/nd6.c \
    third_party/badvpn/lwip/custom/sys.c \
    third_party/badvpn/tun2socks/tun2socks.c \
    third_party/badvpn/base/DebugObject.c \
    third_party/badvpn/base/BLog.c \
    third_party/badvpn/base/BPending.c \
    third_party/badvpn/flowextra/PacketPassInactivityMonitor.c \
    third_party/badvpn/tun2socks/SocksUdpGwClient.c \
    third_party/badvpn/udpgw_client/UdpGwClient.c \
    third_party/badvpn/socks_udp_client/SocksUdpClient.c
LOCAL_LDLIBS := -ldl -llog
LOCAL_LDFLAGS := -Wl,--build-id=none
LOCAL_LDFLAGS += -Wl,-z,common-page-size=16384
LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
LOCAL_BUILD_SCRIPT := BUILD_EXECUTABLE
LOCAL_MAKEFILE := $(local-makefile)
$(call check-defined-LOCAL_MODULE,$(LOCAL_BUILD_SCRIPT))
$(call check-LOCAL_MODULE,$(LOCAL_MAKEFILE))
$(call check-LOCAL_MODULE_FILENAME)
my := TARGET_
$(call handle-module-filename,lib,$(TARGET_SONAME_EXTENSION))
$(call handle-module-built)
LOCAL_MODULE_CLASS := EXECUTABLE
include $(BUILD_SYSTEM)/build-module.mk
