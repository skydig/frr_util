#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define IPV4_LEN 19

#define IFNAMESIZE 16

enum DumpMsgType
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
  IPROUTE = 1,
  OSPFROUTE,
  OSPFINTF,
  OSPFINFO,
  OSPFNEI,
};
#ifndef __cplusplus
typedef uint8_t DumpMsgType;
#endif // __cplusplus

enum RedistRouteType
#ifdef __cplusplus
  : uint8_t
#endif // __cplusplus
 {
  Kernel = 1,
  Connected,
  Static,
  Default,
};
#ifndef __cplusplus
typedef uint8_t RedistRouteType;
#endif // __cplusplus

/**
 * idx is 0 to 65535 reserved, not used
 * area[0-4294967295]
 * lo is loopback, example 192.192.192.192
 * error_msg is buf allocaed by caller
 * error_msg_len is buf length
 */
typedef struct OspfLoopback {
  uint16_t idx;
  uint32_t area;
  const char *lo;
  char *error_msg;
  uint16_t error_msg_len;
} OspfLoopback;

/**
 * router_id is router's id, example 1.1.1.1
 * error_msg is buf allocaed by caller
 * error_msg_len is buf length
 */
typedef struct OspfRouterId {
  const char *router_id;
  char *error_msg;
  uint16_t error_msg_len;
} OspfRouterId;

/**
 * gateway is ip of gateway, example 192.168.3.1
 * dest_ipmask is ip network/host address with mask, example 192.168.3.0/24, 192.168.3.4/32
 * intf_name is interface name
 * rt_type is gateway or interface, 1:gateway, 0:interface
 * config is 1, install static route, config is 0, uninstall static route
 * error_msg is buf allocaed by caller
 * error_msg_len is buf length
 */
typedef struct OspfStaticRoute {
  const char *gateway;
  const char *dest_ipmask;
  const char *intf_name;
  uint8_t rt_type;
  int32_t config;
  char *error_msg;
  uint16_t error_msg_len;
} OspfStaticRoute;

/**
 * name is interface name
 * flags come from if.h
 * IFF_UP                          = 1<<0,
 * IFF_BROADCAST                   = 1<<1,
 * IFF_DEBUG                       = 1<<2,
 * IFF_LOOPBACK                    = 1<<3,
 * IFF_POINTOPOINT                 = 1<<4,
 * IFF_NOTRAILERS                  = 1<<5,
 * IFF_RUNNING                     = 1<<6,
 * IFF_NOARP                       = 1<<7,
 * IFF_PROMISC                     = 1<<8,
 * IFF_ALLMULTI                    = 1<<9,
 * IFF_MASTER                      = 1<<10,
 * IFF_SLAVE                       = 1<<11,
 * IFF_MULTICAST                   = 1<<12,
 * IFF_PORTSEL                     = 1<<13,
 * IFF_AUTOMEDIA                   = 1<<14,
 * IFF_DYNAMIC                     = 1<<15,
 * IFF_LOWER_UP                    = 1<<16,
 * IFF_DORMANT                     = 1<<17,
 * IFF_ECHO                        = 1<<18,
 *
 * ip is like 192.168.3.2
 * prefix_len is [0..32]
 */
typedef struct Link {
  char name[IFNAMESIZE];
  char ip[IPV4_LEN];
  uint32_t flags;
  uint8_t prefix_len;
  uint32_t mtu;
} Link;

/**
 * area[0-4294967295]
 * name is interface name
 * ipmask is interface ip with mask, example 192.168.3.22/24
 * config is 1, install this interface, config is 0, uninstall this interface
 * error_msg is buf allocated by caller
 * error_msg_len is buf length
 */
typedef struct OspfIntf {
  uint32_t area;
  const char *name;
  const char *ipmask;
  int32_t config;
  char *error_msg;
  uint16_t error_msg_len;
} OspfIntf;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * install/uninstall static route
 * return < 0; error_msg should be checked
 * return == 0; means success
 */
int32_t ConfOspfLoopback(struct OspfLoopback *a);

/**
 * install/uninstall static route
 * return < 0; error_msg should be checked
 * return == 0; means success
 */
int32_t ConfOspfRouterId(struct OspfRouterId *a);

/**
 * install/uninstall static route
 * return < 0; error_msg should be checked
 * return == 0; means success
 */
int32_t ConfOspfStaticRt(struct OspfStaticRoute *a);

/**
 * redistribute route
 * metric is (0-16777214)
 * metric type is (1-2)
 * return ==-1 metic error;  ==-2 metric type error; ==-3 other error
 * return == 0; means success
 * metric = -1 means ignore metric
 * metric_type = -1 means ignore metric_type
 * yes_or_no: redistribute(1) or not(0）, if yes_or_no == 0, metirc metric_type parameters all be
 * ignored
 */
int32_t RedistRoute(RedistRouteType rrt, int32_t metric, int8_t metric_type, int8_t yes_or_no);

/**
 * get all OS interfaces
 * size is length of Link array
 * return < 0; failed
 * return >= 0; means success, how many Link are fetched
 */
int32_t DumpLinks(struct Link *links, uint32_t size);

/**
 * get one network interfaces flags and ip etc
 * Link's name shoud be set as input parameter
 * size is length of Link array
 * return < 0; failed
 * return == 0; means success
 */
int32_t GetOneLink(struct Link *one_link, uint32_t size);

/**
 * conf network interface ip
 * name is interface name
 * ip is ,for example, 192.168.3.1/23
 * return < 0; failed
 * return = -2 ;ip format error
 * return == 0; means success
 */
int32_t ConfLinkIp(const char *name, const char *ip);

/**
 * add/del kernel route
 * gateway is next hop gatway ip
 * dest_ip is destination ip (network or host, example:network 3.3.3.3/21 or host 3.3.3.3 which is
 * equal to 3.3.3.3/32);for default route,dest_ip should be 0.0.0.0/0
 * config=1, add; config=0,delete
 * return < 0; failed
 * return == 0; means success
 * error_msg is buf allocated by caller
 * error_msg_len is buf length
 */
int32_t ConfKernelRoute(const char *gateway,
                        const char *dest_ip,
                        int8_t config,
                        char *error_msg,
                        uint16_t error_msg_len);

/**
 * conf network interface promiscuous mode
 * name is interface name
 * is_promisc, 1 promiscuous, 0 no-promiscuous
 * return < 0; failed
 * return == 0; means success
 */
int32_t ConfLinkPromisc(const char *name, int32_t is_promisc);

/**
 * conf network interface status(up/down)
 * up_down, 0 up, 1 down
 * return < 0;  failed
 * return == 0; means success
 */
int32_t ConfLinkAdminStatus(const char *name, int32_t up_down);

/**
 * conf network interface mtu
 * mtu is minimum transfer unit
 * return < 0; failed
 * return == 0; means success
 */
int32_t ConfLinkMtu(const char *name, uint16_t mtu);

/**
 * add/remove interface to ospf
 * return < 0; error_msg should be checked
 * return == 0; means success
 */
int32_t ConfOspfInterface(struct OspfIntf *a);

/**
 * before calling of dump..., call this function to get message length
 */
uint32_t get_dump_len(DumpMsgType t);

/**
 * dump ip route as json message
 */
void dump_ip_routes(char *iproute, uintptr_t len);

/**
 * dump ospf route as json message
 */
void dump_ospf_routes(char *ospfroute, uintptr_t len);

/**
 * dump ospf intf as json message
 */
void dump_ospf_intf(char *ospfintf, uintptr_t len);

/**
 * dump ospf info as json message
 */
void dump_ospf_info(char *ospfinfo, uintptr_t len);

/**
 * dump ospf neighbor as json message
 */
void dump_ospf_nei(char *ospfnei, uintptr_t len);

/**
 * mac is XX:XX:XX:XX:XX:XX
 * name is interface name, example, eth0
 * return = -1 parameter error,
 * return = -2 socket error,
 * return = -3 set hw address error,
 * return == 0; means success
 */
int32_t SetMac(const char *name, const char *mac);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
