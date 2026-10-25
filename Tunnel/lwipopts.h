#ifndef LWIPOPTS_H
#define LWIPOPTS_H

#define NO_SYS                  1
#define LWIP_TCP                1
#define LWIP_UDP                0
#define LWIP_ICMP               1
#define LWIP_ARP                0
#define LWIP_DHCP               0
#define LWIP_DNS                0
#define LWIP_AUTOIP             0
#define LWIP_IGMP               0
#define LWIP_IPV6               0
#define LWIP_NETIF_HOSTNAME     0
#define LWIP_STATS              0
#define LWIP_NETCONN            0
#define LWIP_SOCKET             0

#define MEMP_NUM_TCP_PCB        32
#define MEMP_NUM_TCP_PCB_LISTEN 8
#define MEMP_NUM_TCP_SEG        256
#define MEMP_NUM_PBUF           32
// Куча lwIP (MEM): из неё и входные pbuf (PBUF_RAM в lwip_bridge_input),
// и копии tcp_write. 1MB: окно 64K на соединение × десяток соединений —
// unacked-данные лежат в куче, при нехватке input молча дропался бы
// на pbuf_alloc (счётчик inmem в io-строке журнала).
#define MEM_SIZE                (1024 * 1024)
#define PBUF_POOL_SIZE          64
#define PBUF_POOL_BUFSIZE       1600

// Пропускная способность ≈ WND/RTT. При 16K и RTT 0.2–0.4s через воркер
// выходило ~50–80 КБ/с: тяжёлый updates.getDifference не успевал пройти
// за 12s response-watchdog Telegram-iOS → весь bootstrap-батч уходил
// на пересылку → вечный цикл «Соединение...». 64K — четырёхкратный запас.
#define TCP_SND_BUF             65535
#define TCP_WND                 65535
#define TCP_MSS                 1460

#define LWIP_NETIF_TX_SINGLE_PBUF 1
#define LWIP_CHECKSUM_CTRL_PER_NETIF 0
#define CHECKSUM_GEN_IP         0
#define CHECKSUM_GEN_UDP        0
#define CHECKSUM_GEN_TCP        0
#define CHECKSUM_CHECK_IP       0
#define CHECKSUM_CHECK_UDP      0
#define CHECKSUM_CHECK_TCP      0

#define LWIP_TIMEVAL_PRIVATE    0
#define LWIP_NOASSERT           1

#endif
