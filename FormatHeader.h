#ifndef FORMATHEADER_H
#define FORMATHEADER_H


//字节数
typedef  unsigned char u_char;//1
typedef  unsigned short u_short;//2
typedef  unsigned int u_int;//4
typedef  unsigned long u_long;//4
//不满1字节，按一字节算


//以太网帧格式
//目的 MAC 地址、源 MAC 地址和类型/长度字段各占 6 字节、6 字节和 2 字节，共计 14 字节
typedef struct mac_header{
    u_char mac_des_host[6];//目的 MAC 地址
    u_char mac_src_host[6];//源 MAC 地址
    u_short type;           //以太网类型
}MAC_HEADER;

//ip报文格式  -》ipv4
typedef struct ip_header{
    u_char version_length;// 版本号和头部长度
    u_char TOS;// 服务类型
    u_short total_length;// 总长度
    u_short identfication;// // 标识
    u_short flags_offset;// 标志和分片偏移
    u_char ttl;// 生存时间
    u_char protocol;// 协议类型
    //指明IP层所封装的上层协议类型，如ICMP -> 1、IGMP -> 2 、TCP -> 6、UDP -> 17、EIGRP -> 88 、OSPF -> 89等等
    u_short checksum;// 头部校验和
    u_int src_addr;// 源 IP 地址
    u_int des_addr;// 目的 IP 地址


}IP_HEADER;

//ipv6
//not joined code yet
typedef struct ipv6_header{
    u_int version_length;//版本和流量区分，留标签
    u_short payload_length;// 载荷长度
    u_char next_headr;// 下一个报头类型
    u_char hop_limit;// 跳数限制，类似ttl
    u_char src_addr[16];    // 源 IPv6 地址
    u_char des_addr[16];   // 目的 IPv6 地址
}IPV6_HEADER;  //xxxx

//tcp
typedef struct tcp_header{
    u_short src_port;
    u_short des_port;
    u_int   seq;
    u_int    ack;
    u_char header_len;
    u_char flags;
    u_short window;
    u_short checksum;
    u_short utg_ptr;
}TCP_HEADER;

//udp
typedef struct udp_header{
    u_short src_port;
    u_short des_port;
    u_short data_len;
    u_short checksum;
}UDP_HEADER;

//icmp
typedef struct icmp_header{
    u_char type; //以0 8举例 就是ping的response和request
    u_char code;
    u_short checksum;
    u_short identification;
    u_short seq;
}ICMP_HEADER;

//arp
typedef struct arp_header{
    u_short hardware_type;   //硬件类型
    u_short protocol_type;   //
    u_char hardware_length;       //
    u_char protocol_length;        //
    u_short op_code;         // 操作码

    u_char src_eth_addr[6];  // 源硬件地址
    u_char src_ip_addr[4];   // 源协议地址
    u_char des_eth_addr[6];  // 目标硬件地址
    u_char des_ip_addr[4];   // 目标协议地址

}ARP_HEADER;

//dns
typedef struct dns_header{  // 12 byte
    u_short identification; // 会话标志
    u_short flags;          // 标志
    u_short question;       // 问题计数
    u_short answer;         // 回答资源记录数
    u_short authority;      // 权威服务器回答计数 后面俩通常都是0
    u_short additional;     //附加的回答计数
}DNS_HEADER;

// dns question
typedef struct dns_question{
    // char* name;          // Non-fixed
    u_short query_type;     // 2 byte
    u_short query_class;    // 2 byte
}DNS_QUESITON;

//dns answer
typedef struct dns_answer{
    // char* name          // Non-fixed
    u_short answer_type;   // 2 byte
    u_short answer_class;  // 2 byte
    u_int TTL;             // 4 byte
    u_short dataLength;    // 2 byte
    //char* name           // Non-fixed
}DNS_ANSWER;

#endif // FORMAT_H
