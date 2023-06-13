#include "datapacket.h"
#include<QMetaType>
#include"winsock2.h"
DataPacket::DataPacket()
{
    qRegisterMetaType<DataPacket>("DataPacket");//注册
    this->info="";
    this->timeStamp="";
    this->data_length=0;
    this->package_type=0;
    this->pkt_content=nullptr;
}
void DataPacket::setDataLength(int data_length)
{
    this->data_length=data_length;
}
void DataPacket::setTimeStamp(QString timestamp)
{
    this->timeStamp=timestamp;
}
void DataPacket::setInfo(QString infor)
{
    this->info=infor;
}
void DataPacket::setPackageType(int packagetype)
{
    this->package_type=packagetype;
}
void DataPacket::setPointer(const u_char* pkt,int size)
{
    this->pkt_content=(u_char*)malloc(size);
    if(this->pkt_content!=nullptr)
        memcpy((u_char*)this->pkt_content,pkt,size);
    else this->pkt_content=nullptr;
}

QString DataPacket::getDataLength()
{
    return QString::number(this->data_length);
}
QString DataPacket::getTimeStamp()
{
    return this->timeStamp;
}
QString DataPacket::getInfo()
{
    return this->info;
}
QString DataPacket::getPackageType()
{
    switch(this->package_type){
    case 1:return "ARP";
    case 2:return "ICMP";
    case 3:return "TCP";
    case 4:return "UDP";
    case 5:return "DNS";
    case 6:return "TLS";
    case 7:return "SSL";
    default:return "";
    }
}
QString DataPacket::byteToString(u_char*str,int size)
{
    QString res="";
    for(int i=0;i<size;++i)
    {
        char one=str[i]>>4;  //高4位
        if(one>=0x0A){
            one+=0x41-0x0A;
        }
        else{
            one+=0x30;
        }
        char two=str[i]&0xF; //低4位
        if(two>=0x0A){
            two+=0x41-0x0A;
        }
        else{
            two+=0x30;
        }
        res.append(one);
        res.append(two);
    }
    return res;
}
//modify :6/11  return getarp/source/destination/ip
QString DataPacket::getSource()
{
    if(this->package_type==1){
        return this->getARPSrc_Ip_addr();
    }
    else return this->getSrcIpAddr();
}

QString DataPacket::getDestination()
{
    if(this->package_type==1){
        return this->getARPDes_Ip_addr();
    }
    else return this->getDesIpAddr();
}
//xxxx

//***********************************MAC********************************//
QString DataPacket::getDesMacAddr()
{
    MAC_HEADER*eth;
    eth=(MAC_HEADER*)(pkt_content);
    u_char *addr=eth->mac_des_host;
    if(addr){
        QString res="("+byteToString(addr,1)+"-"
        +byteToString((addr+1),1)+":"
        +byteToString((addr+2),1)+":"
        +byteToString((addr+3),1)+":"
        +byteToString((addr+4),1)+":"
        +byteToString((addr+5),1)+")";
        if(res=="FF-FF-FF-FF-FF-FF")return "FF-FF-FF-FF-FF-FF(Broadcast)";
        else return res;
    }
    return "";
}

QString DataPacket::getSrcMacAddr()
{
    MAC_HEADER*eth;
    eth=(MAC_HEADER*)(pkt_content);
    u_char *addr=eth->mac_src_host;
    if(addr){
        QString res="("+byteToString(addr,1)+"-"
        +byteToString((addr+1),1)+":"
        +byteToString((addr+2),1)+":"
        +byteToString((addr+3),1)+":"
        +byteToString((addr+4),1)+":"
        +byteToString((addr+5),1)+")";
        if(res=="FF-FF-FF-FF-FF-FF")return "FF-FF-FF-FF-FF-FF(Broadcast)";
        else return res;
    }
    return  "";
}
QString DataPacket::getMacType()
{
    MAC_HEADER* eth;
    eth=(MAC_HEADER*)(pkt_content);
    u_short type=ntohs(eth->type);
    if(type==0x0800)return "IPV4(0x0800)";
    else if(type==0x0806)return "ARP(0x0806)";
    else return "";

}
//***********************IP******************************//
QString DataPacket::getDesIpAddr()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr=ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}
QString DataPacket::getSrcIpAddr()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr=ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPacket::getVersion()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ip->version_length>>4);
}
QString  DataPacket::getHeadLength()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    QString res="";
    int length=ip->version_length&0x0F;
    if(length==5) res="20 bytes (5)"; //normal  *4
    else res=QString::number(length*5)+"bytes ("+ QString::number(length) + ")";
    return res;
}
QString DataPacket::getTos()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ip->TOS);
}
QString DataPacket::getTotalLength()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(ip->total_length));
}
QString DataPacket::getIdentification()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(ip->identfication),16);
}

QString DataPacket::getFlags()  //标志  3bit  ，下面取具体标志
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(((ip->flags_offset)& 0xe000)>>8),16);

}
// 第一位保留为始终为 0
QString DataPacket::getIpReservedBit()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs((ip->flags_offset)&0x8000)>>15);
}
QString DataPacket::getIpDF()// DF位为 1 时表示该分组不能被分段
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs((ip->flags_offset)&0x4000)>>14);
}
QString DataPacket::getIpMF()//MF位为 1 时表示后面还有该分组的分段，在有分段的情况下，除了最后一个分段该位为 0 外，其他分段该位都为 1
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs((ip->flags_offset)&0x2000)>>13);
}
QString DataPacket::getOffset()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(ip->flags_offset&0x1FFF));
}
QString DataPacket::getIpTTL()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(ip->ttl));
}
QString DataPacket::getIpProtocol()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    int protocol=ip->protocol;
    switch(protocol){
    case 1:return "ICMP(1)";
    case 6:return "TCP(6)";
    case 17:return "UDP(17)";
    default:return "";
    }
    return "";
}
QString DataPacket::getIpCheckSum()
{
    IP_HEADER*ip;
    ip=(IP_HEADER*)(pkt_content+14);
    return QString::number(ntohs(ip->checksum),16);
}
//***********************ICMP******************//

QString DataPacket::getICMPType()
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(icmp->type));
}
QString DataPacket::getICMPCode()
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(icmp->code));
}
QString DataPacket::getICMPChecksum()
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(icmp->checksum),16);
}
QString DataPacket::getICMPIdentification()
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(icmp->identification));
}
QString DataPacket::getICMPSequence()
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(icmp->seq));
}
QString DataPacket::getIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}
/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
QString DataPacket::getARPHardwareType()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    int type=ntohs(arp->hardware_type);
    QString res="";
    if(type==0x0001) res="Ethernet(1) ";
    else res=QString::number(type);
    return res;
}
QString DataPacket::getARPProtocolType()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    int type=ntohs(arp->protocol_type);
    QString res="";
    if(type==0x0800)res="IPv4(0x0800)";
    else if(type==0x86DD)res="IPv6(0x86DD)";
    else res=QString::number(type);
    return res;
}
QString DataPacket::getHardware_length()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    return QString::number(arp->hardware_length);
}

QString DataPacket::getARPProtocol_length()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    return QString::number(arp->protocol_length);
}
QString DataPacket::getARPOp_Code()
{
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1) ";
    else if(code == 2) res = "reply(2) ";
    return res;
}
QString DataPacket::getARPSrc_Eth_addr()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    u_char *src_eth_addr;
    if(arp){
        src_eth_addr=arp->src_eth_addr;
        QString srcEth=byteToString(src_eth_addr,1)+":"
                +byteToString((src_eth_addr+1),1)+":"
                +byteToString((src_eth_addr+2),1)+":"
                +byteToString((src_eth_addr+3),1)+":"
                +byteToString((src_eth_addr+4),1)+":"
                +byteToString((src_eth_addr+5),1);
        return srcEth;
    }
    return "";

}
QString DataPacket::getARPSrc_Ip_addr()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    if(arp){
        u_char*addr=arp->src_ip_addr;
        QString srcip=QString::number(*addr)+"."
                +QString::number(*(addr+1))+"."
                +QString::number(*(addr+2))+"."
                +QString::number(*(addr+3));
        return srcip;
    }
    return "";
}
QString DataPacket::getARPDes_Eth_addr()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    u_char *des_eth_addr;
    if(arp){
        des_eth_addr=arp->des_eth_addr;
        QString desEth=byteToString(des_eth_addr,1)+":"
                +byteToString((des_eth_addr+1),1)+":"
                +byteToString((des_eth_addr+2),1)+":"
                +byteToString((des_eth_addr+3),1)+":"
                +byteToString((des_eth_addr+4),1)+":"
                +byteToString((des_eth_addr+5),1);
        return desEth;
    }
    return "";
}
QString DataPacket::getARPDes_Ip_addr()
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);
    if(arp){
        u_char* addr=arp->des_ip_addr;
        QString desip=QString::number(*addr)+"."
                +QString::number(*(addr+1))+"."
                +QString::number(*(addr+2))+"."
                +QString::number(*(addr+3));
        return desip;
    }
    return "";

}
//add 6/12
//*******************************udp*****************//
QString DataPacket::getUDPSrcport()
{
    UDP_HEADER*udp;
    udp=(UDP_HEADER*)(pkt_content+14+20);
    u_short port=ntohs(udp->src_port);
    if(port==53){
        return "domain(53)";
    }
    else return QString::number(port);
}
QString DataPacket::getUDPDesport()
{
    UDP_HEADER*udp;
    udp=(UDP_HEADER*)(pkt_content+14+20);
    u_short port=ntohs(udp->des_port);
    if(port==53){
        return "domain(53)";
    }
    else return QString::number(port);
}
QString DataPacket::getUDPDataLen()
{
    UDP_HEADER*udp;
    udp=(UDP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(udp->data_len));
}
QString DataPacket::getUDPChecksum()
{
    UDP_HEADER*udp;
    udp=(UDP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohs(udp->data_len),16);
}
//*******************tcp**********************//
/*
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
}TCP_HEADER;*/
QString DataPacket::getTcpSourcePort()               // get tcp source port
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    u_short port=ntohs(tcp->src_port);
    if(port==443){
        return "https(443)";
    }
    else if(port==80){
        return "http(80)";
    }
    else return QString::number(port);
}
QString DataPacket::getTcpDestinationPort()          // get tcp destination port
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    u_short port=ntohs(tcp->des_port);
    if(port==443){
        return "https(443)";
    }
    else if(port==80){
        return "http(80)";
    }
    else return QString::number(port);
}
QString DataPacket::getTcpSequence()                // get tcp sequence
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohl(tcp->seq));
}
QString DataPacket::getTcpAcknowledgment()           // get acknowlegment
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    return QString::number(ntohl(tcp->ack));
}
QString DataPacket::getTcpHeaderLength()             // get tcp head length
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    int len=(tcp->header_len>>4);
    if(len==5)return "20 bytes (5)";
    else return QString::number(len*4)+" bytes (" + QString::number(len) + ")";
}
QString DataPacket::getTcpRawHeaderLength()          // get tcp raw head length [default is 0x05]
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->header_len >> 4);
}
QString DataPacket::getTcpFlags()                    // get tcp flags
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);      // eg: 0x... (SYN or others)
}

QString DataPacket::getTcpFIN()                      // FIN flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x01));
}
QString DataPacket::getTcpSYN()                      // SYN flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x02)>>1);
}
QString DataPacket::getTcpRST()                     // RST flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x04)>>2);
}
QString DataPacket::getTcpPSH()                      // PSH flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x08)>>3);
}
QString DataPacket::getTcpACK()                      // ACK flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x10)>>4);
}
QString DataPacket::getTcpURG()                      // URG flag
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags)&0x20)>>5);
}
QString DataPacket::getTcpWindowSize()              // get tcp window size
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->window));
}
QString DataPacket::getTcpCheckSum()                 // get tcp checksum
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}
QString DataPacket::getTcpUrgentPointer()            // get tcp urgent pointer
{
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->utg_ptr));
}
QString DataPacket::getTcpOperationKind(int kind)    // get tcp option kind
{
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}
int DataPacket::getTcpOperationRawKind(int offset)   // get tcp raw option kind
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20  + 20+ offset);
    return *tcp;
}
/*
 * tcp optional parts
*/
bool DataPacket::getTcpOperationMSS(int offset,u_short& mss)                          // kind = 2
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 +  20+ offset);
    if(*tcp==2){
        tcp++;
        if(*tcp==4){
            tcp++;
            u_short *Mss=(u_short*)tcp;
            mss=ntohs(*Mss);
            return true;
        }
        else return false;
    }
    return false;
}
bool DataPacket::getTcpOperationWSOPT(int offset,u_char&shit)                        // kind = 3
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 +  20+ offset);
    if(*tcp==3){
        tcp++;
        if(*tcp==3){
            tcp++;
            shit=*tcp;
            return true;
        }
        else return false;
    }
    return false;

}
bool DataPacket::getTcpOperationSACKP(int offset)                                    // kind = 4
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 +  20+ offset);
    if(*tcp==4){
        return true;
    }
    else return false;
}
bool DataPacket::getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge)    // kind = 5
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    if(*tcp == 5){
        tcp++;
        length = *tcp;
        tcp++;
        u_int* pointer = (u_int*)tcp;
        for(int i = 0;i < (length - 2)/4;i++){
            u_int temp = htonl(*pointer);
            edge.push_back(temp);
            pointer++;
        }
        return true;
    }else return false;
}
bool DataPacket::getTcpOperationTSPOT(int offset,u_int& value,u_int&reply)            // kind = 8
{
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 +  20+ offset);
    if(*tcp==8){
        tcp++;
        if(*tcp==10){
            tcp++;
            u_int *pointer = (u_int*)(tcp);
            value = ntohl(*pointer);
            pointer++;
            reply = ntohl(*pointer);
            return true;
        }
        else return false;
    }
    return false;
}

//****************************************************************************************/
//Below for the time being 6/12
/**********************  dns **********************/

/* dns */
/********************** get dns transaction **********************/
QString DataPacket::getDnsTransactionId(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->identification),16);
}
/********************** get dns flag **********************/
QString DataPacket::getDnsFlags(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    int type = ntohs(dns->flags);
    QString info = "";
    if((type & 0xf800) == 0x0000){
        info = "(Standard query)";
    }
    else if((type & 0xf800) == 0x8000){
        info = "(Standard query response)";
    }
    return QString::number(type,16) + info;
}
/********************** get dns QR **********************/
QString DataPacket::getDnsFlagsQR(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x8000) >> 15);
}
/********************** get dns Operation code **********************/
QString DataPacket::getDnsFlagsOpcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x7800) >> 11);
}
/********************** get dns AA **********************/
QString DataPacket::getDnsFlagsAA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0400) >> 10);
}
/********************** get dns TC **********************/
QString DataPacket::getDnsFlagsTC(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0200) >> 9);
}
/********************** get dns RD **********************/
QString DataPacket::getDnsFlagsRD(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0100) >> 8);
}
/********************** get dns RA **********************/
QString DataPacket::getDnsFlagsRA(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0080) >> 7);
}
/********************** get dns Z(reserved) **********************/
QString DataPacket::getDnsFlagsZ(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x0070) >> 4);
}
/********************** get dns Response code **********************/
QString DataPacket::getDnsFlagsRcode(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number((ntohs(dns->flags) & 0x000f));
}
/********************** get dns Question number **********************/
QString DataPacket::getDnsQuestionNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->question));
}
/********************** get dns Answer number **********************/
QString DataPacket::getDnsAnswerNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->answer));
}
/********************** get dns Authority number **********************/
QString DataPacket::getDnsAuthorityNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->authority));
}
/********************** get dns Additional number **********************/
QString DataPacket::getDnsAdditionalNumber(){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    return QString::number(ntohs(dns->additional));
}
/********************** get dns query result **********************/
void DataPacket::getDnsQueriesDomain(QString&name,int&Type,int&Class){
    DNS_HEADER*dns;
    dns = (DNS_HEADER*)(pkt_content + 14 + 20 + 8);
    char*domain = (char*)(pkt_content + 14 + 20 + 8 + 12);
    while(*domain != 0x00){
        if(domain && (*domain) <= 64){
            int length = *domain;
            domain++;
            for(int k = 0;k < length;k++){
                name += (*domain);
                domain++;
            }
            name += ".";
        }else break;
    }
    domain++;
    name = name.left(name.length() - 1);
    DNS_QUESITON *qus = (DNS_QUESITON*)(domain);
    Type = ntohs(qus->query_type);
    Class = ntohs(qus->query_class);
}
/********************** get dns domian name **********************/
QString DataPacket::getDnsDomainName(int offset){
    char*dns;
    dns = (char*)(pkt_content + 14 + 20 + 8 + offset);
    QString name = "";
    while(dns && *dns != 0x00){
        if((unsigned char)(*dns) <= 64){
            int length = *dns;
            dns++;
            for(int k = 0;k<length;k++){
                name += (*dns);
                dns++;
            }
            name += ".";
        }else if(((*dns) & 0xc0) == 0xc0){
            int accOffset = (((*dns) & 0x3f) << 8);
            dns++;
            accOffset += (unsigned char)(*dns);
            name += getDnsDomainName(accOffset) + ".";
            dns++;
            break;
        }
    }
    name = name.left(name.length() - 1);
    return name;
}
/********************** get dns answer result **********************/
int DataPacket::getDnsAnswersDomain(int offset, QString &name1, u_short &Type, u_short &Class, u_int &ttl, u_short &dataLength,QString&name2){
    char*dns = (char*)(pkt_content + 14 + 20 + 8 + 12 + offset);
    if(((*dns) & 0xc0) == 0xc0){
        int accOffset = (((*dns) & 0x3f) << 8);
        dns++; //
        accOffset += (*dns);
        name1 = getDnsDomainName(accOffset);
        dns++; //
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        dns += (2 + 2 + 4 + 2);
        if(dataLength == 4){
            for(int i = 0;i < 4;i++){
                name2 += QString::number((unsigned char)(*dns));
                name2 += ".";
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (unsigned char)(*dns);
                    name2 += getDnsDomainName(accOffset) + ".";
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2;

    }else{
        name1 = getDnsDomainName(offset + 12);
        DNS_ANSWER*answer = (DNS_ANSWER*)(dns + name1.size() + 2);
        Type = ntohs(answer->answer_type);
        Class = ntohs(answer->answer_class);
        ttl = ntohl(answer->TTL);
        dataLength = ntohs(answer->dataLength);
        if(dataLength == 4){
            dns += (2 + 2 + 4 + 2 + name1.size() + 1);
            for(int i = 0;i < 4;i++){
                name2 += (unsigned char)(*dns);
                dns++;
            }
        }else{
            for(int k = 0;k<dataLength;k++){
                if((unsigned char)(*dns) <= 64){
                    int length = *dns;
                    dns++;
                    k++;
                    for(int j = 0;j < length;j++){
                        name2 += *dns;
                        dns++;
                        k++;
                    }
                    name2 += ".";
                }else if(((*dns) & 0xc0) == 0xc0){
                    int accOffset = (((*dns) & 0x3f) << 8);
                    dns++;
                    k++;
                    accOffset += (*dns);
                    name2 += getDnsDomainName(accOffset);
                    dns++;
                    k++;
                }
            }
        }
        name2 = name2.left(name2.length() - 1);
        return dataLength + 2 + 2 + 2 + 4 + 2 + name1.size() + 2;
    }
}
/********************** get dns domain type **********************/
QString DataPacket::getDnsDomainType(int type){
    switch (type) {
    case 1: return "A (Host Address)";
    case 2:return "NS";
    case 5:return "CNAME (Canonical NAME for an alias)";
    case 6:return "SOA";
    case 11:return "WSK";
    case 12:return "PTR";
    case 13:return "HINFO";
    case 15:return "MX";
    case 28:return "AAAA";
    case 252:return "AXFR";
    case 255:return "ANY";
    default:return "";
    }
}

// ***********************tls*************************//

/********************** get tls protocol to check the data is meet this format or not **********************/
bool DataPacket::getisTlsProtocol(int offset){
    char*ssl;
    ssl = (char*)(pkt_content + 14 + 20 + 20 + offset);
    u_char type = (u_char)(*ssl);
    if(type >= 20 && type <= 23){
        u_short *point = (u_short*)(ssl+1);
        int version = ntohs(*point);
        if(version >= 0x0301 && version <= 0x0304)
            return true;
        else return false;
    }
    else return false;
}
/********************** get tls basic information **********************/
void DataPacket::getTlsBasicInfo(int offset, u_char &contentType, u_short &version, u_short &length){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    contentType = *ssl;
    ssl++;
    u_short* pointer = (u_short*)(ssl);
    version = ntohs(*pointer);
    pointer++;
    length = ntohs(*(pointer));
}

/********************** get tls handshake type **********************/
void DataPacket::getTlsHandshakeType(int offset, u_char &type){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    type = *ssl;
}
/********************** get tls client hello information **********************/
void DataPacket::getTlsClientHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString &random, u_char &sessionIdLength, QString &sessionId,u_short&cipherLength,QVector<u_short> &cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl+1)) * 256 + *(ssl + 2);
    ssl += 3;
    u_short* ver = (u_short*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    u_short* clen = (u_short*)(ssl);
    cipherLength = ntohs(*clen);
    clen++;
    for(int k = 0;k < cipherLength/2;k++){
        cipherSuit.push_back(ntohs(*clen));
        clen++;
    }
    ssl += (2 + cipherLength);
    cmLength = *ssl;
    ssl++;
    for(int k = 0;k<cmLength;k++){
        CompressionMethod.push_back(*ssl);
        ssl++;
    }
    extensionLength = (*(ssl)) * 256 + *(ssl + 1);
}

void DataPacket::getTlsServerHelloInfo(int offset, u_char &handShakeType, int &length, u_short &version, QString& random, u_char &sessionIdLength, QString &sessionId, u_short &cipherSuit, u_char &compressionMethod, u_short &extensionLength){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    u_short* ver = (u_short*)(ssl);
    version = ntohs(*ver);
    ver++;
    ssl += 2;
    for(int i = 0;i < 32;i++){
        random += QString::number(*ssl,16);
        ssl++;
    }
    sessionIdLength = *ssl;
    ssl++;
    for(int k = 0;k < sessionIdLength;k++){
        sessionId += QString::number(*ssl,16);
        ssl++;
    }
    u_short*point = (u_short*)(ssl);
    cipherSuit = ntohs(*point);
    ssl += 2;
    compressionMethod = *ssl;
    ssl++;
    extensionLength = (*ssl) * 256 + (*(ssl + 1));
}
void DataPacket::getTlsServerKeyExchange(int offset, u_char &handShakeType, int &length, u_char &curveType, u_short &curveName, u_char &pubLength, QString &pubKey, u_short &sigAlgorithm, u_short &sigLength, QString &sig){
    u_char*ssl;
    ssl = (u_char*)(pkt_content + 14 + 20 + offset);
    handShakeType = *ssl;
    ssl++;
    length = (*ssl) * 4096 + (*(ssl + 1)) * 256 + *(ssl + 2);
    ssl += 3;
    curveType = (*ssl);
    ssl++;
    u_short*point = (u_short*)(ssl);
    curveName = ntohs(*point);
    ssl += 2;
    pubLength = (*ssl);
    ssl++;
    for(int i = 0;i < pubLength;i++){
        pubKey += QString::number(*ssl,16);
        ssl++;
    }
    point = (u_short*)(ssl);
    sigAlgorithm = ntohs(*point);
    point++;
    sigLength = ntohs(*point);
    ssl += 4;
    for(int i = 0;i < sigLength;i++){
        sig += QString::number(*ssl,16);
        ssl++;
    }
}
/********************** get tls handshake type **********************/
QString DataPacket::getTlsHandshakeType(int type){
    switch (type) {
    case 1:return "Client Hello";
    case 2:return "Server hello";
    case 11:return "Certificate";
    case 16:return "Client Key Exchange";
    case 4:return "New Session Ticket";
    case 12:return "Server Key Exchange";
    case 14:return "Server Hello Done";

    default:return "";
    }
}
/********************** get tls content type **********************/
QString DataPacket::getTlsContentType(int type){
    switch (type) {
    case 20: return "Change Cipher Spec";
    case 21:return "Alert";
    case 22:return "Handshake";
    case 23:return "Application Data";
    default:return "";
    }
}
/********************** get tls version **********************/
QString DataPacket::getTlsVersion(int version){
    switch (version) {
    case 0x0300:return "SSL 3.0";
    case 0x0301:return "TLS 1.0";
    case 0x0302:return "TLS 1.1";
    case 0x0303:return "TLS 1.2";
    case 0x0304:return "TLS 1.3";
    default:return "Unkonwn";
    }
}
/********************** get tls handshake cipher suites **********************/
QString DataPacket::getTlsHandshakeCipherSuites(u_short code){
    switch (code) {
    case 0x00ff: return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)";
    case 0xc02c: return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)";
    case 0xc030: return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)";
    case 0x009f: return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 (0x009f)";
    case 0xc0ad: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM (0xc0ad)";
    case 0xc09f: return "TLS_DHE_RSA_WITH_AES_256_CCM (0xc09f)";
    case 0xc024: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 (0xc024)";
    case 0xc028: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 (0xc028)";
    case 0x006b: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)";
    case 0xc00a: return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)";
    case 0xc014: return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)";
    case 0x0039: return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)";
    case 0xc0af: return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 (0xc0af)";
    case 0xc0a3: return "TLS_DHE_RSA_WITH_AES_256_CCM_8 (0xc0a3)";
    case 0xc087: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc087)";
    case 0xc08b: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08b)";
    case 0xc07d: return "TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07d)";
    case 0xc073: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc073)";
    case 0xc077: return "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc077)";
    case 0x00c4: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c4)";
    case 0x0088: return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)";
    case 0xc02b: return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)";
    case 0xc02f: return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)";
    case 0x009e: return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 (0x009e)";
    case 0xc0ac: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM (0xc0ac)";
    case 0xc09e: return "TLS_DHE_RSA_WITH_AES_128_CCM (0xc09e)";
    case 0xc023: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 (0xc023)";
    case 0xc027: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (0xc027)";
    case 0x0067: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 (0x0067)";
    case 0xc009: return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)";
    case 0xc013: return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)";
    case 0x0033: return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)";
    case 0xc0ae: return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xc0ae)";
    case 0xc0a2: return "TLS_DHE_RSA_WITH_AES_128_CCM_8 (0xc0a2)";
    case 0xc086: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc086)";
    case 0xc08a: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08a)";
    case 0xc07c: return "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07c)";
    case 0xc072: return "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc072)";
    case 0xc076: return "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc076)";
    case 0x00be: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00be)";
    case 0x0045: return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)";
    case 0xc008: return "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)";
    case 0xc012: return "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)";
    case 0x0016: return "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)";
    case 0x00ab: return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 (0x00ab)";
    case 0xc0a7: return "TLS_DHE_PSK_WITH_AES_256_CCM (0xc0a7)";
    case 0xc038: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384 (0xc038)";
    case 0x00b3: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 (0x00b3)";
    case 0xc036: return "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA (0xc036) ";
    case 0x0091: return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA (0x0091)";
    case 0xc091: return "TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc091)";
    case 0xc09b: return "TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc09b)";
    case 0xc097: return "TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc097)";
    case 0xc0ab: return "TLS_PSK_DHE_WITH_AES_256_CCM_8 (0xc0ab)";
    case 0x00aa: return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 (0x00aa)";
    case 0xc0a6: return "TLS_DHE_PSK_WITH_AES_128_CCM (0xc0a6)";
    case 0xc037: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 (0xc037)";
    case 0x00b2: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 (0x00b2)";
    case 0xc035: return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA (0xc035)";
    case 0x0090: return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA (0x0090)";
    case 0xc090: return "TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc090)";
    case 0xc096: return "TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc096)";
    case 0xc09a: return "TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc09a)";
    case 0xc0aa: return "TLS_PSK_DHE_WITH_AES_128_CCM_8 (0xc0aa)";
    case 0xc034: return "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA (0xc034)";
    case 0x008f: return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA (0x008f)";
    case 0x009d: return "TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)";
    case 0xc09d: return "TLS_RSA_WITH_AES_256_CCM (0xc09d)";
    case 0x003d: return "TLS_RSA_WITH_AES_256_CBC_SHA256 (0x003d)";
    case 0x0035: return "TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)";
    case 0xc032: return "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 (0xc032)";
    case 0xc02a: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 (0xc02a)";
    case 0xc00f: return "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)";
    case 0xc02e: return "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02e)";
    case 0xc026: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 (0xc026)";
    case 0xc005: return "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)";
    case 0xc0a1: return "TLS_RSA_WITH_AES_256_CCM_8 (0xc0a1)";
    case 0xc07b: return "TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc07b)";
    case 0x00c0: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 (0x00c0)";
    case 0x0084: return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)";
    case 0xc08d: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc08d)  ";
    case 0xc079: return "TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc079)  ";
    case 0xc089: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384 (0xc089)";
    case 0xc075: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384 (0xc075)";
    case 0x009c: return "TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)";
    case 0xc09c: return "TLS_RSA_WITH_AES_128_CCM (0xc09c)";
    case 0x003c: return "TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003c)";
    case 0x002f: return "TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)";
    case 0xc031: return "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xc031)";
    case 0xc029: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xc029)";
    case 0xc00e: return "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)";
    case 0xc02d: return "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02d)";
    case 0xc025: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 (0xc025)";
    case 0xc004: return "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)";
    case 0xc0a0: return "TLS_RSA_WITH_AES_128_CCM_8 (0xc0a0)";
    case 0xc07a: return "TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc07a)";
    case 0x00ba: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0x00ba)";
    case 0x0041: return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)";
    case 0xc08c: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc08c)";
    case 0xc078: return "TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc078)";
    case 0xc088: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256 (0xc088)";
    case 0xc074: return "TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256 (0xc074)";
    case 0x000a: return "TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)";
    case 0xc00d: return "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)  ";
    case 0xc003: return "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)";
    case 0x00ad: return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 (0x00ad)";
    case 0x00b7: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384 (0x00b7)";
    case 0x0095: return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA (0x0095)";
    case 0xc093: return "TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc093)";
    case 0xc099: return "TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc099)";
    case 0x00ac: return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac)";
    case 0x00b6: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256 (0x00b6)";
    case 0x0094: return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA (0x0094)";
    case 0xc092: return "TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc092)";
    case 0xc098: return "TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc098)";
    case 0x0093: return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA (0x0093)";
    case 0x00a9: return "TLS_PSK_WITH_AES_256_GCM_SHA384 (0x00a9)";
    case 0xc0a5: return "TLS_PSK_WITH_AES_256_CCM (0xc0a5)";
    case 0x00af: return "TLS_PSK_WITH_AES_256_CBC_SHA384 (0x00af)";
    case 0x008d: return "TLS_PSK_WITH_AES_256_CBC_SHA (0x008d)";
    case 0xc08f: return "TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384 (0xc08f)";
    case 0xc095: return "TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384 (0xc095)";
    case 0xc0a9: return "TLS_PSK_WITH_AES_256_CCM_8 (0xc0a9)";
    case 0x00a8: return "TLS_PSK_WITH_AES_128_GCM_SHA256 (0x00a8)";
    case 0xc0a4: return "TLS_PSK_WITH_AES_128_CCM (0xc0a4)";
    case 0x00ae: return "TLS_PSK_WITH_AES_128_CBC_SHA256 (0x00ae)";
    case 0x008c: return "TLS_PSK_WITH_AES_128_CBC_SHA (0x008c)";
    case 0xc08e: return "TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256 (0xc08e)";
    case 0xc094: return "TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256 (0xc094)";
    case 0xc0a8: return "TLS_PSK_WITH_AES_128_CCM_8 (0xc0a8)";
    case 0x008b: return "TLS_PSK_WITH_3DES_EDE_CBC_SHA (0x008b)";
    case 0xc007: return "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)";
    case 0xc011: return "TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)";
    case 0xc033: return "TLS_ECDHE_PSK_WITH_RC4_128_SHA (0xc033)";
    case 0x008e: return "TLS_DHE_PSK_WITH_RC4_128_SHA (0x008e) ";
    case 0x0005: return "TLS_RSA_WITH_RC4_128_SHA (0x0005)";
    case 0x0004: return "TLS_RSA_WITH_RC4_128_MD5 (0x0004)";
    case 0xc00c: return "TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)";
    case 0xc002: return "TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002) ";
    case 0x0092: return "TLS_RSA_PSK_WITH_RC4_128_SHA (0x0092)";
    case 0x008a: return "TLS_PSK_WITH_RC4_128_SHA (0x008a)";
    case 0x1302: return "TLS_AES_256_GCM_SHA384 (0x1302)";
    case 0x1303: return "TLS_CHACHA20_POLY1305_SHA256 (0x1303)";
    case 0x1301: return "TLS_AES_128_GCM_SHA256 (0x1301)";
    case 0xcca9: return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)";
    case 0xcca8: return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)";
    case 0xccaa: return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xccaa)";
    default:return "0x" + QString::number(code,16);
    }
}
/********************** get tls handshake compression **********************/
QString DataPacket::getTlsHandshakeCompression(u_char code){
    switch (code) {
    case 0:return "null";
    default:return "";
    }
}

QString DataPacket::getTlsHandshakeExtension(u_short type){
    switch (type) {
    case 0: return "server_name";
    case 5: return "status_request";
    case 11:return "ec_point_format";
    case 10:return "supported_groups";
    case 35:return "session_ticket";
    case 22:return "encrypt_then_mac";
    case 23:return "extended_master_secret";
    case 13:return "signature_algorithms";
    case 43:return "supported_versions";
    case 45:return "psk_key_exchange_modes";
    case 51:return "key_share";
    case 21:return "padding";
    case 18:return "signed_certificate_timestamp";
    case 39578:return "Reserved (GREASE) (39578)";
    default:return "Unknown type";
    }
}

QString DataPacket::getTlsHandshakeExtensionECPointFormat(u_char type){
    switch (type) {
    case 0:return "EC point format: uncompressed (0)";
    case 1:return "EC point format: ansiX962_compressed_prime (1)";
    case 2:return "EC point format: ansiX962_compressed_char2 (2)";
    default:return QString::number(type);
    }
}

QString DataPacket::getTlsHandshakeExtensionSupportGroup(u_short type){
    switch (type) {
    case 0x001d:return "x25519 (0x001d)";
    case 0x0017:return "secp256r1 (0x0017)";
    case 0x001e:return "x448 (0x001e)";
    case 0x0019:return "secp521r1 (0x0019)";
    case 0x0018:return "secp384r1 (0x0018)";
    case 0x001c:return "brainpoolP512r1 (0x001c)";
    case 0x001b:return "brainpoolP384r1 (0x001b)";
    case 0x0016:return "secp256k1 (0x0016)";
    case 0x001a:return "brainpoolP256r1 (0x001a)";
    case 0x0015:return "secp224r1 (0x0015)";
    case 0x0014:return "secp224k1 (0x0014)";
    case 0x0013:return "secp192r1 (0x0013)";
    case 0x0012:return "secp192k1 (0x0012)";
    default:return "0x" + QString::number(type,16);
    }
}

QString DataPacket::getTlsHadshakeExtensionHash(u_char type){
    switch (type) {
    case 4:return "SHA256";
    case 5:return "SHA384";
    case 6:return "SHA512";
    case 2:return "SHA1";
    case 3:return "SHA224";
    case 1:return "MD5";
    default:return "Unknown";
    }
}
QString DataPacket::getTlsHadshakeExtensionSignature(u_char type){
    switch (type) {
    case 1:return "RSA";
    case 2:return "DSA";
    case 3:return "ECDSA";
    default:return "Unknown";
    }
}
u_short DataPacket::getTlsExtensionType(int offset){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    return ntohs(*ssl);
}

void DataPacket::getTlsExtensionServerName(int offset, u_short &type, u_short &length, u_short &listLength, u_char &nameType, u_short &nameLength, QString &name){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    listLength = ntohs(*ssl);
    ssl++;
    u_char*p = (u_char*)ssl;
    nameType = *p;
    p++;
    nameLength = (*p) * 16 + *(p+1);
    p += 2;
    for(int i = 0;i < nameLength;i++){
        name += (*p);
        p++;
    }
    return;
}

void DataPacket::getTlsExtensionKeyShare(int offset, u_short &type, u_short &length, u_short &shareLength, u_short &group, u_short &exchangeLength,QString &exchange){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    shareLength = ntohs(*ssl);
    ssl++;
    group = ntohs(*ssl);
    ssl++;
    exchangeLength = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < exchangeLength;i++){
        exchange += QString::number(*point,16);
        point++;
    }
}

void DataPacket::getTlsExtensionEcPointFormats(int offset, u_short &type, u_short &length,u_char& ecLength,QVector<u_char> &EC){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char* point = (u_char*)(ssl);
    ecLength = *point;
    point++;
    for(int i = 0;i < ecLength;i++){
        EC.push_back(*point);
        point++;
    }
}

void DataPacket::getTlsExtensionOther(int offset, u_short &type, u_short &length,QString&data){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}

void DataPacket::getTlsExtensionSupportGroups(int offset, u_short &type, u_short &length, u_short &groupListLength, QVector<u_short> &group){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    groupListLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < groupListLength/2;i++){
        group.push_back(ntohs(*ssl));
        ssl++;
    }
}

void DataPacket::getTlsExtensionSessionTicket(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
}

void DataPacket::getTlsExtensionEncryptThenMac(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void DataPacket::getTlsExtensionExtendMasterSecret(int offset, u_short &type, u_short &length){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
}

void DataPacket::getTlsExtensionSignatureAlgorithms(int offset, u_short &type, u_short &length, u_short &algorithmLength, QVector<u_short> &signatureAlgorithm){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    algorithmLength = ntohs(*ssl);
    ssl++;
    for(int i = 0;i < algorithmLength/2;i++){
        signatureAlgorithm.push_back(ntohs(*ssl));
        ssl++;
    }
}

void DataPacket::getTlsExtensionSupportVersions(int offset, u_short &type, u_short &length, u_char &supportLength, QVector<u_short> &supportVersion){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    supportLength = *point;
    point++;
    ssl = (u_short*)(point);
    for(int i = 0;i < supportLength;i++){
        supportVersion.push_back(ntohs(*ssl));
        ssl++;
    }
}
void DataPacket::getTlsExtensionPadding(int offset, u_short &type, u_short &length,QString& data){
    u_short*ssl;
    ssl = (u_short*)(pkt_content + 14 + 20 + offset);
    type = ntohs(*ssl);
    ssl++;
    length = ntohs(*ssl);
    ssl++;
    u_char*point = (u_char*)(ssl);
    for(int i = 0;i < length;i++){
        data += QString::number(*point,16);
        point++;
    }
}
