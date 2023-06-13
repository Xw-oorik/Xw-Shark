#include "multhread.h"
#include<QDebug>
#include"FormatHeader.h"
#include"datapacket.h"
multhread::multhread()
{
    this->isDone=true;
    this->pointer=nullptr;
    this->header=nullptr;
    this->pkt_data=nullptr;
}

bool multhread::setPointer(pcap_t* pt)
{
    this->pointer=pt;
    if(pointer){
        return true;
    }
    else{
        return false;
    }
}

void multhread::setFlag()
{
    this->isDone=false;
}

void multhread::resetFlag()
{
    this->isDone=true;
}

void multhread::run()
{
    u_int number_packet=0;
    while(true){
        if(isDone){
            break;
        }
        else{
            //捕获数据包
            //在调用pcap_next_ex()之后系统会分配一部分内存(大概有500KB左右)供其使用
            //返回的报文内容则存放在这部分内存中,不过这只是暂存
            //pointer is 捉实例pcap会话的描述符
            //报文内容存在pkt_data，头存在header
            int ret=pcap_next_ex(pointer,&header,&pkt_data);
            if(ret==0){
                continue;
            }
            local_time_sec=header->ts.tv_sec;
            localtime_s(&local_time,&local_time_sec);
            strftime(timeString,sizeof(timeString),"%H:%M:%S",&local_time);
            //qDebug()<<timeString;
            QString infos="";
            int type=ethrnetPackageHandle(pkt_data,infos);
            if(type){
                DataPacket data;
                int len=header->len;
                data.setInfo(infos);
                data.setDataLength(len);
                data.setTimeStamp(timeString);
                data.setPackageType(type);
                data.setPointer(pkt_data,len);
                if(pkt_data!=nullptr){
                    emit send(data);
                    number_packet++;
                }
                else{
                    continue;
                }

            }
            else continue;
        }
    }
}

int multhread::ethrnetPackageHandle(const u_char *pkt_content, QString &info)
{
    MAC_HEADER* mac;
    u_short type;
    mac=(MAC_HEADER*)pkt_content;
    type=ntohs(mac->type);
    switch(type){
    case 0x0800:{
        //取出协议字段的值
        int ipPacket=0;
        int res=ipPacketHandler(pkt_content,ipPacket);
        switch(res){
        case 1:{//icmp
               info= icmpPacketHandle(pkt_content);
               return 2;
            }
        case 6:{//tcp
              return tcpPacketHandle(pkt_content,info,ipPacket);

        }
        case 17:{//udp
              return udpPacketHandle(pkt_content,info);
        }
        default:break;
        }
        break;
    }
    case 0x0806:{//arp
        info=arpPacketHandle(pkt_content);
        return 1;
    }
    case 0x86DD:{// not joined code ipv6
        info="ipv6";
        return 0;
    }
    default:break;
    }
    return 0;
}

int multhread::ipPacketHandler(const u_char *pkt_content, int &ipPakcet)//返回ip封装的上层协议的协议号
{
    IP_HEADER *ip;
    ip=(IP_HEADER*)(pkt_content+14);//越过以太网帧
    int protocol=ip->protocol;
    ipPakcet=ntohs(ip->total_length)-((ip->version_length&0x0f)*4);//数据部分
    return protocol;
}

int multhread::tcpPacketHandle(const u_char *pkt_content, QString &info, int ipPakcet)
{
    TCP_HEADER*tcp;
    tcp=(TCP_HEADER*)(pkt_content+14+20);
    u_short src=htons(tcp->src_port);
    u_short des=htons(tcp->des_port);
    QString prosend="";
    QString prorecv="";

    int type=3;
    int delta=(tcp->header_len>>4)*4;//tcp头部占字节
    int tcpLoader=ipPakcet-delta;//数据部分
    if((src==443||des==443)&&(tcpLoader > 0)){
        if(src==443)
            prosend=("https");
         else prorecv=("https");

         u_char *ssl;
         ssl=(u_char*)(pkt_content+14+20+delta);
         u_char isTLS=(*ssl);
         ssl++;
         u_short *pointer=(u_short*)ssl;
         u_short version=ntohs(*pointer);
         if(isTLS>=20&&isTLS<=23&&version>=0x0301&&version<=0x0304){
             type=6;  //tls
             switch(isTLS){
             case 20:{
                 info="Change Cipher Spec ";
                 break;
             }
             case 21:{
                 info="Alert ";
                 break;
             }
             case 22:{
                 info="Handshake ";
                 ssl+=4;
                 u_char type=(*ssl);
                 switch(type){
                 case 1:{
                     info+=" Client hello! ";
                     break;
                 }
                 case 2:
                 {
                     info+=" Server hello! ";
                     break;
                 }
                 case 4: {
                     info += " New Session Ticket";
                     break;
                 }
                 case 11:{
                     info += " Certificate";
                     break;
                 }
                 case 16:{
                     info += " Client Key Exchange";
                     break;
                 }
                 case 12:{
                     info += " Server Key Exchange";
                     break;
                 }
                 case 14:{
                     info += " Server Hello Done";
                     break;
                 }
                 default:break;
                 }
                 break;
             }
             case 23:
                   {
                   info ="Application Data ";
                   break;
               }
             default:break;
             }
         }
         else{
             type=7; //ssl
         }
    }
    if(type==7){
        info="Continuation Data ";
    }
    if(src==80||des==80){
        if(src==80)
            prosend=("http");
         else prorecv=("http");
    }
    info+="src_port:"+QString::number(src)+"("+prosend+")"+"->"+"des_port:"+QString::number(des)+"("+prorecv+")";
    QString flag="";
    if(tcp->flags&0x08) flag+="PSH,";
    if(tcp->flags&0x10) flag+="ACK,";
    if(tcp->flags&0x02) flag+="SYN,";
    if(tcp->flags&0x20) flag+="URG,";
    if(tcp->flags&0x01) flag+="FIN,";
    if(tcp->flags&0x04) flag+="RST,";
    if(flag!=""){
        flag=flag.left(flag.length()-1);
        info+="[" + flag + "]";
    }
    u_int seq=ntohl(tcp->seq);
    u_int ack=ntohl(tcp->ack);
    u_short window=ntohs(tcp->window);
    u_short check=ntohs(tcp->checksum);
    u_short urg=ntohs(tcp->utg_ptr);
    info+=" Seq="+QString::number(seq)+" Ack="+QString::number(ack)+" windows="+QString::number(window)
            +" Checksum="+QString::number(check)+" Utg_ptr="+QString::number(urg)+" tcpLoader="+QString::number(tcpLoader);
    return type;
}

int multhread::udpPacketHandle(const u_char *pkt_content, QString &info)
{
    UDP_HEADER*udp;
    udp=(UDP_HEADER*)(pkt_content+14+20);
    u_short des=udp->des_port;
    u_short src=udp->src_port;
    if(des==53||src==53){
        info=dnsPacketHandle(pkt_content);
        return 5;
    }
    else{
        QString res="src_port:"+QString::number(src)+"->"+"des_port:"+QString::number(des)+" ";
        u_short data_len=ntohs(udp->data_len);
        u_short check=ntohs(udp->checksum);
        res+="len = "+QString::number(data_len)+" checksum = "+QString::number(check);
        info=res;
        return 4;
    }
}

QString multhread::arpPacketHandle(const u_char *pkt_content) //和ip是同层级的
{
    ARP_HEADER*arp;
    arp=(ARP_HEADER*)(pkt_content+14);

    u_short op=ntohs(arp->op_code);
    QString res="";
    u_char *des_addr=arp->des_ip_addr;
    QString desip=QString::number(*des_addr)+"."
            +QString::number(*(des_addr+1))+"."
            +QString::number(*(des_addr+2))+"."
            +QString::number(*(des_addr+3));
    u_char *src_addr=arp->src_ip_addr;
    QString srcip=QString::number(*src_addr)+"."
            +QString::number(*(src_addr+1))+"."
            +QString::number(*(src_addr+2))+"."
            +QString::number(*(src_addr+3));

    u_char *src_eth_add=arp->src_eth_addr;
    QString srcEth=byteToString(src_eth_add,1)+":"
            +byteToString((src_eth_add+1),1)+":"
            +byteToString((src_eth_add+2),1)+":"
            +byteToString((src_eth_add+3),1)+":"
            +byteToString((src_eth_add+4),1)+":"
            +byteToString((src_eth_add+5),1);

    if(op==1)res="request: who has "+desip+" -> Tell: "+srcip;
    else if(op==2){
            res="replay: "+srcip+" is at "+srcEth;
        }
    return res;

}

QString multhread::dnsPacketHandle(const u_char *pkt_content)
{
    DNS_HEADER*dns;
    dns=(DNS_HEADER*)(pkt_content+14+20+8); //mac ip udp
    u_short identification=ntohs(dns->identification);
    u_short type=dns->flags;
    QString info="";
    if((type&0xf800)==0x0000){
        info="Standard query";
    }
    else if((type&0xf800)==0x8000){
        info="Standard query response";
    }
    QString name="";
    u_char*domin=(u_char*)(pkt_content+14+20+8+12);//dns具体数据部分，问题，回答
    while(*domin!=0x00){
        if(domin&&(*domin)<=64){//他是标识这一段总长度
            int lens=*domin;
            domin++;
            for(int k=0;k<lens;++k)
            {
                name+=(*domin);
            }
            name+=".";
            domin++;//?
        }
        else break;
    }
    if(name!="") name=name.left(name.length()-1);
    info+="0x"+QString::number(identification,16)+" "+name;
    return info;
}

QString multhread::icmpPacketHandle(const u_char *pkt_content)
{
    ICMP_HEADER*icmp;
    icmp=(ICMP_HEADER*)(pkt_content+14+20);//mac ip
    u_char type=icmp->type;
    u_char code=icmp->code;
    QString res="";
    switch(type){
    case 0:
    {
        if(!code){
            res="Echo response(ping)";
        }
        break;
    }
    case 3:{
        switch (code) {
        case 0:{
            res = "Network unreachable";
            break;
        }
        case 1:{
            res = "Host unreachable";
            break;
        }
        case 2:{
            res = "Protocol unreachable";
            break;
        }
        case 3:{
            res = "Port unreachable";
            break;
        }
        case 4:{
            res = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            res = "Source route selection failed";
            break;
        }
        case 6:{
            res = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        res = "Source station suppression [congestion control]";
        break;
    }
    case 8:
    {
        if(!code){
            res="Echo request (ping)";
        }
        break;
    }
    default:break;
    }
    return res;
}
QString multhread::byteToString(u_char*str,int size)//字节数组转为16进制字符串
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

