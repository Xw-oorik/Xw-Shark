#ifndef MULTHREAD_H
#define MULTHREAD_H
#include <stdio.h>
#include"pcap.h"
#include <QThread>
#include"datapacket.h"

class multhread:public QThread
{
    Q_OBJECT
public:
    multhread();
    bool setPointer(pcap_t*);//打开设备描述符的地址
    void setFlag();//控制开关变量
    void resetFlag();

    int ethrnetPackageHandle(const u_char *pkt_content,QString& info);//句柄 ->mac
    int ipPacketHandler(const u_char *pkt_content,int&ipPakcet);//ip处理函数
    int tcpPacketHandle(const u_char *pkt_content,QString& info,int ipPakcet);//tcp ,ipPakcet数据包大小
    int udpPacketHandle(const u_char *pkt_content,QString& info);//udp
    QString arpPacketHandle(const u_char *pkt_content);//arp
    QString dnsPacketHandle(const u_char*pkt_content);//dns
    QString icmpPacketHandle(const u_char*pkt_content);//icmp

protected:
    void run()override;
    QString byteToString(u_char*str,int size); //字节数组转为16进制字符串

signals:
    void send(DataPacket data);
private:
    pcap_t *pointer; //描述符
    struct pcap_pkthdr*header; //数据包头
    const u_char* pkt_data;//数据部分
    time_t local_time_sec;//表示时间戳的秒部分。
    struct tm local_time;//表示本地时间的 tm 结构体。
    char timeString[16];//表示格式化后的时间字符串。
    bool isDone;//线程开关
};

#endif // MULTHREAD_H
