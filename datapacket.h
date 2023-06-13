#ifndef DATAPACKET_H
#define DATAPACKET_H
#include"FormatHeader.h"
#include<QString>
#include<QVector>
//this class is describe the data packet information
/*
*     1  ->  arp
*     2  ->  icmp
*     3  ->  tcp
*     4  ->  udp
*     5  ->  dns
*     6  ->  tls
*     7  ->  ssl
 */
class DataPacket
{             //Parse the contents of the package  for gui tree show
public:
    DataPacket();
    ~DataPacket()=default;

    //set val to catched packet
    void setDataLength(int data_length);
    void setTimeStamp(QString timestamp);
    void setInfo(QString infor);
    void setPackageType(int packagetype);
    void setPointer(const u_char* pkt,int size);
    //get val to catched packet
    QString getDataLength();
    QString getTimeStamp();
    QString getInfo();
    QString getPackageType();
    QString getSource();
    QString getDestination();

    //---------------------------------------
    //get mac info
    QString getDesMacAddr();  //以太网帧，mac地址，主要服务于arp这块
    QString getSrcMacAddr();
    QString getMacType();
    //------------------------
    //get ip info
    QString getDesIpAddr();  //ip
    QString getSrcIpAddr();
    QString getVersion();
    QString getHeadLength();
    QString getTos();
    QString getTotalLength();
    QString getIdentification();
    QString getFlags();  //标志  3bit  ，下面取具体标志
    // 第一位保留为始终为 0
    QString getIpReservedBit();
    QString getIpDF();// DF位为 1 时表示该分组不能被分段
    QString getIpMF();//MF位为 1 时表示后面还有该分组的分段，在有分段的情况下，除了最后一个分段该位为 0 外，其他分段该位都为 1

    QString getOffset();
    QString getIpTTL();                       // get ip ttl [time to live]
    QString getIpProtocol();                  // get the ip protocol
    QString getIpCheckSum();                  // get the checksum
    //------------------------------
    //get icmp val
    QString getICMPType();
    QString getICMPCode();
    QString getICMPChecksum();
    QString getICMPIdentification();
    QString getICMPSequence();
    QString getIcmpData(int size);
    //-------------------------------------
    //get arp val
    QString getARPHardwareType();
    QString getARPProtocolType();
    QString getHardware_length();
    QString getARPProtocol_length();
    QString getARPOp_Code();
    QString getARPSrc_Eth_addr();
    QString getARPSrc_Ip_addr();
    QString getARPDes_Eth_addr();
    QString getARPDes_Ip_addr();
    //-------------------------------
    //get udp val
    QString getUDPSrcport();
    QString getUDPDesport();
    QString getUDPDataLen();
    QString getUDPChecksum();

    //get tcp val
    QString getTcpSourcePort();               // get tcp source port
    QString getTcpDestinationPort();          // get tcp destination port
    QString getTcpSequence();                 // get tcp sequence
    QString getTcpAcknowledgment();           // get acknowlegment
    QString getTcpHeaderLength();             // get tcp head length
    QString getTcpRawHeaderLength();          // get tcp raw head length [default is 0x05]
    QString getTcpFlags();                    // get tcp flags
    QString getTcpPSH();                      // PSH flag
    QString getTcpACK();                      // ACK flag
    QString getTcpSYN();                      // SYN flag
    QString getTcpURG();                      // URG flag
    QString getTcpFIN();                      // FIN flag
    QString getTcpRST();                      // RST flag
    QString getTcpWindowSize();               // get tcp window size
    QString getTcpCheckSum();                 // get tcp checksum
    QString getTcpUrgentPointer();            // get tcp urgent pointer
    QString getTcpOperationKind(int kind);    // get tcp option kind
    int getTcpOperationRawKind(int offset);   // get tcp raw option kind

    /*
     * tcp optional parts
    */
    bool getTcpOperationMSS(int offset,u_short& mss);                          // kind = 2
    bool getTcpOperationWSOPT(int offset,u_char&shit);                         // kind = 3
    bool getTcpOperationSACKP(int offset);                                     // kind = 4
    bool getTcpOperationSACK(int offset,u_char&length,QVector<u_int>&edge);    // kind = 5
    bool getTcpOperationTSPOT(int offset,u_int& value,u_int&reply);            // kind = 8


    // dns ssl tls stop  6/12

    // get the dns info
    QString getDnsTransactionId();            // get dns transaction id
    QString getDnsFlags();                    // get dns flags
    QString getDnsFlagsQR();                  // get dns flag QR
    QString getDnsFlagsOpcode();              // get dns flag operation code
    QString getDnsFlagsAA();                  // get dns flag AA
    QString getDnsFlagsTC();                  // get dns flag TC
    QString getDnsFlagsRD();                  // get dns flag RD
    QString getDnsFlagsRA();                  // get dns flag RA
    QString getDnsFlagsZ();                   // get dns flag Z [reserved]
    QString getDnsFlagsRcode();               // get dns flag Rcode
    QString getDnsQuestionNumber();           // get dns question number
    QString getDnsAnswerNumber();             // get dns answer number
    QString getDnsAuthorityNumber();          // get dns authority number
    QString getDnsAdditionalNumber();         // get dns addition number
    void getDnsQueriesDomain(QString&name,int&Type,int&Class);
    QString getDnsDomainType(int type);
    QString getDnsDomainName(int offset);
    int getDnsAnswersDomain(int offset,QString&name1,u_short&Type,u_short& Class,u_int&ttl,u_short&dataLength,QString& name2);

    // get the tls info
    bool getisTlsProtocol(int offset);
    void getTlsBasicInfo(int offset,u_char&contentType,u_short&version,u_short&length);
    void getTlsClientHelloInfo(int offset,u_char&handShakeType,int& length,u_short&version,QString&random,u_char&sessionIdLength,QString&sessionId,u_short&cipherLength,QVector<u_short>&cipherSuit,u_char& cmLength,QVector<u_char>&CompressionMethod,u_short&extensionLength);
    void getTlsServerHelloInfo(int offset,u_char&handShakeType,int&length,u_short&version,QString& random,u_char&sessionIdLength,QString&sessionId,u_short&cipherSuit,u_char&compressionMethod,u_short&extensionLength);
    void getTlsServerKeyExchange(int offset,u_char&handShakeType,int&length,u_char&curveType,u_short&curveName,u_char&pubLength,QString&pubKey,u_short&sigAlgorithm,u_short&sigLength,QString&sig);
    u_short getTlsExtensionType(int offset);
    void getTlsHandshakeType(int offset,u_char&type);

    /*
     * these functions are used to parse the extension parts
     * extension parts are common in handshake parts (client hello,server hello ...)
     * there are some extension types are not included in, maybe you should refer the official API
    */
    void getTlsExtensionServerName(int offset,u_short&type,u_short&length,u_short&listLength,u_char&nameType,u_short&nameLength,QString& name);
    void getTlsExtensionSignatureAlgorithms(int offset,u_short&type,u_short&length,u_short&algorithmLength,QVector<u_short>&signatureAlgorithm);
    void getTlsExtensionSupportGroups(int offset,u_short&type,u_short&length,u_short&groupListLength,QVector<u_short>&group);
    void getTlsExtensionEcPointFormats(int offset,u_short&type,u_short&length,u_char& ecLength,QVector<u_char>&EC);
    void getTlsExtensionSessionTicket(int offset,u_short&type,u_short&length);
    void getTlsExtensionEncryptThenMac(int offset,u_short&type,u_short&length);
    void getTlsExtensionSupportVersions(int offset,u_short&type,u_short&length,u_char&supportLength,QVector<u_short>&supportVersion);
    void getTlsExtensionPskKeyExchangeModes(int offset,u_short&type,u_short&length,u_char&modeLength,QVector<u_char>&mode);
    void getTlsExtensionKeyShare(int offset,u_short&type,u_short&length,u_short&shareLength,u_short&group,u_short&exchangeLength,QString& exchange);
    void getTlsExtensionOther(int offset,u_short&type,u_short&length,QString& data);
    void getTlsExtensionExtendMasterSecret(int offset,u_short&type,u_short&length);
    void getTlsExtensionPadding(int offset,u_short&type,u_short&length,QString&data);

    /*
     * when transfer data,some types will be encoded,like using 0x01 to represent the MD5 in extension hash part
     * to visual display these types,we need to decode and analysis
     * this functions are used to do these analisis
     * however,some types may be the custom types, so we can't decode
     * also,there are some rules not be included, maybe you should refer the official API
    */
    // Parsing the encode data
    static QString getTlsHandshakeType(int type);                          // Parsing TLS handshake type
    static QString getTlsContentType(int type);                            // Parsing TLS content type
    static QString getTlsVersion(int version);                             // Parsing TLS version
    static QString getTlsHandshakeCipherSuites(u_short code);              // Parsing TLS cipher suite
    static QString getTlsHandshakeCompression(u_char code);                // Parsing TLS compression
    static QString getTlsHandshakeExtension(u_short type);                 // Parsing TLS extension
    static QString getTlsHandshakeExtensionECPointFormat(u_char type);     // Parsing TLS EC point format
    static QString getTlsHandshakeExtensionSupportGroup(u_short type);     // Parsing TLS support group
    static QString getTlsHadshakeExtensionSignature(u_char type);          // Parsing TLS signature
    static QString getTlsHadshakeExtensionHash(u_char type);               // Parsing TLS hash

private:
    u_int data_length;//数据长度
    QString timeStamp;//时间戳
    QString info;//数据信息
    int package_type;//数据包类型

protected:
    static QString byteToString(u_char*str,int size);//一字节数据转换为16进制
public:
    const u_char* pkt_content;//保留初始指针

};

#endif // DATAPACKET_H
