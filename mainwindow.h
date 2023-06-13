#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <stdio.h>
#include"pcap.h"
#include"winsock2.h"
#include <QMainWindow>
#include"datapacket.h"
#include<QDebug>
#include<QVector>
#include"readonlydelegate.h"
QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    void showNetworkCard();//显示全部的网卡设备信息
    int capture();//捕获 抓包

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void on_tableWidget_cellClicked(int row, int column);
    //add new 6/12
    void on_lineEdit_returnPressed();
    void on_lineEdit_textChanged(const QString &arg1);
    void on_tableWidget_currentCellChanged(int currentRow, int currentColumn, int previousRow, int previousColumn);
public slots:
    void HandleMessage(DataPacket data);//主线程接收子线程处理完数据包的send信号
private:
    Ui::MainWindow *ui;
    pcap_if_t* all_device;//指向所有设备的指针
    pcap_if_t* device;//指向当前设备  pcap_if_t->网络接口名称和描述等信息
    pcap_t*pointer;//打开设备的描述符
    char errbuf[PCAP_ERRBUF_SIZE];//错误信息的缓冲区256
    QVector<DataPacket>pData;//存数据包
    int countNumber;//数据包个数
    int numberRow;//tree 看选的哪一行
    //new add.
    readonlydelegate* readOnlyDelegate;     // readonly detegate table数据只读设计
    bool isStart;  //pthread start or not
};
#endif // MAINWINDOW_H
