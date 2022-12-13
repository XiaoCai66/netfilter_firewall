#include "alterrule.h"
#include "ui_alterrule.h"
#include "iostream"
#include <QMessageBox>
#include "QtDebug"
#include "QSqlQuery"
#include "QSqlDatabase"
#include "QSqlError"
#include "QSqlTableModel"
#include "QSqlRecord"
#include "QDebug"
#include "unistd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
using namespace std;

extern QString id;

int kernel(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,
           unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

alterrule::alterrule(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::alterrule)
{
    ui->setupUi(this);
    QSqlDatabase db = QSqlDatabase::database();
    db.setDatabaseName("dbtest.db");
    if(!db.open()){
            QMessageBox::warning(this, "警告", db.lastError().text());
                    return ;
        }

    QSqlQuery query;

    QString sel = QString("select * from rule6 where id = '%1'").arg(id);
    query.exec(sel);
    while(query.next()){
        ui->name->setText(query.value("name").toString());

        QStringList list = query.value("ori_ip_down").toString().split(".");
        ui->ori_ip_down1->setValue(list[0].toUInt());
        ui->ori_ip_down2->setValue(list[1].toUInt());
        ui->ori_ip_down3->setValue(list[2].toUInt());
        ui->ori_ip_down4->setValue(list[3].toUInt());

        QStringList list1 = query.value("ori_ip_up").toString().split(".");
        ui->ori_ip_up1->setValue(list1[0].toUInt());
        ui->ori_ip_up2->setValue(list1[1].toUInt());
        ui->ori_ip_up3->setValue(list1[2].toUInt());
        ui->ori_ip_up4->setValue(list1[3].toUInt());

        ui->ori_port_down->setValue(query.value("ori_port_down").toString().toUInt());
        ui->ori_port_up->setValue(query.value("ori_port_up").toString().toUInt());

        QStringList list2 = query.value("target_ip_down").toString().split(".");
        ui->target_ip_down1->setValue(list2[0].toUInt());
        ui->target_ip_down2->setValue(list2[1].toUInt());
        ui->target_ip_down3->setValue(list2[2].toUInt());
        ui->target_ip_down4->setValue(list2[3].toUInt());

        QStringList list3 = query.value("target_ip_up").toString().split(".");
        ui->target_ip_up1->setValue(list3[0].toUInt());
        ui->target_ip_up2->setValue(list3[1].toUInt());
        ui->target_ip_up3->setValue(list3[2].toUInt());
        ui->target_ip_up4->setValue(list3[3].toUInt());

        ui->target_port_down->setValue(query.value("target_port_down").toString().toUInt());
        ui->target_port_up->setValue(query.value("target_port_up").toString().toUInt());

        ui->service->setText(query.value("service").toString());

        if(query.value("action").toString() == "1"){
            ui->action->setCurrentText("拒绝");
        } else {
            ui->action->setCurrentText("接受");
        }

        if(query.value("time_begin").toString() != NULL){
            ui->radioButton->setChecked(1);
            qDebug()<<"alterrule";
            qDebug()<<query.value("time_begin").toString();
            qDebug()<<query.value("time_end").toString();

            QDateTime datetime;
            ui->time1->setDateTime(datetime.fromString(query.value("time_begin").toString(),"yyyy/MM/dd hh:mm:ss"));
            ui->time2->setDateTime(datetime.fromString(query.value("time_end").toString(),"yyyy/MM/dd hh:mm:ss"));

        }


    }

    db.close();

    /*
    ui->name->setText(record.value("name").toString());


    QStringList list = record.value("ori_ip_down").toString().split(".");
    ui->ori_ip_down1->setValue(list[0].toUInt());
    ui->ori_ip_down2->setValue(list[1].toUInt());
    ui->ori_ip_down3->setValue(list[2].toUInt());
    ui->ori_ip_down4->setValue(list[3].toUInt());

    QStringList list1 = record.value("ori_ip_up").toString().split(".");
    ui->ori_ip_up1->setValue(list1[0].toUInt());
    ui->ori_ip_up2->setValue(list1[1].toUInt());
    ui->ori_ip_up3->setValue(list1[2].toUInt());
    ui->ori_ip_up4->setValue(list1[3].toUInt());

    ui->ori_port_down->setValue(record.value("ori_port_down").toString().toUInt());
    ui->ori_port_up->setValue(record.value("ori_port_up").toString().toUInt());

    QStringList list2 = record.value("target_ip_down").toString().split(".");
    ui->target_ip_down1->setValue(list2[0].toUInt());
    ui->target_ip_down2->setValue(list2[1].toUInt());
    ui->target_ip_down3->setValue(list2[2].toUInt());
    ui->target_ip_down4->setValue(list2[3].toUInt());

    QStringList list3 = record.value("target_ip_up").toString().split(".");
    ui->target_ip_up1->setValue(list3[0].toUInt());
    ui->target_ip_up2->setValue(list3[1].toUInt());
    ui->target_ip_up3->setValue(list3[2].toUInt());
    ui->target_ip_up4->setValue(list3[3].toUInt());

    ui->target_port_down->setValue(record.value("target_port_down").toString().toUInt());
    ui->target_port_up->setValue(record.value("target_port_up").toString().toUInt());

    ui->service->setEditText(record.value("service").toString());
    if(record.value("action").toString() == "1"){
        ui->action->setEditText("接受");
    } else {
        ui->action->setEditText("拒绝");
    }
    */
    //ui->time1->setDateTime(QDataTime::fromDtring(record.value("time_begin").toString(), ""));
    //ui->time2->setDateTime();
}

alterrule::~alterrule()
{
    delete ui;
}

void alterrule::on_save_clicked()
{
    QSqlDatabase db = QSqlDatabase::database();
    db.setDatabaseName("dbtest.db");
    if(!db.open()){
            QMessageBox::warning(this, "警告", db.lastError().text());
                    return ;
        }

    QSqlQuery query;

    QString name = ui->name->text();
    QString ori_ip_down1 = ui->ori_ip_down1->text();
    QString ori_ip_down2 = ui->ori_ip_down2->text();
    QString ori_ip_down3 = ui->ori_ip_down3->text();
    QString ori_ip_down4 = ui->ori_ip_down4->text();

    QString ori_ip_up1 = ui->ori_ip_up1->text();
    QString ori_ip_up2 = ui->ori_ip_up2->text();
    QString ori_ip_up3 = ui->ori_ip_up3->text();
    QString ori_ip_up4 = ui->ori_ip_up4->text();

    int32_t ori_port_down = ui->ori_port_down->text().toUInt();
    int32_t ori_port_up = ui->ori_port_up->text().toUInt();

    QString target_ip_down1 = ui->target_ip_down1->text();
    QString target_ip_down2 = ui->target_ip_down2->text();
    QString target_ip_down3 = ui->target_ip_down3->text();
    QString target_ip_down4 = ui->target_ip_down4->text();

    QString target_ip_up1 = ui->target_ip_up1->text();
    QString target_ip_up2 = ui->target_ip_up2->text();
    QString target_ip_up3 = ui->target_ip_up3->text();
    QString target_ip_up4 = ui->target_ip_up4->text();

    int32_t target_port_down = ui->target_port_down->text().toUInt();
    int32_t target_port_up = ui->target_port_up->text().toUInt();

    QString service = ui->service->text();
    QString action = ui->action->currentText();
    bool action1 = !(action == "接受");

    bool time = ui->radioButton->isChecked();
    QString begin = ui->time1->text();
    QString end = ui->time2->text();

    QSqlTableModel model;
    model.setTable("rule6");
    QSqlRecord record = model.record();

    QString old_name;
    query.exec(QString("select * from rule6 where name=%1").arg(name));
    while (query.next()) {
        old_name = query.value("name").toString();
    }

    unsigned int saddr1;
    unsigned int saddr2;
    unsigned int daddr1;
    unsigned int daddr2;

    QString ori_ip_down = ori_ip_down1+'.'+ori_ip_down2+'.'+ori_ip_down3+'.'+ori_ip_down4;
    QString ori_ip_up = ori_ip_up1+'.'+ori_ip_up2+'.'+ori_ip_up3+'.'+ori_ip_up4;
    QString target_ip_down = target_ip_down1+'.'+target_ip_down2+'.'+target_ip_down3+'.'+target_ip_down4;
    QString target_ip_up = target_ip_up1+'.'+target_ip_up2+'.'+target_ip_up3+'.'+target_ip_up4;

    const char *q = ori_ip_down.toStdString().c_str();
    const char *w = ori_ip_up.toStdString().c_str();
    const char *e = target_ip_down.toStdString().c_str();
    const char *r = target_ip_up.toStdString().c_str();

    inet_aton(q, (struct in_addr* )&saddr1);
    inet_aton(w, (struct in_addr* )&saddr2);
    inet_aton(e, (struct in_addr* )&daddr1);
    inet_aton(r, (struct in_addr* )&daddr2);

    if(!((ntohl(saddr2) >= ntohl(saddr1))&&(ntohl(daddr2) >= ntohl(daddr1))&&(ori_port_up >=ori_port_down)&&(target_port_up >=target_port_down))){
        QMessageBox::warning(this, "警告", "上下界大小错误！");

    } else if((old_name != NULL)&&(old_name != name)){
        QMessageBox::warning(this,"警告","策略名已存在！");

    } else{
        QString ori_ip_down = ori_ip_down1+'.'+ori_ip_down2+'.'+ori_ip_down3+'.'+ori_ip_down4;
        QString ori_ip_up = ori_ip_up1+'.'+ori_ip_up2+'.'+ori_ip_up3+'.'+ori_ip_up4;
        QString target_ip_down = target_ip_down1+'.'+target_ip_down2+'.'+target_ip_down3+'.'+target_ip_down4;
        QString target_ip_up = target_ip_up1+'.'+target_ip_up2+'.'+target_ip_up3+'.'+target_ip_up4;
        QString ins;


        if(time == 1){

            ins = QString("update rule6 set name='%1',ori_ip_down='%2',ori_ip_up='%3',ori_port_down='%4',ori_port_up='%5',target_ip_down='%6',"
                                  "target_ip_up='%7',target_port_down='%8',target_port_up='%9',service='%10',action='%11',time_begin='%12',time_end='%13' where"
                          " id = '%14'").arg(name).arg(ori_ip_down).arg(ori_ip_up).arg(ori_port_down).arg(ori_port_up).arg(target_ip_down)
                    .arg(target_ip_up).arg(target_port_down).arg(target_port_up).arg(service).arg(action1).arg(begin).arg(end).arg(id);
            query.exec(ins);
        } else {
            ins = QString("update rule6 set name='%1',ori_ip_down='%2',ori_ip_up='%3',ori_port_down='%4',ori_port_up='%5',target_ip_down='%6',"
                                  "target_ip_up='%7',target_port_down='%8',target_port_up='%9',service='%10',action='%11',time_begin='%12',time_end='%13' where"
                          " id = '%14'").arg(name).arg(ori_ip_down).arg(ori_ip_up).arg(ori_port_down).arg(ori_port_up).arg(target_ip_down)
                    .arg(target_ip_up).arg(target_port_down).arg(target_port_up).arg(service).arg(action1).arg("").arg("").arg(id);

           query.exec(ins);
        }


        QMessageBox::about(this,"提示","修改成功！");


        qint32 datetime1;
        qint32 datetime2;

        if(time){
           datetime1 = ui->time1->dateTime().toSecsSinceEpoch();
           datetime2 = ui->time2->dateTime().toSecsSinceEpoch();
         } else{
            datetime1 = -1;
            datetime2 = -1;
        }

        //内核执行代码
            unsigned int saddr1;
            unsigned int saddr2;
            unsigned int daddr1;
            unsigned int daddr2;
            const char *q = ori_ip_down.toStdString().c_str();
            const char *w = ori_ip_up.toStdString().c_str();
            const char *e = target_ip_down.toStdString().c_str();
            const char *r = target_ip_up.toStdString().c_str();
            inet_aton(q, (struct in_addr* )&saddr1);
            inet_aton(w, (struct in_addr* )&saddr2);
            inet_aton(e, (struct in_addr* )&daddr1);
            inet_aton(r, (struct in_addr* )&daddr2);
            int32_t moving = 3;//修改
            int32_t id_n = id.toUInt();
            int32_t protocol;

            if(service == "TCP"){
                protocol = 1;
            } else if(service == "UDP"){
                protocol = 2;
            } else if(service == "ICMP"){
                protocol = 3;
            } else if(service == "ALL"){
                protocol = 4;
            } else{
                QMessageBox::warning(this,"警告","service不合法！");
            }

            int32_t ori_port_down1 = ori_port_down;
            int32_t ori_port_up1 = ori_port_up;
            int32_t target_port_down1 = target_port_down;
            int32_t target_port_up1 = target_port_up;
            int32_t mode = 1;
            int32_t action2 = action1;

            kernel(moving,id_n,protocol,saddr1,saddr2,daddr1,daddr2,ori_port_down1,ori_port_up1,target_port_down1,
                   target_port_up1, datetime1, datetime2, mode, action2);



        QMessageBox::about(this,"提示","内核写入完成！");

    }



    db.close();
}

/*
int kernel(unsigned int moving,unsigned int id,unsigned int protocol,unsigned int saddr1,unsigned int saddr2,unsigned int daddr1,
           unsigned int daddr2,unsigned int sport1,unsigned int sport2,unsigned int dport1,unsigned int dport2,
           unsigned int time1,unsigned int time2,unsigned int mode,unsigned int action){
    char controlinfo[64];
    int controlinfo_len = 0;
    int fd;
    struct stat buf;

    printf("rule:\nsaddr %d-%d\ndaddr:%d-%d\nsport:%d-%d\ndport:%d-%d\n",saddr1,saddr2,daddr1,daddr2,sport1,sport2,dport1,dport2);

    *(int *)(controlinfo) = moving;// 增删改123
    *(int *)(controlinfo+4) = id;
    *(int *)(controlinfo+8) = protocol;//1tcp 2udp 3ping 4all
    *(int *)(controlinfo+12) = saddr1;
    *(int *)(controlinfo+16) = saddr2;
    *(int *)(controlinfo+20) = daddr1;
    *(int *)(controlinfo+24) = daddr2;
    *(int *)(controlinfo+28) = sport1;
    *(int *)(controlinfo+32) = sport2;
    *(int *)(controlinfo+36) = dport1;
    *(int *)(controlinfo+40) = dport2;
    *(int *)(controlinfo+44) = time1;
    *(int *)(controlinfo+48) = time2;
    *(int *)(controlinfo+52) = mode;// on 1 off 0
    *(int *)(controlinfo+56) = action;// drop 1 accept 0

    controlinfo_len = 60;

    if (stat("/dev/controlinfo",&buf) != 0){
        if (system("mknod /dev/controlinfo c 124 0") == -1){
            printf("Cann't create the devive file ! \n");
            printf("Please check and try again! \n");
            exit(1);
        }
    }

    // write:pass the control info to the kernel space
    fd = open("/dev/controlinfo",O_RDWR,S_IRUSR|S_IWUSR);
    if (fd > 0)
    {
        write(fd,controlinfo,controlinfo_len);
    }
    else {
        perror("can't open /dev/controlinfo \n");
        exit(1);
    }
    close(fd);
    return 0;
}
*/
