#include "addrule.h"
#include "ui_addrule.h"
#include "iostream"
#include <QMessageBox>
#include "QtDebug"
#include "QSqlQuery"
#include "QSqlDatabase"
#include "QSqlError"
#include "QSqlTableModel"
#include "QSqlRecord"
#include "QDateTime"
#include "unistd.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

extern QString id;

int kernel(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,
           unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);


addrule::addrule(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::addrule)
{
    ui->setupUi(this);

}

addrule::~addrule()
{
    delete ui;
}

void addrule::on_buttonBox_accepted()
{


}

void addrule::on_save_clicked()
{

    QSqlDatabase db = QSqlDatabase::database();
    db.setDatabaseName("dbtest.db");
    if(!db.open()){
            QMessageBox::warning(this, "警告", db.lastError().text());
                    return ;
        }

    QSqlQuery query;

    query.exec("create table IF NOT EXISTS rule6(id integer primary key ,mode char(5),name varchar(20) unique, ori_ip_down char(20), ori_ip_up char(20),"
               "ori_port_down int,ori_port_up int,target_ip_down char(20), target_ip_up char(20),"
               "target_port_down int, target_port_up int,service char(20),action char(1),time_begin char(50), time_end char(50))");

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

    QString service = ui->service->currentText();
    QString action = ui->action->currentText();
    bool action1 = !(action == "接受");

    bool time = ui->radioButton->isChecked();
    QString begin = ui->time1->text();
    QString end = ui->time2->text();

    QSqlTableModel model;
    model.setTable("rule6");
    QSqlRecord record = model.record();
    QString old_name;
    query.exec(QString("select * from rule6 where name= %1").arg(name));
    while(query.next()){
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

    qDebug()<<"tcp"<<ntohl(saddr1);
    qDebug()<<"tcp"<<ntohl(saddr2);
    qDebug()<<"tcp"<<ntohl(daddr1);
    qDebug()<<"tcp"<<ntohl(daddr2);
    qDebug()<<((ntohl(saddr2) >= ntohl(saddr1))&&(ntohl(daddr2) >= ntohl(daddr1)));
    qDebug()<<((ori_port_up >=ori_port_down)&&(target_port_up >=target_port_down));
    qDebug()<<ori_port_up;

    if(!((ntohl(saddr2) >= ntohl(saddr1))&&(ntohl(daddr2) >= ntohl(daddr1))&&(ori_port_up >=ori_port_down)&&(target_port_up >=target_port_down))){
        QMessageBox::warning(this, "警告", "上下界大小错误！");

    } else if(old_name != NULL){
        QMessageBox::warning(this,"警告","策略名已存在！");

    } else {
        /*
        QString ori_ip_down = ori_ip_down1+'.'+ori_ip_down2+'.'+ori_ip_down3+'.'+ori_ip_down4;
        QString ori_ip_up = ori_ip_up1+'.'+ori_ip_up2+'.'+ori_ip_up3+'.'+ori_ip_up4;
        QString target_ip_down = target_ip_down1+'.'+target_ip_down2+'.'+target_ip_down3+'.'+target_ip_down4;
        QString target_ip_up = target_ip_up1+'.'+target_ip_up2+'.'+target_ip_up3+'.'+target_ip_up4;
        QString ins;
        if(time == 1){
            ins = QString("insert into rule6 (mode,name,ori_ip_down,ori_ip_up,ori_port_down,ori_port_up,target_ip_down,"
                                  "target_ip_up,target_port_down,target_port_up,service,action,time_begin,time_end) values('%1','%2','%3','%4','%5','%6','%7','%8',"
                                  "'%9','%10','%11','%12','%13','%14')").arg("off").arg(name).arg(ori_ip_down).arg(ori_ip_up).arg(ori_port_down)
                    .arg(ori_port_up).arg(target_ip_down).arg(target_ip_up).arg(target_port_down).arg(target_port_up)
                    .arg(service).arg(action1).arg(begin).arg(end);
        } else{
            ins = QString("insert into rule6 (mode,name,ori_ip_down,ori_ip_up,ori_port_down,ori_port_up,target_ip_down,"
                                  "target_ip_up,target_port_down,target_port_up,service,action) values('%1','%2','%3','%4','%5','%6','%7','%8',"
                                  "'%9','%10','%11','%12')").arg("off").arg(name).arg(ori_ip_down).arg(ori_ip_up).arg(ori_port_down)
                    .arg(ori_port_up).arg(target_ip_down).arg(target_ip_up).arg(target_port_down).arg(target_port_up)
                    .arg(service).arg(action1);
        }

        query.exec(ins);
        */

        record.setValue("mode","on");
        record.setValue("name", name);
        record.setValue("ori_ip_down", ori_ip_down1+'.'+ori_ip_down2+'.'+ori_ip_down3+'.'+ori_ip_down4);
        record.setValue("ori_ip_up", ori_ip_up1+'.'+ori_ip_up2+'.'+ori_ip_up3+'.'+ori_ip_up4);
        record.setValue("ori_port_down", ori_port_down);
        record.setValue("ori_port_up", ori_port_up);
        record.setValue("target_ip_down", target_ip_down1+'.'+target_ip_down2+'.'+target_ip_down3+'.'+target_ip_down4);
        record.setValue("target_ip_up", target_ip_up1+'.'+target_ip_up2+'.'+target_ip_up3+'.'+target_ip_up4);
        record.setValue("target_port_down", target_port_down);
        record.setValue("target_port_up", target_port_up);
        record.setValue("service", service);
        record.setValue("action", action1);
        if(time == 1){
            record.setValue("time_begin", begin);
            record.setValue("time_end", end);
        }

        model.insertRecord(0,record);
        model.submitAll();

        QMessageBox::about(this,"提示","保存成功！");

        QString sel = QString("select * from rule6 where name = '%1'").arg(name);
        query.exec(sel);
        while (query.next()) {
            id = query.value("id").toString();
        }

        qint32 datetime1;
        qint32 datetime2;
        if(time){
            datetime1 = ui->time1->dateTime().toSecsSinceEpoch();
            datetime2 = ui->time2->dateTime().toSecsSinceEpoch();
        } else{
            datetime1 = -1;
            datetime2 = -1;
        }

        QString ori_ip_down = ori_ip_down1+'.'+ori_ip_down2+'.'+ori_ip_down3+'.'+ori_ip_down4;
        QString ori_ip_up = ori_ip_up1+'.'+ori_ip_up2+'.'+ori_ip_up3+'.'+ori_ip_up4;
        QString target_ip_down = target_ip_down1+'.'+target_ip_down2+'.'+target_ip_down3+'.'+target_ip_down4;
        QString target_ip_up = target_ip_up1+'.'+target_ip_up2+'.'+target_ip_up3+'.'+target_ip_up4;

        //内核执行代码
            unsigned int saddr1;
            unsigned int saddr2;
            unsigned int daddr1;
            unsigned int daddr2;


            const char *q = ori_ip_down.toStdString().c_str();
            const char *w = ori_ip_up.toStdString().c_str();
            const char *e = target_ip_down.toStdString().c_str();
            const char *r = target_ip_up.toStdString().c_str();
            qDebug()<<q;
            qDebug()<<w;
            qDebug()<<e;
            qDebug()<<r;

            inet_aton(q, (struct in_addr* )&saddr1);
            inet_aton(w, (struct in_addr* )&saddr2);
            inet_aton(e, (struct in_addr* )&daddr1);
            inet_aton(r, (struct in_addr* )&daddr2);
            int32_t moving = 1;
            int32_t id_n = id.toUInt();
            int32_t protocol;

            qDebug()<<"id="<<id_n;

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
            qDebug()<<saddr1;
            qDebug()<<saddr2;
            qDebug()<<daddr1;
            qDebug()<<daddr2;
            kernel(moving,id_n,protocol,saddr1,saddr2,daddr1,daddr2,ori_port_down1,ori_port_up1,target_port_down1,
                   target_port_up1, datetime1, datetime2, mode, action2);



        QMessageBox::about(this,"提示","内核写入完成！");

}
         db.close();


}


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

