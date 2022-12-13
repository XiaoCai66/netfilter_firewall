#include "screen.h"
#include "ui_screen.h"
#include"addrule.h"
#include "alterrule.h"
#include "QMessageBox"
#include "QSqlError"
#include "QSqlQuery"
#include "QDebug"
#include "QList"
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
#include "iostream"
using namespace std;


QString id = NULL;

int kernel(unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,unsigned int,
           unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int);

screen::screen(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::screen)
{
    ui->setupUi(this);
    QSqlDatabase db = QSqlDatabase::addDatabase("QSQLITE");
    db.setDatabaseName("dbtest.db");

    if(!db.open()){
        QMessageBox::warning(this, "警告", db.lastError().text());
                return ;
    }

    static QSqlTableModel* model = new QSqlTableModel(this);
    model->setTable("rule6");
    //model->setEditStrategy(QSqlTableModel::OnManualSubmit);
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->scrollToBottom();
    db.close();
    //QSqlDatabase::removeDatabase("connect1");



}

screen::~screen()
{
    QString name = QSqlDatabase::database().connectionName();
    QSqlDatabase::removeDatabase(name);
    delete ui;
}

void screen::on_addrule_clicked()
{
   addrule w;
   w.exec();

   QSqlDatabase db = QSqlDatabase::database();
   db.setDatabaseName("dbtest.db");

   if(!db.open()){
       QMessageBox::warning(this, "警告", db.lastError().text());
               return ;
   }

   QSqlTableModel* model = new QSqlTableModel(this);
   model->setTable("rule6");
   //model->setEditStrategy(QSqlTableModel::OnManualSubmit);
   model->select();
   ui->tableView->setModel(model);
   ui->tableView->scrollToBottom();
   db.close();
}

void screen::on_delrule_clicked()
{
   QList<QModelIndex> list = ui->tableView->selectionModel()->selectedRows();
   QString del;
   if(list.size()==0){
       QMessageBox::warning(this, "警告", "请选中一条记录！");
   }else{
       id = list[0].data().toString();
       del = QString("delete from rule6 where id='%1'").arg(list[0].data().toString());
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
            const char* ori_ip_down = query.value("ori_ip_down").toString().toStdString().c_str();
            const char* ori_ip_up = query.value("ori_ip_up").toString().toStdString().c_str();
            const char* target_ip_down = query.value("target_ip_down").toString().toStdString().c_str();
            const char* target_ip_up = query.value("target_ip_up").toString().toStdString().c_str();

            unsigned int saddr1;
            unsigned int saddr2;
            unsigned int daddr1;
            unsigned int daddr2;

            inet_aton(ori_ip_down, (struct in_addr* )&saddr1);
            inet_aton(ori_ip_up, (struct in_addr* )&saddr2);
            inet_aton(target_ip_down, (struct in_addr* )&daddr1);
            inet_aton(target_ip_up, (struct in_addr* )&daddr2);

            int32_t id_n = id.toUInt();
            int32_t ori_port_down1 = query.value("ori_port_down").toUInt();
            int32_t ori_port_up1 = query.value("ori_port_up").toUInt();
            int32_t target_port_down1 = query.value("target_port_down").toUInt();
            int32_t target_port_up1 = query.value("target_port_up").toUInt();

            int32_t moving = 2;//删除
            int32_t protocol;
            QString service = query.value("service").toString();
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

            QDateTime datetime;
            qint32 datetime1 = datetime.fromString(query.value("time_begin").toString(),"yyyy/MM/dd hh:mm:ss").toSecsSinceEpoch();
            qint32 datetime2 = datetime.fromString(query.value("time_end").toString(),"yyyy/MM/dd hh:mm:ss").toSecsSinceEpoch();

            int32_t mode = query.value("mode").toString().toUInt();

            int32_t action2 = query.value("action").toUInt();
            qDebug()<<"delete";
            qDebug()<<id_n;
            qDebug()<<protocol;

            kernel(moving,id_n,protocol,saddr1,saddr2,daddr1,daddr2,ori_port_down1,ori_port_up1,target_port_down1,
                   target_port_up1, datetime1, datetime2, mode, action2);

            QMessageBox::about(this,"提示","内核删除完成！");
        }

        query.exec(del);



   }

    QSqlTableModel* model = new QSqlTableModel(this);
    model->setTable("rule6");
      //model->setEditStrategy(QSqlTableModel::OnManualSubmit);
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->scrollToBottom();
    db.close();
   //QDebug(list[0].data().toString())
}

void screen::on_alterrule_clicked()
{
    QList<QModelIndex> list = ui->tableView->selectionModel()->selectedRows();
    if(list.size()==0){
        QMessageBox::warning(this, "警告", "请选中一条记录！");
    }else{
        id = list[0].data().toString();
        alterrule w;
        w.exec();
    }

    QSqlDatabase db = QSqlDatabase::database();
    db.setDatabaseName("dbtest.db");

    if(!db.open()){
        QMessageBox::warning(this, "警告", db.lastError().text());
                return ;
    }

    QSqlTableModel* model = new QSqlTableModel(this);
    model->setTable("rule6");
    //model->setEditStrategy(QSqlTableModel::OnManualSubmit);
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->scrollToBottom();
    db.close();
}

void screen::on_on_off_clicked()
{
    QList<QModelIndex> list = ui->tableView->selectionModel()->selectedRows();
    if(list.size()==0){
        QMessageBox::warning(this, "警告", "请选中一条记录！");
    }else{
        id = list[0].data().toString();

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
            const char* ori_ip_down = query.value("ori_ip_down").toString().toStdString().c_str();
            const char* ori_ip_up = query.value("ori_ip_up").toString().toStdString().c_str();
            const char* target_ip_down = query.value("target_ip_down").toString().toStdString().c_str();
            const char* target_ip_up = query.value("target_ip_up").toString().toStdString().c_str();

            unsigned int saddr1;
            unsigned int saddr2;
            unsigned int daddr1;
            unsigned int daddr2;

            inet_aton(ori_ip_down, (struct in_addr* )&saddr1);
            inet_aton(ori_ip_up, (struct in_addr* )&saddr2);
            inet_aton(target_ip_down, (struct in_addr* )&daddr1);
            inet_aton(target_ip_up, (struct in_addr* )&daddr2);

            int32_t id_n = id.toUInt();
            int32_t ori_port_down1 = query.value("ori_port_down").toUInt();
            int32_t ori_port_up1 = query.value("ori_port_up").toUInt();
            int32_t target_port_down1 = query.value("target_port_down").toUInt();
            int32_t target_port_up1 = query.value("target_port_up").toUInt();

            int32_t moving = 3;
            int32_t protocol;
            QString service = query.value("service").toString();
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
            QDateTime datetime;
            qint32 datetime1 = datetime.fromString(query.value("time_begin").toString(),"yyyy/MM/dd hh:mm:ss").toSecsSinceEpoch();
            qint32 datetime2 = datetime.fromString(query.value("time_end").toString(),"yyyy/MM/dd hh:mm:ss").toSecsSinceEpoch();

            int32_t mode;
            QString new_mode;
            if(query.value("mode").toString() == "on"){
                mode = 0;
                new_mode = "off";
            }else{
                mode = 1;
                new_mode = "on";
            }



            int32_t action2 = query.value("action").toUInt();

            QString ins = QString("update rule6 set mode='%1' where id = '%2'").arg(new_mode).arg(id);
            query.exec(ins);

            kernel(moving,id_n,protocol,saddr1,saddr2,daddr1,daddr2,ori_port_down1,ori_port_up1,target_port_down1,
                   target_port_up1, datetime1, datetime2, mode, action2);

            QMessageBox::about(this,"提示","内核更改完成！");
        }


    }




    QSqlTableModel* model = new QSqlTableModel(this);
    model->setTable("rule6");
    //model->setEditStrategy(QSqlTableModel::OnManualSubmit);
    model->select();
    ui->tableView->setModel(model);
    ui->tableView->scrollToBottom();
    db.close();
}


