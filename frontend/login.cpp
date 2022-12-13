#include "login.h"
#include "ui_login.h"
#include "screen.h"
#include "QtDebug"
#include "QSqlQuery"
#include "QSqlDatabase"
#include "QSqlError"
#include <QMessageBox>



login::login(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::login)
{
    ui->setupUi(this);

}

login::~login()
{
    delete ui;
}



void login::on_login_2_clicked()
{
    if((ui->username->text() == "test")&&(ui->password->text() == "test")){
        screen k;
        k.exec();
    }else{
        QMessageBox::warning(this,"提示","用户名密码错误");
    }

}

