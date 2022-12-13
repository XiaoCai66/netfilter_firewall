#include "mainwindow.h"
#include"addrule.h"
#include "screen.h"
#include "login.h"
#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    //MainWindow w;
    //addrule j;
    //screen k;
    login m;
    m.show();
    //w.show();
    //j.show();
    //k.show();
    //if(w.exec()==)
    return a.exec();
}
