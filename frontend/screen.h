#ifndef SCREEN_H
#define SCREEN_H

#include <QDialog>
#include <QSqlDatabase>
#include <QSqlQuery>
#include "QSqlTableModel"
#include "qsql.h"
#include "QDebug"

namespace Ui {
class screen;
}

class screen : public QDialog
{
    Q_OBJECT

public:
    explicit screen(QWidget *parent = nullptr);
    ~screen();

private slots:
    void on_addrule_clicked();

    void on_delrule_clicked();

    void on_alterrule_clicked();

    void on_on_off_clicked();



private:
    Ui::screen *ui;
    QSqlDatabase db;
    QSqlTableModel model;
};

#endif // SCREEN_H
