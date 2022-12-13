#ifndef ADDRULE_H
#define ADDRULE_H

#include <QDialog>

#include <QSqlDatabase>
#include <QSqlQuery>
#include "QSqlTableModel"

namespace Ui {
class addrule;
}

class addrule : public QDialog
{
    Q_OBJECT

public:
    explicit addrule(QWidget *parent = nullptr);
    ~addrule();

private slots:
    void on_buttonBox_accepted();

    void on_save_clicked();

private:
    Ui::addrule *ui;
    QSqlDatabase db;
    QSqlTableModel model;
};

#endif // ADDRULE_H
