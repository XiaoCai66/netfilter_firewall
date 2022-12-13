#ifndef ALTERRULE_H
#define ALTERRULE_H

#include <QDialog>
#include <QSqlDatabase>
#include <QSqlQuery>
#include "QSqlTableModel"
namespace Ui {
class alterrule;
}

class alterrule : public QDialog
{
    Q_OBJECT

public:
    explicit alterrule(QWidget *parent = nullptr);
    ~alterrule();

private slots:
    void on_save_clicked();

private:
    Ui::alterrule *ui;
    QSqlDatabase db;
    QSqlTableModel model;
};

#endif // ALTERRULE_H
