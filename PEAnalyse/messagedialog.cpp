#include "messagedialog.h"
#include "ui_messagedialog.h"

MessageDialog::MessageDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MessageDialog)
{
    ui->setupUi(this);
    setWindowFlags(Qt::WindowCloseButtonHint);
}

MessageDialog::~MessageDialog()
{
    delete ui;
}

bool MessageDialog::SetLabelText(QString str)
{
    ui->label->setText(str);
    return true;
}
