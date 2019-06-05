#ifndef ADDIMPORTFUNCDIALOG_H
#define ADDIMPORTFUNCDIALOG_H

#include <QDialog>
#include <QTableWidgetItem>

namespace Ui {
class AddImportFuncDialog;
}

class AddImportFuncDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AddImportFuncDialog(QWidget *parent = nullptr);
    ~AddImportFuncDialog();
    bool AnalyseExportTable();
    void InitTableHeader();

    QString FileName() const;
    void setFileName(const QString &FileName);

    QString FuncName() const;
    void setFuncName(const QString &FuncName);

private slots:
    void on_OPENFILE_BUTTON_clicked();

    void on_EXPORTFUNCTABLE_itemClicked(QTableWidgetItem *item);

private:
    Ui::AddImportFuncDialog *ui;
    QString m_FileName;
    QString m_FuncName;
    QByteArray m_FileBuffer;
};

#endif // ADDIMPORTFUNCDIALOG_H
