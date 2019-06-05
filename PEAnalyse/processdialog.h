#ifndef PROCESSDIALOG_H
#define PROCESSDIALOG_H

#include <QDialog>
#include <QMenu>
#include <QSharedPointer>
#include <QVector>
#include <Windows.h>
#include <Psapi.h>
#include <Tlhelp32.h>

namespace Ui {
class ProcessDialog;
}

class ProcessDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessDialog(QWidget *parent = nullptr);
    ~ProcessDialog();
    bool GetProcessInfo();
    DWORD GetProcessCount();
    bool InitTableHeader();
    DWORD GetPID();
    bool AnalyseData(HANDLE hProcess,char *);

private slots:
    void on_processtable_customContextMenuRequested(const QPoint &pos);
    void slot_terminate();
    void slot_refresh();
    void slot_dump();

private:
    Ui::ProcessDialog *ui;
    QSharedPointer<QMenu> m_menu;
    QString m_ProcessName;
    QByteArray m_ProcessMemoryFirstPage;
    QVector<IMAGE_SECTION_HEADER> m_SectionsVector;
    HMODULE m_hImageBase = 0;
};

#endif // PROCESSDIALOG_H
