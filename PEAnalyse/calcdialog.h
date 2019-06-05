#ifndef CALCDIALOG_H
#define CALCDIALOG_H

#include <QDialog>
#include <QList>
#include <Windows.h>

namespace Ui {
class CalcDialog;
}

class CalcDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CalcDialog(QWidget *parent = nullptr);
    ~CalcDialog();

    DWORD FileAlignment() const;
    void setFileAlignment(const DWORD &FileAlignment);

    DWORD SectionAlignment() const;
    void setSectionAlignment(const DWORD &SectionAlignment);

    DWORD ImageBase() const;
    void setImageBase(const DWORD &ImageBase);

    DWORD SectionOffset() const;
    void setSectionOffset(const DWORD &SectionOffset);

    DWORD SectionCount() const;
    void setSectionCount(const DWORD &SectionCount);

    void ClearData();

    QList<IMAGE_SECTION_HEADER> SectionList() const;
    void setSectionList(const QList<IMAGE_SECTION_HEADER> &SectionList);

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

    void on_VA_EDIT_returnPressed();

    void on_RVA_EDIT_returnPressed();

    void on_FA_EDIT_returnPressed();

private:

    QString CalculateRVA(DWORD);
    QString CalculateVA(DWORD);
    QString CalculateFA(DWORD);

    Ui::CalcDialog *ui;
    //文件对齐值
    DWORD m_FileAlignment = 0;
    //内存对齐值
    DWORD m_SectionAlignment = 0;
    //基址
    DWORD m_ImageBase = 0;
    //节偏移
    DWORD m_SectionOffset = 0;
    //节个数
    DWORD m_SectionCount = 0;

    //节表链表
    QList<IMAGE_SECTION_HEADER> m_SectionList;

    QByteArray m_bSectionName;

    //RVA
    DWORD m_RVA = 0;
    //VA
    DWORD m_VA = 0;
    //FA
    DWORD m_FA = 0;
};

#endif // CALCDIALOG_H
