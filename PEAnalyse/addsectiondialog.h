#ifndef ADDSECTIONDIALOG_H
#define ADDSECTIONDIALOG_H

#include <QDialog>
#include <windows.h>

namespace Ui {
class AddSectionDialog;
}

class AddSectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AddSectionDialog(QWidget *parent = nullptr);
    ~AddSectionDialog();

    QString SectionName() const;
    void setSectionName(const QString &SectionName);

    DWORD FileAlignment() const;
    void setFileAlignment(const DWORD &FileAlignment);

    DWORD SectionAlignment() const;
    void setSectionAlignment(const DWORD &SectionAlignment);

    DWORD SizeOfImage() const;
    void setSizeOfImage(const DWORD &SizeOfImage);

    DWORD NumberOfSection() const;
    void setNumberOfSection(const DWORD &NumberOfSection);

    DWORD SectionHeaders() const;
    void setSectionHeaders(const DWORD &SectionHeaders);

    DWORD SectionOffset() const;
    void setSectionOffset(const DWORD &SectionOffset);

    QByteArray FileBuffer() const;
    void setFileBuffer(const QByteArray &FileBuffer);

    QList<IMAGE_SECTION_HEADER> SectionList() const;
    void setSectionList(const QList<IMAGE_SECTION_HEADER> &SectionList);

    DWORD PEOffset() const;
    void setPEOffset(const DWORD &PEOffset);

    bool HandleFile(QString& filename);
    bool HandleEmptySection(QString& SectionName);

    DWORD FileSeek() const;
    void setFileSeek(const DWORD &FileSeek);

    QByteArray AppendFileBuffer() const;
    void setAppendFileBuffer(const QByteArray &AppendFileBuffer);

    bool IsEmpty() const;
    void setIsEmpty(bool IsEmpty);

private slots:
    void on_checkBox_clicked(bool checked);

    void on_ADD_BUTTON_clicked();

private:

    Ui::AddSectionDialog *ui;
    //是否添加数据
    bool m_AddData = true;
    bool m_IsEmpty = false;

    ////此处应弄个结构体

    //区段名
    QString m_SectionName;
    //区段大小
    DWORD m_SectionSize;
    //文件头部数据
    QByteArray m_FileBuffer;
    //添加到节的数据
    QByteArray m_AppendFileBuffer;
    //文件对齐值
    DWORD m_FileAlignment = 0;
    //内存对齐值
    DWORD m_SectionAlignment = 0;
    //镜像大小
    DWORD m_SizeOfImage = 0;
    //区段个数
    DWORD m_NumberOfSection = 0;
    //头大小
    DWORD m_SectionHeaders = 0;
    //区段相对于文件的偏移
    DWORD m_SectionOffset = 0;
    //区段链表
    QList<IMAGE_SECTION_HEADER> m_SectionList;
    //PE偏移
    DWORD m_PEOffset = 0;

    //添加的文件的大小
    DWORD m_AppendDataSize = 0;
    DWORD m_FileSeek = 0;
};

#endif // ADDSECTIONDIALOG_H
