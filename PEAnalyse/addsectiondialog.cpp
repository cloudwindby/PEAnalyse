#include "addsectiondialog.h"
#include "ui_addsectiondialog.h"
#include <QDebug>
#include <QFileDialog>
#include <QFile>
#include <QRegExpValidator>

AddSectionDialog::AddSectionDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddSectionDialog)
{
    ui->setupUi(this);
    setWindowFlags(Qt::WindowCloseButtonHint);
    setWindowTitle("Add Section");
    QRegExp regExp("[a-fA-F0-9]{8}");
    ui->SIZE_EDIT->setValidator(new QRegExpValidator(regExp, this));
    ui->SIZE_EDIT->setReadOnly(true);
}

AddSectionDialog::~AddSectionDialog()
{
    delete ui;
}

void AddSectionDialog::on_checkBox_clicked(bool checked)
{
    qDebug() << "on_checkBox_clicked";
    if(checked)
    {
        m_AddData = false;
        m_IsEmpty = true;
        ui->SIZE_EDIT->setReadOnly(false);
    }
    else
    {
        m_AddData = true;
        m_IsEmpty = false;
        ui->SIZE_EDIT->setReadOnly(true);
    }
}

void AddSectionDialog::on_ADD_BUTTON_clicked()
{
    m_SectionName = ui->NAME_EDIT->text();
    if(m_AddData)
    {
        QString filename = QFileDialog::getOpenFileName();
        if(!filename.isEmpty())
        {
            HandleFile(filename);
        }
    }
    else
    {
        bool OK;
        m_SectionSize = ui->SIZE_EDIT->text().toUInt(&OK,16);
        HandleEmptySection(m_SectionName);
    }

    this->accept();
}

bool AddSectionDialog::IsEmpty() const
{
    return m_IsEmpty;
}

void AddSectionDialog::setIsEmpty(bool IsEmpty)
{
    m_IsEmpty = IsEmpty;
}

QByteArray AddSectionDialog::AppendFileBuffer() const
{
    return m_AppendFileBuffer;
}

void AddSectionDialog::setAppendFileBuffer(const QByteArray &AppendFileBuffer)
{
    m_AppendFileBuffer = AppendFileBuffer;
}

DWORD AddSectionDialog::FileSeek() const
{
    return m_FileSeek;
}

void AddSectionDialog::setFileSeek(const DWORD &FileSeek)
{
    m_FileSeek = FileSeek;
}

DWORD AddSectionDialog::PEOffset() const
{
    return m_PEOffset;
}

void AddSectionDialog::setPEOffset(const DWORD &PEOffset)
{
    m_PEOffset = PEOffset;
}

bool AddSectionDialog::HandleFile(QString &filename)
{
    QFile AppendFile(filename);
    m_AppendFileBuffer =  AppendFile.readAll();

    m_AppendDataSize = AppendFile.size();

    HandleEmptySection(m_SectionName);

    return true;
}

bool AddSectionDialog::HandleEmptySection(QString &SectionName)
{

    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)(m_FileBuffer.data() + m_PEOffset);
    IMAGE_SECTION_HEADER SectionHeader;
    if(m_NumberOfSection > 0)
    {
        SectionHeader = m_SectionList.at(m_NumberOfSection - 1);
        //需要处理中间有空节的情况.
    }

    DWORD dwRawAddr = SectionHeader.PointerToRawData + SectionHeader.SizeOfRawData;
    qDebug("dwRawAddr :%p",dwRawAddr);
    DWORD dwVirtualAddr =  SectionHeader.VirtualAddress + SectionHeader.Misc.VirtualSize;
    qDebug("dwSize :%p",dwVirtualAddr);
    //只处理内存对齐
    if(m_IsEmpty)
    {
        if(dwVirtualAddr < m_SectionAlignment)
        {
            qDebug("m_SectionAlignment :%p",m_SectionAlignment);
            qDebug("m_SectionSize :%p",dwVirtualAddr);
            //如果输入的大小小于内存对齐值.按内存对齐值设置大小
            dwVirtualAddr = m_SectionAlignment;
        }
        else
        {
            DWORD n = dwVirtualAddr % m_SectionAlignment;
            qDebug("dwVirtualAddr % m_SectionAlignment :%p",n);
            if(n > 0)
            {
                dwVirtualAddr = (dwVirtualAddr/m_SectionAlignment + 1) * m_SectionAlignment;
                qDebug("dwSize :%p",dwVirtualAddr);
            }
        }
    }
    //需要处理文件和内存
    else
    {
        if(dwVirtualAddr < m_SectionAlignment)
        {
            qDebug("m_SectionAlignment :%p",m_SectionAlignment);
            qDebug("m_SectionSize :%p",dwVirtualAddr);
            //如果输入的大小小于内存对齐值.按内存对齐值设置大小
            dwVirtualAddr = m_SectionAlignment;
        }
        else
        {
            DWORD n = dwVirtualAddr % m_SectionAlignment;
            qDebug("dwVirtualAddr % m_SectionAlignment :%p",n);
            if(n > 0)
            {
                dwVirtualAddr = (dwVirtualAddr/m_SectionAlignment + 1) * m_SectionAlignment;
                qDebug("dwSize :%p",dwVirtualAddr);
            }
        }

        if(dwRawAddr < m_FileAlignment)
        {
            qDebug("m_FileAlignment :%p",m_FileAlignment);
            qDebug("dwRawAddr :%p",dwRawAddr);
            //如果输入的大小小于内存对齐值.按内存对齐值设置大小
            dwRawAddr = m_FileAlignment;
        }
        else
        {
            DWORD n = dwRawAddr % m_FileAlignment;
            qDebug("dwVirtualAddr % m_SectionAlignment :%p",n);
            if(n > 0)
            {
                dwRawAddr = (dwRawAddr/m_FileAlignment + 1) * m_FileAlignment;
                qDebug("dwSize :%p",dwRawAddr);
            }
        }
    }


    DWORD SectionOffset = m_SectionOffset + (m_NumberOfSection * sizeof(IMAGE_SECTION_HEADER));
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(m_FileBuffer.data() + SectionOffset);
    memcpy(pSectionHeader->Name, SectionName.toStdString().c_str(), 8);
    pSectionHeader->VirtualAddress = dwVirtualAddr;
    pSectionHeader->Misc.VirtualSize = m_SectionSize;

    if(m_IsEmpty)
    {
        pSectionHeader->PointerToRawData = NULL;
        pSectionHeader->SizeOfRawData = NULL;
        pNTHeaders->OptionalHeader.SizeOfImage = m_SectionSize + dwVirtualAddr;
    }
    else
    {
        pSectionHeader->PointerToRawData = dwRawAddr;
        pSectionHeader->SizeOfRawData = m_AppendDataSize;
        pNTHeaders->OptionalHeader.SizeOfImage = m_AppendDataSize + dwVirtualAddr;
        m_FileSeek = dwRawAddr;
    }
    pSectionHeader->Characteristics = 0xF0000040;
    pNTHeaders->FileHeader.NumberOfSections++;


    qDebug("pSectionHeader->Name: %s",pSectionHeader->Name);
    qDebug("pSectionHeader->VirtualAddress:%p",pSectionHeader->VirtualAddress);
    qDebug("pSectionHeader->Misc.VirtualSize:%p",pSectionHeader->Misc.VirtualSize);
    qDebug("pNTHeaders->FileHeader.NumberOfSections:%p",pNTHeaders->FileHeader.NumberOfSections);
    qDebug("pNTHeaders->OptionalHeader.SizeOfImage:%p",pNTHeaders->OptionalHeader.SizeOfImage);
    return true;
}

QList<IMAGE_SECTION_HEADER> AddSectionDialog::SectionList() const
{
    return m_SectionList;
}

void AddSectionDialog::setSectionList(const QList<IMAGE_SECTION_HEADER> &SectionList)
{
    m_SectionList = SectionList;
}

QByteArray AddSectionDialog::FileBuffer() const
{
    return m_FileBuffer;
}

void AddSectionDialog::setFileBuffer(const QByteArray &FileBuffer)
{
    m_FileBuffer = FileBuffer;
}

DWORD AddSectionDialog::SectionOffset() const
{
    return m_SectionOffset;
}

void AddSectionDialog::setSectionOffset(const DWORD &SectionOffset)
{
    m_SectionOffset = SectionOffset;
}

DWORD AddSectionDialog::SectionHeaders() const
{
    return m_SectionHeaders;
}

void AddSectionDialog::setSectionHeaders(const DWORD &SectionHeaders)
{
    m_SectionHeaders = SectionHeaders;
}

DWORD AddSectionDialog::NumberOfSection() const
{
    return m_NumberOfSection;
}

void AddSectionDialog::setNumberOfSection(const DWORD &NumberOfSection)
{
    m_NumberOfSection = NumberOfSection;
}

DWORD AddSectionDialog::SizeOfImage() const
{
    return m_SizeOfImage;
}

void AddSectionDialog::setSizeOfImage(const DWORD &SizeOfImage)
{
    m_SizeOfImage = SizeOfImage;
}

DWORD AddSectionDialog::SectionAlignment() const
{
    return m_SectionAlignment;
}

void AddSectionDialog::setSectionAlignment(const DWORD &SectionAlignment)
{
    m_SectionAlignment = SectionAlignment;
}

DWORD AddSectionDialog::FileAlignment() const
{
    return m_FileAlignment;
}

void AddSectionDialog::setFileAlignment(const DWORD &FileAlignment)
{
    m_FileAlignment = FileAlignment;
}

QString AddSectionDialog::SectionName() const
{
    return m_SectionName;
}

void AddSectionDialog::setSectionName(const QString &SectionName)
{
    m_SectionName = SectionName;
}
