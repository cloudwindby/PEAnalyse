#include "calcdialog.h"
#include "ui_calcdialog.h"
#include <QRegExpValidator>
#include <QDebug>

CalcDialog::CalcDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CalcDialog)
{
    ui->setupUi(this);
    setWindowFlags(Qt::WindowCloseButtonHint);
    setWindowTitle("VA<==>FA Clac");
    QRegExp regExp("[a-fA-F0-9]{8}");
    ui->RVA_EDIT->setValidator(new QRegExpValidator(regExp, this));
    ui->FA_EDIT->setValidator(new QRegExpValidator(regExp, this));
    ui->VA_EDIT->setValidator(new QRegExpValidator(regExp, this));
}

CalcDialog::~CalcDialog()
{
    delete ui;
}

void CalcDialog::on_pushButton_clicked()
{
    ClearData();
}

DWORD CalcDialog::SectionCount() const
{
    return m_SectionCount;
}

void CalcDialog::setSectionCount(const DWORD &SectionCount)
{
    m_SectionCount = SectionCount;
}

void CalcDialog::ClearData()
{
    ui->RVA_EDIT->clear();
    ui->FA_EDIT->clear();
    ui->VA_EDIT->clear();
    ui->SECTION_EDIT->clear();
}

DWORD CalcDialog::SectionOffset() const
{
    return m_SectionOffset;
}

void CalcDialog::setSectionOffset(const DWORD &SectionOffset)
{
    m_SectionOffset = SectionOffset;
}

DWORD CalcDialog::ImageBase() const
{
    return m_ImageBase;
}

void CalcDialog::setImageBase(const DWORD &ImageBase)
{
    m_ImageBase = ImageBase;
}

DWORD CalcDialog::SectionAlignment() const
{
    return m_SectionAlignment;
}

void CalcDialog::setSectionAlignment(const DWORD &SectionAlignment)
{
    m_SectionAlignment = SectionAlignment;
}

DWORD CalcDialog::FileAlignment() const
{
    return m_FileAlignment;
}

void CalcDialog::setFileAlignment(const DWORD &FileAlignment)
{
    m_FileAlignment = FileAlignment;
}

void CalcDialog::on_pushButton_2_clicked()
{
    //如果FA编辑框内容不为空
    if(!ui->FA_EDIT->text().isEmpty())
    {
        QString FA = ui->FA_EDIT->text();
        bool OK;
        m_FA = FA.toUInt(&OK,16);
        qDebug() << "FA" << m_FA;
        CalculateFA(m_FA);
    }

    //如果FA编辑框内容不为空
    else if(!ui->RVA_EDIT->text().isEmpty())
    {
        QString RVA = ui->RVA_EDIT->text();
        bool OK;
        m_RVA = RVA.toUInt(&OK,16);
        qDebug() << "RVA" << m_RVA;
        CalculateRVA(m_RVA);
    }

    //如果FA编辑框内容不为空
    else if(!ui->VA_EDIT->text().isEmpty())
    {
        QString VA = ui->VA_EDIT->text();
        bool OK;
        m_VA = VA.toUInt(&OK,16);
        qDebug() << "VA" << m_VA;
        CalculateVA(m_VA);
    }
}

QString CalcDialog::CalculateRVA(DWORD RVA)
{
    qDebug() << "CalculateRVA" << RVA;
    IMAGE_SECTION_HEADER ptagSectionHeader;
    IMAGE_SECTION_HEADER ptagSectionHeader2 = m_SectionList.at(0);
    ptagSectionHeader = m_SectionList.at(m_SectionList.size() - 1);
    if(RVA > (ptagSectionHeader.VirtualAddress + m_SectionAlignment) || RVA < ptagSectionHeader2.VirtualAddress)
    {
        ui->SECTION_EDIT->setText("RVA无效!");
    }
    else
    {
        ui->VA_EDIT->setText(tr("%1").arg(RVA + m_ImageBase,8,16,QLatin1Char('0')).toUpper());
        //遍历链表
        for(auto list : m_SectionList)
        {
            qDebug("Name:%s",(list.Name));
            //qDebug() <<  "当前" << list.Name;
            //如果RVA大于当前节的RVA并且小于当前节的RVA+内存对齐值.说明RVA在当前的节中
            if(RVA > list.VirtualAddress && RVA < list.VirtualAddress + m_SectionAlignment)
            {
                //算节内偏移
                DWORD dwOffset = RVA - list.VirtualAddress;
                if(dwOffset > list.SizeOfRawData)
                {
                    ui->FA_EDIT->setText("FA无效!");
                }
                else
                {
                    //算FA
                    DWORD dwFA = list.PointerToRawData + dwOffset;
                    ui->FA_EDIT->setText(tr("%1").arg(dwFA,8,16,QLatin1Char('0')).toUpper());
                }
                m_bSectionName = (char*)list.Name;
                ui->SECTION_EDIT->setText(QString(m_bSectionName.mid(0,8)));
            }
        }
    }
    return "";
}

QString CalcDialog::CalculateVA(DWORD VA)
{
    qDebug() << "CalculateVA" << VA;
    qDebug() << "ImageBase" << m_ImageBase;
    //如果VA小于基址
    if(VA < m_ImageBase)
    {
        ui->SECTION_EDIT->setText("VA无效!");
    }
    else
    {
        //VA减基址是RVA
        DWORD offset = VA - m_ImageBase;
        //显示RVA
        ui->RVA_EDIT->setText(tr("%1").arg(offset,8,16,QLatin1Char('0')).toUpper());

        IMAGE_SECTION_HEADER ptagSectionHeader;
        qDebug() <<  "offset" << offset;
        ptagSectionHeader = m_SectionList.at(m_SectionList.size() - 1);

        //如果RVA大于RVA+内存对齐值说明当前输入的RVA无效
        if(offset > ptagSectionHeader.VirtualAddress + m_SectionAlignment)
        {
            ui->SECTION_EDIT->setText("VA无效!");
        }
        //遍历链表
        for(auto list : m_SectionList)
        {
            qDebug("Name:%s",(list.Name));
            //qDebug() <<  "当前" << list.Name;
            //如果RVA大于当前节的RVA并且小于当前节的RVA+内存对齐值.说明RVA在当前的节中
            if(offset > list.VirtualAddress && offset < list.VirtualAddress + m_SectionAlignment)
            {
                //算节内偏移
                offset = offset - list.VirtualAddress;
                if(offset > list.SizeOfRawData)
                {
                    ui->FA_EDIT->setText("FA无效!");
                }
                else
                {
                    //算FA
                    DWORD dwFA = list.PointerToRawData + offset;
                    ui->FA_EDIT->setText(tr("%1").arg(dwFA,8,16,QLatin1Char('0')).toUpper());
                }
                m_bSectionName = (char*)list.Name;
                ui->SECTION_EDIT->setText(QString(m_bSectionName.mid(0,8)));

            }
        }
    }
    return "";
}

QString CalcDialog::CalculateFA(DWORD FA)
{
    qDebug("FA:%08x",FA);
    IMAGE_SECTION_HEADER ptagSectionHeader = m_SectionList.at(m_SectionList.size() - 1);
    IMAGE_SECTION_HEADER ptagSectionHeader2 = m_SectionList.at(0);
    if(FA > (ptagSectionHeader.PointerToRawData + m_FileAlignment))
    {
        ui->SECTION_EDIT->setText("FA无效!");
    }
    else if(FA < ptagSectionHeader2.PointerToRawData)
    {
        ui->SECTION_EDIT->setText("FA无效!");
    }
    else
    {
        for(auto list : m_SectionList)
        {
            qDebug("Name:%s",(list.Name));
            //qDebug() <<  "当前" << list.Name;
            //表示在当前节内
            if(FA > list.PointerToRawData && FA < list.PointerToRawData + m_FileAlignment)
            {
                //算节内偏移
                DWORD dwOffset = FA - list.PointerToRawData;
                //算VA
                DWORD dwVA = list.VirtualAddress + dwOffset;
                m_bSectionName = (char*)list.Name;
                ui->SECTION_EDIT->setText(QString(m_bSectionName.mid(0,8)));
                ui->RVA_EDIT->setText(tr("%1").arg(dwVA,8,16,QLatin1Char('0')).toUpper());
                ui->VA_EDIT->setText(tr("%1").arg(dwVA + m_ImageBase,8,16,QLatin1Char('0')).toUpper());
            }
        }
    }
    qDebug() << "CalculateFA" << FA;
    return "";
}

QList<IMAGE_SECTION_HEADER> CalcDialog::SectionList() const
{
    return m_SectionList;
}

void CalcDialog::setSectionList(const QList<IMAGE_SECTION_HEADER> &SectionList)
{
    m_SectionList = SectionList;
}

void CalcDialog::on_VA_EDIT_returnPressed()
{
    ui->FA_EDIT->setReadOnly(true);
    ui->RVA_EDIT->setReadOnly(true);
}

void CalcDialog::on_RVA_EDIT_returnPressed()
{
    ui->FA_EDIT->setReadOnly(true);
    ui->VA_EDIT->setReadOnly(true);
}

void CalcDialog::on_FA_EDIT_returnPressed()
{
    ui->VA_EDIT->setReadOnly(true);
    ui->RVA_EDIT->setReadOnly(true);
}
