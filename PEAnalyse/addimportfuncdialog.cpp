#include "addimportfuncdialog.h"
#include "ui_addimportfuncdialog.h"
#include <QFile>
#include <QFileDialog>
#include <QDebug>
#include <Windows.h>
#include <QMessageBox>
#include <Dbghelp.h>

AddImportFuncDialog::AddImportFuncDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddImportFuncDialog)
{
    ui->setupUi(this);
    InitTableHeader();
    setWindowFlags(Qt::WindowCloseButtonHint);
}

AddImportFuncDialog::~AddImportFuncDialog()
{
    delete ui;
}

//遍历导出表
bool AddImportFuncDialog::AnalyseExportTable()
{
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)m_FileBuffer.data();
    PIMAGE_NT_HEADERS32 pNTHeader = (PIMAGE_NT_HEADERS32)(pDOSHeader->e_lfanew + m_FileBuffer.data());
    if(pNTHeader->FileHeader.Machine != 0x014c)
    {
        QMessageBox::warning(NULL, "warning", QStringLiteral("暂不支持i386以外的平台"), QMessageBox::Yes);
        ui->FILEPATH_EDIT->clear();
        return false;
    }

    PIMAGE_DATA_DIRECTORY pExportTable = pNTHeader->OptionalHeader.DataDirectory;
    if(pExportTable->VirtualAddress == NULL)
    {
        QMessageBox::warning(NULL, "warning", QStringLiteral("该PE文件没有导出表"), QMessageBox::Yes);
        ui->FILEPATH_EDIT->clear();
        return false;
    }
    //qDebug("%p",pExportTable->VirtualAddress);
    DWORD dwExportAddr = (DWORD)(ImageRvaToVa(pNTHeader, (PVOID)0,pExportTable->VirtualAddress,NULL));
    //qDebug("ExportAddr: %p",dwExportAddr);
    PIMAGE_EXPORT_DIRECTORY pExportAddr = (PIMAGE_EXPORT_DIRECTORY)(m_FileBuffer.data() + dwExportAddr);
//    qDebug("Base: %d",pExportAddr->Base);
//    qDebug("NumberOfFunctions: %d",pExportAddr->NumberOfFunctions);
//    qDebug("NumberOfNames: %d",pExportAddr->NumberOfNames);
//    qDebug("AddressOfFunctions: %p",pExportAddr->AddressOfFunctions);
//    qDebug("AddressOfNames: %p",pExportAddr->AddressOfNames);
//    qDebug("AddressOfNameOrdinals: %p",pExportAddr->AddressOfNameOrdinals);

    ui->EXPORTFUNCTABLE->setRowCount(pExportAddr->NumberOfFunctions);

    DWORD dwExportNameFOA = (DWORD)(ImageRvaToVa(pNTHeader, (PVOID)0,pExportAddr->AddressOfNames,NULL));
    DWORD dwExportAddressOfNameOrdinalsFOA = (DWORD)(ImageRvaToVa(pNTHeader, (PVOID)0,pExportAddr->AddressOfNameOrdinals,NULL));
    DWORD dwExportAddressOfFunctionsFOA = (DWORD)(ImageRvaToVa(pNTHeader, (PVOID)0,pExportAddr->AddressOfFunctions,NULL));
//    qDebug("AddressOfNamesFOA: %p",dwExportNameFOA);
//    qDebug("AddressOfNameOrdinalsFOA: %p",dwExportAddressOfNameOrdinalsFOA);

    ui->BASE->setText(QString::number(pExportAddr->Base));
    ui->NUMBEROFFUNCTIONS->setText(QString::number(pExportAddr->NumberOfFunctions));
    ui->NUMBEROFNAMES->setText(QString::number(pExportAddr->NumberOfNames));

    for(int i = 0;i < pExportAddr->NumberOfFunctions;i++)
    {
        DWORD* pFuncRVA = (DWORD*)(m_FileBuffer.data() + dwExportAddressOfFunctionsFOA + i * sizeof(DWORD));
        if(*pFuncRVA != NULL)
        {
            ui->EXPORTFUNCTABLE->setItem(i,0,new QTableWidgetItem(tr("%1").arg(i+1,8,16,QLatin1Char('0')).toUpper()));
            ui->EXPORTFUNCTABLE->setItem(i,1,new QTableWidgetItem(tr("%1").arg(*pFuncRVA,8,16,QLatin1Char('0')).toUpper()));
            ui->EXPORTFUNCTABLE->setItem(i,2,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,3,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,4,new QTableWidgetItem("-"));
        }
        else
        {
            ui->EXPORTFUNCTABLE->setItem(i,0,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,1,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,2,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,3,new QTableWidgetItem("-"));
            ui->EXPORTFUNCTABLE->setItem(i,4,new QTableWidgetItem("-"));
        }
    }

    for(DWORD n = 0;n < pExportAddr->NumberOfNames;n++)
    {
        DWORD* pFuncNameRVA = (DWORD*)(m_FileBuffer.data() + dwExportNameFOA + n * sizeof(DWORD));
        //qDebug("dwFuncNameRVA:%p",*pFuncNameRVA);
        DWORD dwFuncNameFOA = (DWORD)(ImageRvaToVa(pNTHeader, (PVOID)0,*pFuncNameRVA,NULL));
        //qDebug("dwFuncNameFOA:%p",dwFuncNameFOA);
       // qDebug("FuncName:%s",(char*)(m_FileBuffer.data() + dwFuncNameFOA));

        WORD* AddressOfNameOrdinals = (WORD*)(m_FileBuffer.data() + dwExportAddressOfNameOrdinalsFOA + n * sizeof(WORD));
        //qDebug("AddressOfNameOrdinals:%d",(*AddressOfNameOrdinals) + pExportAddr->Base);
        ui->EXPORTFUNCTABLE->setItem(*AddressOfNameOrdinals,3,new QTableWidgetItem(QString((char*)(m_FileBuffer.data() + dwFuncNameFOA))));
        ui->EXPORTFUNCTABLE->setItem(*AddressOfNameOrdinals,2,new QTableWidgetItem(tr("%1").arg(*AddressOfNameOrdinals,4,16,QLatin1Char('0')).toUpper()));
    }

    return true;
}

void AddImportFuncDialog::InitTableHeader()
{
    QStringList labels;
    labels << QStringLiteral("Ordinal")
           << QStringLiteral("RVA")
           << QStringLiteral("Name Ordinal")
           << QStringLiteral("FunctionName");
    ui->EXPORTFUNCTABLE->setHorizontalHeaderLabels(labels);//设置表头
    ui->EXPORTFUNCTABLE->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止编辑
    ui->EXPORTFUNCTABLE->setSelectionBehavior(QAbstractItemView::SelectRows);  //整行选中的方式
}

void AddImportFuncDialog::on_OPENFILE_BUTTON_clicked()
{
    QString qsFilePath = QFileDialog::getOpenFileName(this, tr("Open File"),"",tr("PEFile (*.exe *.dll *.sys)"));
    if(!qsFilePath.isEmpty())
    {
        ui->FILEPATH_EDIT->setText(qsFilePath);
        QFileInfo qFileInfo(qsFilePath);
        m_FileName = qFileInfo.fileName();
        QFile file(qsFilePath);
        if (file.open(QIODevice::ReadOnly))
        {
            m_FileBuffer = file.readAll();
            AnalyseExportTable();
            file.close();
        }
    }

}

void AddImportFuncDialog::on_EXPORTFUNCTABLE_itemClicked(QTableWidgetItem *item)
{
    //bool OK;
    qDebug() << "on_EXPORTFUNCTABLE_itemClicked:" << item->row();
    if(ui->EXPORTFUNCTABLE->item(item->row(),3)->text() != "-")
    {
        m_FuncName = ui->EXPORTFUNCTABLE->item(item->row(),3)->text();
        qDebug() << m_FuncName;
    }
}

QString AddImportFuncDialog::FuncName() const
{
    return m_FuncName;
}

void AddImportFuncDialog::setFuncName(const QString &FuncName)
{
    m_FuncName = FuncName;
}

QString AddImportFuncDialog::FileName() const
{
    return m_FileName;
}

void AddImportFuncDialog::setFileName(const QString &FileName)
{
    m_FileName = FileName;
}
