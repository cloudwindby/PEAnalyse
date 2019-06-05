#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDialog>
#include <Dbghelp.h>


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    //初始化表头
    InitHeader();
    //设置主窗口只有关闭按钮
    setWindowFlags(Qt::WindowCloseButtonHint);
    this->resize( QSize( 440, 400 ));
    //设置接收拖拽
    setAcceptDrops(true);
    m_WindowTitel = "PEAnalyse";
    setWindowTitle(m_WindowTitel);

    m_ProcessDialog = nullptr;

    //第一次打开文件
    m_IsFirstOpen = false;
    //文件是否保存了
    m_IsFileSave = false;
    //文件是否被修改了
    m_IsFileChange = false;
}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::InitHeader()
{
    //设置table自动等宽
    ui->DOS_HEADER_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->File_HEADER_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    //ui->OPTIONAL_HEADER_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->OPTIONAL_HEADER_TABLE->setColumnWidth(0, 200);//设置第一列的宽度
    ui->OPTIONAL_HEADER_TABLE->setColumnWidth(1, 116);//设置第一列的宽度
    ui->DATA_DIRECTORY_TABLE->setColumnWidth(0, 220);//设置第一列的宽度
    ui->DATA_DIRECTORY_TABLE->setColumnWidth(1, 75);//设置第一列的宽度
    ui->DATA_DIRECTORY_TABLE->setColumnWidth(2, 75);//设置第一列的宽度
    //ui->DATA_DIRECTORY_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);

    QStringList labels;
    labels << QStringLiteral("Name")
           << QStringLiteral("RVA")
           << QStringLiteral("Size");

    ui->DATA_DIRECTORY_TABLE->setHorizontalHeaderLabels(labels);//设置表头

    QStringList SectionsLabels;
    SectionsLabels << QStringLiteral("Name")
                   << QStringLiteral("RVA")
                   << QStringLiteral("Virtual Size")
                   << QStringLiteral("Raw Address")
                   << QStringLiteral("Raw Size")
                   << QStringLiteral("Characteristics");

    ui->SECTIONS_HEADER_TABLE->horizontalHeader()->setVisible(true);
    ui->SECTIONS_HEADER_TABLE->setHorizontalHeaderLabels(SectionsLabels);//设置表头

    QStringList ImportTableLabels;
    ImportTableLabels << QStringLiteral("DllName")
                      << QStringLiteral("OFTs")
                      << QStringLiteral("Name RVA")
                      << QStringLiteral("FTs(IAT)");

    ui->DLL_TABLE->horizontalHeader()->setVisible(true);
    ui->DLL_TABLE->setHorizontalHeaderLabels(ImportTableLabels);//设置表头
    ui->DLL_TABLE->setRowCount(0);
    ui->DLL_TABLE->setSelectionBehavior(QAbstractItemView::SelectRows);  //整行选中的方式

    //初始化IAT
    InitFuncTable();

    //右键菜单
    m_menu = QSharedPointer<QMenu>(new QMenu());

    QAction* pAddSection = m_menu->addAction(QStringLiteral("添加区段"));
    QAction* pExtendLastSection = m_menu->addAction(QStringLiteral("扩展最后一个区段"));
    connect(pAddSection,SIGNAL(triggered()),this,SLOT(slot_AddSection()));
    connect(pExtendLastSection,SIGNAL(triggered()),this,SLOT(slot_ExtendLastSection()));

    qDebug("on_DLL_TABLE_customContextMenuRequested");
    //右键菜单
    m_AddImportFunc = QSharedPointer<QMenu>(new QMenu());

    QAction* pAddImportFunc = m_AddImportFunc->addAction(QStringLiteral("添加导入函数"));

    connect(pAddImportFunc,SIGNAL(triggered()),this,SLOT(slot_AddImportFunc()));

    ui->RELOCDIR_TABLE->setDisabled(true);
    ui->RELOC_TABLE->setDisabled(true);
    ui->RELOCDIR_TABLE->horizontalHeader()->setVisible(false);
    ui->RELOC_TABLE->horizontalHeader()->setVisible(false);
}

//重写拖拽
void MainWindow::dragEnterEvent(QDragEnterEvent *e)
{
    e->acceptProposedAction();
    //  qDebug() << "Qdebug";
}

//重写拖拽
void MainWindow::dropEvent(QDropEvent *e)
{
    ClearInfo();
    InitHeader();
    if(m_file.isOpen())
    {
        m_MessageDialog.move(this->x() + 50,this->y() + 50);
        m_MessageDialog.setWindowTitle(QStringLiteral("警告!"));
        if(m_MessageDialog.exec() == QDialog::Accepted)
        {
            m_file.close();
            //获取文件路径
            QList<QUrl> urls = e->mimeData()->urls();

            if(urls.isEmpty())
                return ;

            QString fileName = urls.first().toLocalFile();
            // qDebug() << fileName;

            if(fileName.isEmpty())
            {
                ui->FILE_PATH->setText("文件打开失败");
                return;
            }
            m_LastOpenFileName = fileName;
            ReadFile(fileName);
        }
    }
    else
    {
        //获取文件路径
        QList<QUrl> urls = e->mimeData()->urls();

        if(urls.isEmpty())
            return ;

        QString fileName = urls.first().toLocalFile();
        // qDebug() << fileName;

        if(fileName.isEmpty())
        {
            ui->FILE_PATH->setText("文件打开失败");
            ClearInfo();
            return;
        }
        m_LastOpenFileName = fileName;
        ReadFile(fileName);
    }

}

//关闭事件.关闭文件.
void MainWindow::closeEvent(QCloseEvent *e)
{
    ExitProcess();
}

void MainWindow::on_actionSave_File_triggered()
{
    //如果文件内容被修改了
    if(m_IsFileChange)
    {
        qDebug() << "file is change";
        m_file.seek(0);
        m_file.write(m_bFileBuffer);
        //说明文件被保存了
        m_IsFileSave = true;
        m_IsFileChange = false;
        qDebug() << "file is Save";
    }
}

void MainWindow::on_actionClose_File_triggered()
{
    if(m_file.isOpen())
    {
        //文件被修改但是未保存
        if(m_IsFileChange && !m_IsFileSave)
        {
            m_MessageDialog.move(this->x() + 50,this->y() + 50);
            m_MessageDialog.setWindowTitle(QStringLiteral("警告!"));
            m_MessageDialog.SetLabelText(QStringLiteral("当前文件被修改但是未保存.您是否要关闭?"));
            if(m_MessageDialog.exec() == QDialog::Accepted)
            {
                qDebug() << "文件被修改但是未保存";
                m_file.close();
                ClearInfo();
            }
        }
        else
        {
            qDebug() << "file is open";
            m_file.close();
            ClearInfo();
        }
    }
}

void MainWindow::on_actionOpen_File_triggered()
{
    QString filename = QFileDialog::getOpenFileName();
    if(!filename.isEmpty())
    {
        m_LastOpenFileName = filename;
        ReadFile(filename);
    }
}

void MainWindow::on_actionCalc_triggered()
{
    if(m_IsPEFile)
    {
        //设置文件对齐值
        m_CalcDialog.setFileAlignment(m_FileAlignment);
        //设置内存对齐值
        m_CalcDialog.setSectionAlignment(m_SectionAlignment);
        //设置基址
        m_CalcDialog.setImageBase(m_ImageBase);
        //设置节相对于文件的偏移
        m_CalcDialog.setSectionOffset(m_SectionOffset);
        //设置节的个数
        m_CalcDialog.setSectionCount(m_SectionCount);
        //拷贝节表的链表
        m_CalcDialog.setSectionList(m_SectionList);
        //显示对话框
        m_CalcDialog.show();
    }

}

//退出按钮
void MainWindow::on_actionExit_triggered()
{
    ExitProcess();
    this->close();
}

//重新加载文件
void MainWindow::on_actionReload_triggered()
{
    qDebug() << "Reload" << m_LastOpenFileName;
    //关闭当前
    on_actionClose_File_triggered();
    //重新打开
    if(!m_LastOpenFileName.isEmpty())
    {
        qDebug() << "isNotEmpty()" << m_LastOpenFileName;
        ReadFile(m_LastOpenFileName);
    }

}

//进程按钮
void MainWindow::on_actionProcess_triggered()
{
    m_ProcessDialog = QSharedPointer<ProcessDialog>(new ProcessDialog());
    m_ProcessDialog->show();
}


//处理文件
bool MainWindow::ReadFile(QString FileName)
{

    m_file.setFileName(FileName);
    //读写方式打开
    if(!m_file.open(QIODevice::ReadWrite))
    {
        ui->FILE_PATH->setText("文件打开失败");
        ClearInfo();
        return false;
    }
    else
    {
        QFileInfo info(m_file);
        //设置窗口标题
        setWindowTitle(m_WindowTitel + "  ---->  " + info.fileName());
        //文件路径
        ui->FILE_PATH->setText(FileName);
        //文件大小
        QString FileSize(QString::number(m_file.size()));
        ui->FILE_SIZE->setText(FileSize + QStringLiteral(" 字节"));
        //文件创建时间
        ui->CREATE_TIME->setText(info.birthTime().toString("yyyy-MM-dd hh:mm:ss"));
        //读取文件
        m_bFileBuffer = m_file.readAll();
        //读取DOS Header
        QByteArray bDosHeader = QByteArray::fromRawData(m_bFileBuffer.data(),0x40);
        //文件MD5
        QByteArray bFileMD5 = QCryptographicHash::hash(m_bFileBuffer, QCryptographicHash::Md5);
        ui->FILE_MD5->setText(bFileMD5.toHex().constData());

        if(m_bFileBuffer.at(0) == 0x4d && m_bFileBuffer.at(1) == 0x5a)
        {
            m_IsPEFile = true;
            AnalyseDOSHeader(bDosHeader);
        }
        else
        {
            ui->PE_STYPE->setText("当前可能不是PE文件!");
        }
    }
    return true;
}

bool MainWindow::AnalyseDOSHeader(QByteArray & bDOSHeader)
{
    //清除残留
    ui->DOS_HEADER_TABLE->clear();

    //DOS_Header结构体
    PIMAGE_DOS_HEADER tagDosHeader = (PIMAGE_DOS_HEADER)bDOSHeader.data();

    QChar qcZero = '0';

    //DOS_Header结构体成员
    QStringList list;
    list << "e_magic" << "e_cblp" << "e_cp" << "e_crlc" << "e_cparhdr" << "e_minalloc" << "e_maxalloc" << "e_ss"
         << "e_sp" << "e_csum" << "e_ip" << "e_cs" << "e_lfarlc" << "e_ovno" << "e_res[0]" << "e_res[1]"
         << "e_res[2]" << "e_res[3]" << "e_oemid" << "e_oeminfo" << "e_res2[0]" << "e_res2[1]" << "e_res2[2]" << "e_res2[3]"
         << "e_res2[4]" << "e_res2[5]" << "e_res2[6]" << "e_res2[7]" << "e_res2[8]" << "e_res2[9]" << "e_lfanew";

    //bDOSHeader.toHex();
    for(int i = 0;i < list.size();i++)
    {
        ui->DOS_HEADER_TABLE->setItem(i,0,new QTableWidgetItem(list.at(i)));

        //因为e_lfanew比其他成员长.所以单独处理
        if(30 == i)
        {
            //ui->DOS_HEADER_TABLE->setItem(i,1,new QTableWidgetItem(QString::number(nValue,16).toUpper()));
            //转换读取到的值.
            QString string = tr("%1").arg(tagDosHeader->e_lfanew,8,16,qcZero).toUpper();
            ui->DOS_HEADER_TABLE->setItem(i,1,new QTableWidgetItem(string));
        }
        else
        {
            unsigned short nValue = *((unsigned short*)tagDosHeader + i);
            //QString::number(nValue,16).toUpper().sprintf("%02d",nValue))
            //转换读取到的值.
            QString string = tr("%1").arg(nValue,4,16,qcZero).toUpper();
            ui->DOS_HEADER_TABLE->setItem(i,1,new QTableWidgetItem(string));
        }

    }

    m_IsFirstOpen = true;
    AnalysePEHeader(tagDosHeader->e_lfanew);

    return true;
}

//修改DOS_HEADER_TABLE
void MainWindow::on_DOS_HEADER_TABLE_cellChanged(int row, int column)
{
    if(m_IsFirstOpen)
    {
        m_IsFileChange = true;
        if(row != 30)
        {
            QString text(ui->DOS_HEADER_TABLE->item(row,column)->text());
            bool OK;
            //qDebug() << "row != 30" <<  text.toUShort(&OK,16);
            *((WORD*)m_bFileBuffer.data() + row) = text.toUShort(&OK,16);
        }
        //DWORD
        else if(row == 30)
        {
            QString text(ui->DOS_HEADER_TABLE->item(row,column)->text());
            bool OK;
            //qDebug() << "row == 30" << text;
            // qDebug() << text.toUInt(&OK,16);

            *(long*)(m_bFileBuffer.data() + row * sizeof(WORD)) = text.toUInt(&OK,16);
        }

        //qDebug() << "column" << column;
        // qDebug() << "row" << row;
    }
}

//解析PE头
bool MainWindow::AnalysePEHeader(DWORD PE_Offset)
{
    qDebug() << PE_Offset;
    QChar qcZero = '0';
    m_PEOffset = PE_Offset;
    WORD* pMachine =  (WORD*)(m_bFileBuffer.data() + PE_Offset + sizeof(DWORD));

    switch (*pMachine)
    {
    ui->PE_STYPE->clear();
    case IMAGE_FILE_MACHINE_UNKNOWN:
        ui->PE_STYPE->setText("Machine Unknown");
        break;
    case IMAGE_FILE_MACHINE_I386:
        ui->PE_STYPE->setText("Intel 386");
        break;
    case IMAGE_FILE_MACHINE_ALPHA:
        ui->PE_STYPE->setText("Alpha_AXP");
        break;
    case IMAGE_FILE_MACHINE_POWERPC:
        ui->PE_STYPE->setText("IBM PowerPC Little-Endian");
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        ui->PE_STYPE->setText("AMD64 (K8)");
        break;
    }
    // qDebug() << *pMachine;

    if(*pMachine == IMAGE_FILE_MACHINE_AMD64)
    {
        //PIMAGE_NT_HEADERS64 tagPEHeader = (PIMAGE_NT_HEADERS64)(m_bFileBuffer.data() + PE_Offset);
    }
    else
    {
        //File Header
        tagPEHeader = (PIMAGE_NT_HEADERS32)(m_bFileBuffer.data() + PE_Offset);

        m_SizeOfImage = tagPEHeader->OptionalHeader.SizeOfImage;
        m_SectionHeaders = tagPEHeader->OptionalHeader.SizeOfHeaders;
        m_FileAlignment =  tagPEHeader->OptionalHeader.FileAlignment;
        m_SectionAlignment =  tagPEHeader->OptionalHeader.SectionAlignment;
        m_SectionCount = tagPEHeader->FileHeader.NumberOfSections;
        m_ImageBase = tagPEHeader->OptionalHeader.ImageBase;
        m_ImportTableRva = tagPEHeader->OptionalHeader.DataDirectory[1].VirtualAddress;
        m_ImportTableSize = tagPEHeader->OptionalHeader.DataDirectory[1].Size;
        m_ResourceRVA = tagPEHeader->OptionalHeader.DataDirectory[2].VirtualAddress;
        m_ResourceSize = tagPEHeader->OptionalHeader.DataDirectory[2].Size;
        m_RelocRVA = tagPEHeader->OptionalHeader.DataDirectory[5].VirtualAddress;
        m_RelocSize = tagPEHeader->OptionalHeader.DataDirectory[5].Size;
        m_TlsRVA = tagPEHeader->OptionalHeader.DataDirectory[9].VirtualAddress;
        m_TlsSize = tagPEHeader->OptionalHeader.DataDirectory[9].Size;


        qDebug("m_RelocRVA:%p",m_RelocRVA);
        qDebug("m_RelocSize:%p",m_RelocSize);

        QStringList FileHeaderValueList;
        QStringList FileHeaderlist;
        FileHeaderlist << "Machine" << "NumberOfSections" << "TimeDateStamp"
                       << "PointerToSymbolTable" << "NumberOfSymbols"
                       << "SizeOfOptionalHeader" << "Characteristics";

        FileHeaderValueList << tr("%1").arg(tagPEHeader->FileHeader.Machine,4,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.NumberOfSections,4,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.TimeDateStamp,8,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.PointerToSymbolTable,8,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.NumberOfSymbols,8,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.SizeOfOptionalHeader,4,16,qcZero).toUpper()
                            << tr("%1").arg(tagPEHeader->FileHeader.Characteristics,4,16,qcZero).toUpper();

        ui->File_HEADER_TABLE->setRowCount(FileHeaderlist.size());
        for(int i = 0;i < FileHeaderlist.size(); i++)
        {
            ui->File_HEADER_TABLE->setItem(i,0,new QTableWidgetItem(FileHeaderlist.at(i)));
            ui->File_HEADER_TABLE->setItem(i,1,new QTableWidgetItem(FileHeaderValueList.at(i)));
            ui->File_HEADER_TABLE->item(i,0)->setFlags(Qt::ItemIsEnabled);
        }
        ui->File_HEADER_TABLE->item(0,1)->setBackgroundColor(QColor(0,120,215));
        ui->File_HEADER_TABLE->item(6,1)->setBackgroundColor(QColor(0,120,215));


        //Optional Header
        QStringList OptionalHeaderValueList;
        QStringList OptionalHeaderlist;

        OptionalHeaderlist << "Magic" << "MajorLinkerVersion" << "MinorLinkerVersion" << "SizeOfCode"
                           << "SizeOfInitializedData" << "SizeOfUninitializedData" << "AddressOfEntryPoint" << "BaseOfCode"
                           << "BaseOfData"
                           << "ImageBase" << "SectionAlignment" << "FileAlignment" << "MajorOperatingSystemVersion"
                           << "MinorOperatingSystemVersion" << "MajorImageVersion" << "MinorImageVersion" << "MajorSubsystemVersion"
                           << "MinorSubsystemVersion" << "Win32VersionValue" << "SizeOfImage" << "SizeOfHeaders"
                           << "CheckSum" << "Subsystem" << "DllCharacteristics" << "SizeOfStackReserve"
                           << "SizeOfStackCommit" << "SizeOfHeapReserve" << "SizeOfHeapCommit" << "LoaderFlags"
                           << "NumberOfRvaAndSizes";

        OptionalHeaderValueList << tr("%1").arg(tagPEHeader->OptionalHeader.Magic,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MajorLinkerVersion,2,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MinorLinkerVersion,2,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfCode,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfInitializedData,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfUninitializedData,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.AddressOfEntryPoint,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.BaseOfCode,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.BaseOfData,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.ImageBase,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SectionAlignment,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.FileAlignment,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MajorOperatingSystemVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MinorOperatingSystemVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MajorImageVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MinorImageVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MajorSubsystemVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.MinorSubsystemVersion,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.Win32VersionValue,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfImage,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfHeaders,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.CheckSum,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.Subsystem,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.DllCharacteristics,4,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfStackReserve,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfStackCommit,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfHeapReserve,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.SizeOfHeapCommit,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.LoaderFlags,8,16,qcZero).toUpper()
                                << tr("%1").arg(tagPEHeader->OptionalHeader.NumberOfRvaAndSizes,8,16,qcZero).toUpper();


        ui->OPTIONAL_HEADER_TABLE->setRowCount(OptionalHeaderlist.size());
        for(int i = 0;i < OptionalHeaderlist.size(); i++)
        {
            ui->OPTIONAL_HEADER_TABLE->setItem(i,0,new QTableWidgetItem(OptionalHeaderlist.at(i)));
            ui->OPTIONAL_HEADER_TABLE->setItem(i,1,new QTableWidgetItem(OptionalHeaderValueList.at(i)));
            ui->OPTIONAL_HEADER_TABLE->item(i,0)->setFlags(Qt::ItemIsEnabled);
        }
        ui->OPTIONAL_HEADER_TABLE->item(0,1)->setBackgroundColor(QColor(0,120,215));

        //Data Directory
        //QStringList OptionalHeaderValueList;
        QStringList DataDirectoryList;
        DataDirectoryList << "Export Directory" << "Import Directory" << "Resource Directory" << "Exception Directory"
                          << "Security Directory" << "Base Relocation Table" << "Debug Directory" << "Architecture Specific Data"
                          << "RVA of GP" << "Tls Directory" << "Load Configuration Directory" << "Bound Import Directory in headers"
                          << "Import Address Table " << "Delay Load Import Descriptors" << "COM Runtime descriptor";

        ui->DATA_DIRECTORY_TABLE->setRowCount(DataDirectoryList.size());
        for(int i = 0;i < DataDirectoryList.size(); i++)
        {

            ui->DATA_DIRECTORY_TABLE->setItem(i,0,new QTableWidgetItem(DataDirectoryList.at(i)));
            ui->DATA_DIRECTORY_TABLE->item(i,0)->setFlags(Qt::ItemIsEnabled);
            ui->DATA_DIRECTORY_TABLE->setItem(i,1,new QTableWidgetItem(tr("%1").arg(tagPEHeader->OptionalHeader.DataDirectory[i].VirtualAddress,8,16,qcZero).toUpper()));
            ui->DATA_DIRECTORY_TABLE->setItem(i,2,new QTableWidgetItem(tr("%1").arg(tagPEHeader->OptionalHeader.DataDirectory[i].Size,8,16,qcZero).toUpper()));
        }

        //Session
        //qDebug() << "offsetofsection";
        m_SectionOffset = tagPEHeader->FileHeader.SizeOfOptionalHeader + sizeof(tagPEHeader->FileHeader) + sizeof(tagPEHeader->Signature) + PE_Offset;
        // int  SectionsNumber =  tagPEHeader->FileHeader.NumberOfSections;
        AnalyseSessionHeader(m_SectionOffset,m_SectionCount);

    }

    return true;
}

bool MainWindow::AnalyseSessionHeader(DWORD SectionsOffset,DWORD SectionsNumber)
{


    //qDebug() << SectionsOffset;
    QChar qcZero = '0';
    pTagSectionHeader = (PIMAGE_SECTION_HEADER)(m_bFileBuffer.data() + SectionsOffset);

    //SectionList.push_back();

    ui->SECTIONS_HEADER_TABLE->setRowCount(SectionsNumber);
    QString str;
    for(int n = 0;n < SectionsNumber; n++)
    {
        m_SectionList.push_back(pTagSectionHeader[n]);
        m_bSectionName = (char*)pTagSectionHeader[n].Name;
        ui->SECTIONS_HEADER_TABLE->setItem(n,0,new QTableWidgetItem(QString(m_bSectionName.mid(0,8))));
        ui->SECTIONS_HEADER_TABLE->setItem(n,1,new QTableWidgetItem(tr("%1").arg(pTagSectionHeader[n].VirtualAddress,8,16,qcZero).toUpper()));
        ui->SECTIONS_HEADER_TABLE->setItem(n,2,new QTableWidgetItem(tr("%1").arg(pTagSectionHeader[n].Misc.VirtualSize,8,16,qcZero).toUpper()));
        ui->SECTIONS_HEADER_TABLE->setItem(n,3,new QTableWidgetItem(tr("%1").arg(pTagSectionHeader[n].PointerToRawData,8,16,qcZero).toUpper()));
        ui->SECTIONS_HEADER_TABLE->setItem(n,4,new QTableWidgetItem(tr("%1").arg(pTagSectionHeader[n].SizeOfRawData,8,16,qcZero).toUpper()));
        ui->SECTIONS_HEADER_TABLE->setItem(n,5,new QTableWidgetItem(tr("%1").arg(pTagSectionHeader[n].Characteristics,8,16,QLatin1Char('0')).toUpper()));
        //        qDebug("Name:%s",(pTagSectionHeader[n]).Name);
        //        qDebug("VirtualAddress:%08x",pTagSectionHeader[n].VirtualAddress);
        //        qDebug("VirtualSize:%08x",pTagSectionHeader[n].Misc.VirtualSize);
        //        qDebug("PointerToRawData:%08x",pTagSectionHeader[n].PointerToRawData);
        //        qDebug("SizeOfRawData:%08x",pTagSectionHeader[n].SizeOfRawData);
        //        qDebug("Characteristics:%08x",pTagSectionHeader[n].Characteristics);
    }



    AnalyseImportTbale();

    //初始化重定位表
    if(m_RelocRVA != 0)
    {
        ui->RELOCDIR_TABLE->setDisabled(false);
        ui->RELOC_TABLE->setDisabled(false);
        InitRelocHeader();
    }

    //解析Tls表
    if(m_TlsRVA != 0)
    {
        InitTlsHeader();
        AnalyseTlsTable();
    }

    //解析资源表
    if(m_ResourceRVA != 0)
    {
        AnalyseResTable();
    }


    return true;
}

//解析导入表
bool MainWindow::AnalyseImportTbale()
{
    if(m_ImportTableRva != 0)
    {
        ImportFOA = (DWORD)ImageRvaToVa(tagPEHeader,(PVOID)m_ImageBase,m_ImportTableRva,NULL) - m_ImageBase;
        pImportTable = (PIMAGE_IMPORT_DESCRIPTOR)(m_bFileBuffer.data() + ImportFOA);
        qDebug() << pImportTable;

        dwImportCount = 0;
        while(pImportTable[dwImportCount].Name)
        {
            ui->DLL_TABLE->setRowCount(ui->DLL_TABLE->rowCount() + 1);
            DWORD DllNameOffset = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pImportTable[dwImportCount].Name,NULL));
            qDebug("DLLName:%s", (LPCSTR)(m_bFileBuffer.data() + DllNameOffset));
            ui->DLL_TABLE->setItem(dwImportCount,0,new QTableWidgetItem(QString((char*)(m_bFileBuffer.data() + DllNameOffset))));
            ui->DLL_TABLE->setItem(dwImportCount,1,new QTableWidgetItem(tr("%1").arg(pImportTable[dwImportCount].OriginalFirstThunk,8,16,QLatin1Char('0')).toUpper()));
            ui->DLL_TABLE->setItem(dwImportCount,2,new QTableWidgetItem(tr("%1").arg(pImportTable[dwImportCount].Name,8,16,QLatin1Char('0')).toUpper()));
            ui->DLL_TABLE->setItem(dwImportCount,3,new QTableWidgetItem(tr("%1").arg(pImportTable[dwImportCount].FirstThunk,8,16,QLatin1Char('0')).toUpper()));
            dwImportCount++;
        }
        qDebug() << "dwImportCount:" << dwImportCount;
    }
    return true;
}



QString MainWindow::formatUInt(unsigned int n)
{
    QChar chZero = '0';
    return tr("%1").arg(n, 8, 16, chZero).toUpper();
}

QString MainWindow::formatUShort(unsigned short n)
{
    QChar chZero = '0';
    return tr("%1").arg(n, 4, 16, chZero).toUpper();
}



//节表的右键响应
void MainWindow::on_SECTIONS_HEADER_TABLE_customContextMenuRequested(const QPoint &pos)
{
    if(ui->SECTIONS_HEADER_TABLE->rowCount() < 1)
    {
        return;
    }
    else if(ui->SECTIONS_HEADER_TABLE->itemAt(pos) != 0)
    {
        m_menu->exec(QCursor::pos());
    }
}

//添加节
void MainWindow::slot_AddSection()
{
    //如果节后的空闲小于或者等于一个节的大小.表示可以添加.否则不能添加
    if( (m_SectionCount * sizeof(IMAGE_SECTION_HEADER) + m_SectionOffset) <= (m_SectionHeaders - sizeof(IMAGE_SECTION_HEADER)))
    {
        m_AddSectionDialog = QSharedPointer<AddSectionDialog>(new AddSectionDialog());
        //文件对齐
        m_AddSectionDialog->setFileAlignment(m_FileAlignment);
        //内存对齐
        m_AddSectionDialog->setSectionAlignment(m_SectionAlignment);
        //区段个数
        m_AddSectionDialog->setNumberOfSection(m_SectionCount);
        //区段的偏移
        m_AddSectionDialog->setSectionOffset(m_SectionOffset);
        //头部总大小
        m_AddSectionDialog->setSectionHeaders(m_SectionHeaders);
        //镜像总大小
        m_AddSectionDialog->setSizeOfImage(m_SizeOfImage);
        //文件缓冲区
        m_AddSectionDialog->setFileBuffer(m_bFileBuffer);
        //区段链表
        m_AddSectionDialog->setSectionList(m_SectionList);
        //PE偏移
        m_AddSectionDialog->setPEOffset(m_PEOffset);

        if(m_AddSectionDialog->exec() == 1)
        {

            if(m_AddSectionDialog->IsEmpty())
            {
                m_bFileBuffer.replace(0, m_file.size(), m_AddSectionDialog->FileBuffer());
            }
            else
            {
                m_file.seek(m_AddSectionDialog->FileSeek());
                m_file.write(m_AddSectionDialog->AppendFileBuffer());
            }
            m_IsFileChange = true;
            m_AddSectionDialog->close();
        }
    }
}

void MainWindow::slot_ExtendLastSection()
{

}

//添加导入函数
void MainWindow::slot_AddImportFunc()
{
    if(m_IsPEFile)
    {
        qDebug() << "slot_AddImportFunc";
        m_AddImportFuncDialog = QSharedPointer<AddImportFuncDialog>(new AddImportFuncDialog());
        if(m_AddImportFuncDialog->exec() == QDialog::Accepted)
        {
            qDebug() << "Add";
            //如果函数名和PE文件名都不为空.表示有数据.
            if(!m_AddImportFuncDialog->FuncName().isEmpty() && !m_AddImportFuncDialog->FileName().isEmpty())
            {
                m_AddFuncName = m_AddImportFuncDialog->FuncName();
                m_AddFuncFileName = m_AddImportFuncDialog->FileName();
                qDebug() << "FuncName" << m_AddFuncName;
                qDebug() << "FuncFileName" << m_AddFuncFileName;
                //导入表注入
                ImportInjack();
            }
        }
    }
}

//导入表注入处理
bool MainWindow::ImportInjack()
{

    //ImportFOA
    //dwImportCount
    if(m_ImportTableSize < m_FileAlignment)
    {
        qDebug() << "m_ImportTableSize" << m_ImportTableSize;
        m_bFileBuffer.append(m_FileAlignment,0);
        DWORD dwAddInfoRVA = 0;
        DWORD dwAddInfoFOA = 0;
        PIMAGE_SECTION_HEADER pLastHeader = (PIMAGE_SECTION_HEADER)(m_bFileBuffer.data() + m_SectionOffset + sizeof(IMAGE_SECTION_HEADER)* (m_SectionList.size() - 1));
        pLastHeader->Characteristics = 0xC0000040;
        if(pLastHeader->SizeOfRawData == 0 && m_SectionList.size() >= 2)
        {
            dwAddInfoRVA = pTagSectionHeader[m_SectionList.size() - 2].SizeOfRawData + pTagSectionHeader[m_SectionList.size() - 1].VirtualAddress;
            dwAddInfoFOA = pTagSectionHeader[m_SectionList.size() - 2].SizeOfRawData + pTagSectionHeader[m_SectionList.size() - 1].PointerToRawData;
            pLastHeader->PointerToRawData  = pTagSectionHeader[m_SectionList.size() - 2].SizeOfRawData + pTagSectionHeader[m_SectionList.size() - 2].SizeOfRawData;
            qDebug("LastHeader_PointerToRawData:%p",pLastHeader->PointerToRawData);
        }
        else
        {
            qDebug("SizeOfRawData:%p",pLastHeader->SizeOfRawData);
            qDebug("PointerToRawData:%p",pLastHeader->PointerToRawData);
            dwAddInfoRVA = pLastHeader->SizeOfRawData + pLastHeader->VirtualAddress;
            dwAddInfoFOA = pLastHeader->SizeOfRawData + pLastHeader->PointerToRawData;
        }

        //修改最后一个节的内存大小
        pLastHeader->Misc.VirtualSize += m_FileAlignment;
        //修改最后一个节的文件大小
        pLastHeader->SizeOfRawData += m_FileAlignment;
        //修改总文件大小
        tagPEHeader->OptionalHeader.SizeOfImage += m_FileAlignment;
        //导入表的位置.
        DWORD dwDataDirectoryOffset = sizeof(IMAGE_NT_HEADERS32) + m_PEOffset - 8 * 15;
        //        qDebug("dwAddInfoRVA:%p",dwAddInfoRVA);
        //        qDebug("dwAddInfoFOA:%p",dwAddInfoFOA);
        //        qDebug("dwDataDirectoryOffset:%p",dwDataDirectoryOffset);
        PIMAGE_DATA_DIRECTORY pIMPORT = (PIMAGE_DATA_DIRECTORY)(m_bFileBuffer.data() + dwDataDirectoryOffset);
        //        qDebug("Size:%p",pIMPORT->Size);
        //        qDebug("Size:%p",pIMPORT->VirtualAddress);

        //原始数据的FOA
        DWORD dwOriginalDataFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pIMPORT->VirtualAddress,NULL));
        //qDebug("OriginalDataFOA:%p",dwOriginalDataFOA);
        //原始数据的大小
        DWORD dwSizeOfCopyData = pIMPORT->Size - sizeof(IMAGE_IMPORT_DESCRIPTOR);
        //拷贝原始数据到扩展后的位置.重建导入表
        memcpy((m_bFileBuffer.data() + dwAddInfoFOA),(m_bFileBuffer.data() + dwOriginalDataFOA),dwSizeOfCopyData);
        //qDebug("dwSizeOfCopyData:%p",dwSizeOfCopyData);
        pIMPORT->Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        pIMPORT->VirtualAddress =  dwAddInfoRVA;

        //新的导入表的DLLNAME的RVA
        DWORD dwNewNameRVA = dwAddInfoRVA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 + 8;
        DWORD dwFirstThunkRVA = dwAddInfoRVA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3;
        DWORD dwOriginalFirstThunkRVA = dwAddInfoRVA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3;
        //        qDebug("Name:%p",dwNewNameRVA);
        //        qDebug("FirstThunk:%p",dwFirstThunkRVA);
        //        qDebug("OriginalFirstThunk:%p",dwOriginalFirstThunkRVA);

        //IAT的RVA
        DWORD dwImportByNameRVA = m_AddFuncFileName.size() + 1 + dwAddInfoRVA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 + 8;

        *(DWORD*)(m_bFileBuffer.data() + dwAddInfoFOA + dwSizeOfCopyData) = dwOriginalFirstThunkRVA;
        *(DWORD*)(m_bFileBuffer.data() + dwAddInfoFOA + dwSizeOfCopyData + 0xc) = dwNewNameRVA;
        *(DWORD*)(m_bFileBuffer.data() + dwAddInfoFOA + dwSizeOfCopyData + 0x10) = dwFirstThunkRVA;
        *(DWORD*)(m_bFileBuffer.data() + dwAddInfoFOA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3) = dwImportByNameRVA;

        //存放DLLNAME的FOA
        DWORD dwNewNameFOA = dwAddInfoFOA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 + 8;
        //存放函数名的FOA
        DWORD dwNewIATFOA = dwAddInfoFOA + dwSizeOfCopyData + sizeof(IMAGE_IMPORT_DESCRIPTOR) * 3 + 8 + m_AddFuncFileName.size() + 1 + sizeof(WORD);

        qDebug("NewNameFOA:%p",dwNewNameFOA);
        qDebug("NewIATFOA:%p",dwNewIATFOA);

        memcpy((m_bFileBuffer.data() + dwNewNameFOA),m_AddFuncFileName.toStdString().c_str(),m_AddFuncFileName.size());
        memcpy((m_bFileBuffer.data() + dwNewIATFOA),m_AddFuncName.toStdString().c_str(),m_AddFuncName.size());


        //        if(strcmp((char*)pTagSectionHeader->Name,".text") == 0)
        //        {
        //            qDebug(".text,%p",pTagSectionHeader->Characteristics);
        //            pTagSectionHeader->Characteristics = 0xC0000040;
        //        }

        QMessageBox::warning(NULL, "information", QStringLiteral("添加成功.注意保存"), QMessageBox::Yes);

        m_IsFileChange = true;
    }
    return true;
}


void MainWindow::InitFuncTable()
{
    QStringList IATLabels;
    IATLabels << QStringLiteral("FTs(IAT)")
              << QStringLiteral("Name");
    ui->FUNC_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->FUNC_TABLE->horizontalHeader()->setVisible(true);
    ui->FUNC_TABLE->setHorizontalHeaderLabels(IATLabels);//设置表头
    ui->FUNC_TABLE->setRowCount(0);
    ui->FUNC_TABLE->setSelectionBehavior(QAbstractItemView::SelectRows);  //整行选中的方式
}

//遍历导入表
void MainWindow::on_DLL_TABLE_itemClicked(QTableWidgetItem *item)
{
    ui->FUNC_TABLE->clear();
    InitFuncTable();
    bool OK;
    qDebug() << "on_DLL_TABLE_itemClicked" << item->row();
    DWORD IATs = ui->DLL_TABLE->item(item->row(),3)->text().toUInt(&OK,16);
    PIMAGE_THUNK_DATA pIAT_FA = (PIMAGE_THUNK_DATA)(m_bFileBuffer.data() + (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,IATs,NULL)));
    qDebug("IATs %p",IATs);
    qDebug("IATOffset %p",pIAT_FA);

    DWORD INTs = ui->DLL_TABLE->item(item->row(),1)->text().toUInt(&OK,16);
    PIMAGE_THUNK_DATA pINT_FA = (PIMAGE_THUNK_DATA)(m_bFileBuffer.data() + (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,INTs,NULL)));

    qDebug("INTs %p",INTs);
    qDebug("INTOffset %p",pINT_FA);

    int i = 0;
    while (pIAT_FA[i].u1.AddressOfData)
    {
        ui->FUNC_TABLE->setRowCount(ui->FUNC_TABLE->rowCount() + 1);
        if (IMAGE_SNAP_BY_ORDINAL32(pIAT_FA[i].u1.AddressOfData))
        {
            //序号导入
            qDebug("Number:%p Addr:%p\n", pIAT_FA[i].u1.Ordinal & 0xFFFF, pINT_FA[i].u1.Function);
            ui->FUNC_TABLE->setItem(i,0,new QTableWidgetItem(tr("%1").arg(pINT_FA[i].u1.Function,8,16,QLatin1Char('0')).toUpper()));
            ui->FUNC_TABLE->setItem(i,1,new QTableWidgetItem(tr("%1 %L2").arg(QStringLiteral("序号:")).arg(pIAT_FA[i].u1.Ordinal & 0xFFFF,8,16,QLatin1Char('0')).toUpper()));
        }
        else
        {
            PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)(m_bFileBuffer.data() + (DWORD)ImageRvaToVa(tagPEHeader, (PVOID)0,pINT_FA[i].u1.AddressOfData,NULL));
            qDebug("Name:%s Addr:%p\n", pImportByName->Name, pIAT_FA[i].u1.Function);
            ui->FUNC_TABLE->setItem(i,1,new QTableWidgetItem(QString((char*)(pImportByName->Name))));
            ui->FUNC_TABLE->setItem(i,0,new QTableWidgetItem(tr("%1").arg(pIAT_FA[i].u1.Function,8,16,QLatin1Char('0')).toUpper()));
        }
        i++;
    }
}

//添加导入函数
void MainWindow::on_DLL_TABLE_customContextMenuRequested(const QPoint &pos)
{
    m_AddImportFunc->exec(QCursor::pos());
}

//初始化重定位表信息
void MainWindow::InitRelocHeader()
{
    DWORD dwRelocFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,m_RelocRVA,NULL));
    qDebug("dwRelocFOA:%p",dwRelocFOA);
    PIMAGE_BASE_RELOCATION pRelocDir = (PIMAGE_BASE_RELOCATION)(m_bFileBuffer.data() + dwRelocFOA);

    qDebug("pRelocDir:%p",pRelocDir);
    qDebug("VirtualAddress:%p",pRelocDir->VirtualAddress);
    qDebug("SizeOfBlock:%p",pRelocDir->SizeOfBlock);
    QStringList RelocLabels;
    RelocLabels << "Virtual Address"
                << "Size Of Block"
                << "Items";
    ui->RELOCDIR_TABLE->setHorizontalHeaderLabels(RelocLabels);
    ui->RELOCDIR_TABLE->horizontalHeader()->setVisible(true);

    // handle data
    unsigned int nItemNum = 0;
    unsigned int nCurSize = 0;
    unsigned int nTotalSize = nCurSize;
    DWORD dwRelocDirAddr = 0;
    while(nTotalSize < m_RelocSize)
    {
        nCurSize = pRelocDir->SizeOfBlock;
        nTotalSize += nCurSize;

        InsertRelocDirTable(pRelocDir);
        // qDebug("InsertRelocDirTable");
        nItemNum = CreateRelocDirTable((DWORD)pRelocDir, nCurSize - sizeof(DWORD) * 2);

        dwRelocDirAddr = (DWORD)(m_bFileBuffer.data() + dwRelocFOA) + nTotalSize;
        //        qDebug("RelocDirAddr:%p",dwRelocDirAddr);
        //        qDebug("nTotalSize:%d",nTotalSize);
        pRelocDir = (PIMAGE_BASE_RELOCATION)dwRelocDirAddr;
    }
}

//插入重定位表
bool MainWindow::InsertRelocDirTable(PIMAGE_BASE_RELOCATION pRelocDir)
{
    int nRow = ui->RELOCDIR_TABLE->rowCount();
    ui->RELOCDIR_TABLE->setRowCount(nRow + 1);

    QString strData = formatUInt(pRelocDir->VirtualAddress);
    ui->RELOCDIR_TABLE->setItem(nRow, 0, new QTableWidgetItem(strData));
    strData = formatUInt(pRelocDir->SizeOfBlock);
    ui->RELOCDIR_TABLE->setItem(nRow, 1, new QTableWidgetItem(strData));

    // qDebug() << "InsertRelocDirTable::pRelocDir->VirtualAddress" << strData;
    //qDebug() << "InsertRelocDirTable::pRelocDir->SizeOfBlock" << strData;

    return true;
}

//生成重定位表子表
unsigned int MainWindow::CreateRelocDirTable(DWORD dwRelocDirAddr, DWORD dwTypeSize)
{
    PIMAGE_BASE_RELOCATION pRelocDir = (PIMAGE_BASE_RELOCATION)dwRelocDirAddr;
    DWORD dwBaseRVA = pRelocDir->VirtualAddress;
    DWORD nCurOffset = dwRelocDirAddr + sizeof(DWORD) * 2;

    //    qDebug("pRelocDir:%p",pRelocDir);
    //    qDebug("VirtualAddress:%p",dwBaseRVA);
    //    qDebug("nCurOffset:%p",nCurOffset);

    // create new table
    QStringList strHeader;
    strHeader << "Item"
              << "RVA"
              << "Type";
    QTableWidget* pNewTable = new QTableWidget(0, strHeader.size());
    pNewTable->setHorizontalHeaderLabels(strHeader);
    ui->RELOC_TABLE->horizontalHeader()->setVisible(true);

    DWORD dwCount = 0;
    DWORD dwRVA = 0;
    WORD wData;
    QString strItem = "";
    QString strRVA = "";
    QString strType = "";
    while(dwCount * sizeof(WORD) < dwTypeSize)
    {
        pNewTable->setRowCount(dwCount + 1);
        if(*(WORD*)nCurOffset & 0xF000)   // HIGHLOW
        {
            wData = *(WORD*)nCurOffset & 0x0FFF;
            dwRVA = wData + dwBaseRVA;
            strRVA = formatUInt(dwRVA);
            strType = "HIGHLOW";
            //qDebug("wData:%p",wData);
            //qDebug("dwRVA:%p",dwRVA);

        }
        else    // ABSOLUTE
        {
            wData = 0;
            strRVA = "N/A";
            strType = "ABSOLUTE";
        }
        strItem = formatUShort(wData);

        pNewTable->setItem(dwCount, 0, new QTableWidgetItem(strItem));
        pNewTable->setItem(dwCount, 1, new QTableWidgetItem(strRVA));
        pNewTable->setItem(dwCount, 2, new QTableWidgetItem(strType));

        dwCount += 1;
        nCurOffset += 2;
    }

    // insert into module map
    int nRow = ui->RELOCDIR_TABLE->rowCount() - 1;
    m_mRelocTable[nRow] = pNewTable;

    QString strData = formatUInt(dwCount);
    ui->RELOCDIR_TABLE->setItem(nRow, 2, new QTableWidgetItem(strData));
    return dwCount;
}

//重定位表点击DIR,显示RELOC_TABLE
void MainWindow::on_RELOCDIR_TABLE_cellClicked(int nRow, int column)
{
    if(ui->RELOC_LAYOUT->itemAt(2) != nullptr)
    {
        ui->RELOC_LAYOUT->itemAt(2)->widget()->setHidden(true);
        ui->RELOC_LAYOUT->removeItem(ui->RELOC_LAYOUT->itemAt(2));
    }
    ui->RELOC_LAYOUT->insertWidget(-1, m_mRelocTable[nRow]);
    ui->RELOC_LAYOUT->itemAt(2)->widget()->setHidden(false);
}

void MainWindow::InitTlsHeader()
{
    QStringList TlsLabels;
    TlsLabels << QStringLiteral("Member")
              << QStringLiteral("Value(VA)")
              << QStringLiteral("Value(FOA)");
    ui->TLS_TABLE->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->TLS_TABLE->horizontalHeader()->setVisible(true);
    ui->TLS_TABLE->setHorizontalHeaderLabels(TlsLabels);//设置表头
    ui->TLS_TABLE->setRowCount(4);
    ui->TLS_TABLE->setSelectionBehavior(QAbstractItemView::SelectRows);  //整行选中的方式
}

//解析Tls表
bool MainWindow::AnalyseTlsTable()
{
    DWORD dwTlsTableFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,m_TlsRVA,NULL));
    PIMAGE_TLS_DIRECTORY32 pTls = (PIMAGE_TLS_DIRECTORY32)(m_bFileBuffer.data() + dwTlsTableFOA);
    ui->TLS_TABLE->setItem(0,0,new QTableWidgetItem(QString("StartAddressOfRawData:")));
    ui->TLS_TABLE->setItem(1,0,new QTableWidgetItem(QString("EndAddressOfRawData:")));
    ui->TLS_TABLE->setItem(2,0,new QTableWidgetItem(QString("AddressOfIndex:")));
    ui->TLS_TABLE->setItem(3,0,new QTableWidgetItem(QString("AddressOfCallBacks:")));

    ui->TLS_TABLE->setItem(0,1,new QTableWidgetItem(tr("%1").arg(pTls->StartAddressOfRawData,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(1,1,new QTableWidgetItem(tr("%1").arg(pTls->EndAddressOfRawData,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(2,1,new QTableWidgetItem(tr("%1").arg(pTls->AddressOfIndex,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(3,1,new QTableWidgetItem(tr("%1").arg(pTls->AddressOfCallBacks,8,16,QLatin1Char('0')).toUpper()));


    DWORD dwStartAddressFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pTls->StartAddressOfRawData - m_ImageBase,NULL));
    qDebug("dwStartAddressFOA:%p",dwStartAddressFOA);
    DWORD dwEndAddressFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pTls->EndAddressOfRawData - m_ImageBase,NULL));
    qDebug("dwEndAddressFOA:%p",dwEndAddressFOA);
    DWORD dwIndexAddressFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pTls->AddressOfIndex - m_ImageBase,NULL));
    qDebug("dwIndexAddressFOA:%p",dwIndexAddressFOA);
    DWORD dwCallBackAddressFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pTls->AddressOfCallBacks - m_ImageBase,NULL));
    qDebug("dwCallBackAddressFOA:%p",dwCallBackAddressFOA);

    ui->TLS_TABLE->setItem(0,2,new QTableWidgetItem(tr("%1").arg(dwStartAddressFOA,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(1,2,new QTableWidgetItem(tr("%1").arg(dwEndAddressFOA,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(2,2,new QTableWidgetItem(tr("%1").arg(dwIndexAddressFOA,8,16,QLatin1Char('0')).toUpper()));
    ui->TLS_TABLE->setItem(3,2,new QTableWidgetItem(tr("%1").arg(dwCallBackAddressFOA,8,16,QLatin1Char('0')).toUpper()));

    ui->TLS_TABLE->update();

    QByteArray TlsDataBuffer(m_bFileBuffer.data() + dwStartAddressFOA,dwEndAddressFOA - dwStartAddressFOA);
    ui->TLS_TEXT_EDIT->setText(TlsDataBuffer.toHex());

    return true;
}

void MainWindow::on_RES_TREE_itemClicked(QTreeWidgetItem *item, int column)
{
    if(item->data(column,Qt::UserRole).isValid())
    {
        DWORD OffsetToDataFOA;
        PIMAGE_RESOURCE_DATA_ENTRY  pResDataEn;
        unsigned int ResDataOffset =  item->data(column,Qt::UserRole).toUInt();
        qDebug("ResDataOffset:%p",ResDataOffset);
        PIMAGE_RESOURCE_DIRECTORY  pResDir = (PIMAGE_RESOURCE_DIRECTORY )(m_bFileBuffer.data() + dwResTableFOA + ResDataOffset);
        int nLoopCount = pResDir->NumberOfIdEntries + pResDir->NumberOfNamedEntries;
        pResDir += 1;
        qDebug("nLoopCount:%p",nLoopCount);
        for(int i = 0; i < nLoopCount;i++)
        {
            PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDirEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY )((char*)pResDir +  i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
            //qDebug("pResDataEntry->Size:%p",pResDirEntry->OffsetToData);
            pResDataEn = (PIMAGE_RESOURCE_DATA_ENTRY )(m_bFileBuffer.data() + dwResTableFOA + pResDirEntry->OffsetToData);
            //qDebug("pResDataEntry->Size:%p",pResDataEn->OffsetToData);
            //qDebug("pResDataEntry->Size:%p",pResDataEn->Size);
            OffsetToDataFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,pResDataEn->OffsetToData,NULL));
            ui->FOAEdit->setText(tr("%1").arg(OffsetToDataFOA,8,16,QLatin1Char('0')).toUpper());
            ui->OffsetToDataEdit->setText(tr("%1").arg(pResDataEn->OffsetToData,8,16,QLatin1Char('0')).toUpper());
            ui->SizeEdit->setText(tr("%1").arg(pResDataEn->Size,8,16,QLatin1Char('0')).toUpper());
        }
        QByteArray ResData(m_bFileBuffer.data() + OffsetToDataFOA,pResDataEn->Size);
        ui->RES_DATA_EDIT->setText(ResData.toHex());
    }

}

bool MainWindow::ResSecondLayer(DWORD OffsetToDirectory,DWORD dwResTableFOA,int nItemIndex)
{

    PIMAGE_RESOURCE_DIRECTORY  pResSecond = (PIMAGE_RESOURCE_DIRECTORY )(m_bFileBuffer.data() + dwResTableFOA + OffsetToDirectory);
    int nLoopCount = pResSecond->NumberOfIdEntries + pResSecond->NumberOfNamedEntries;
    pResSecond += 1;
    for(int i = 0; i < nLoopCount;i++)
    {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDIREntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY )((char*)pResSecond +  i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        //qDebug("pResDIREntry->Id:%p",pResDIREntry->Id);
        QTreeWidgetItem* pChildItem = new QTreeWidgetItem(QStringList(QString::number(pResDIREntry->Id)));
        pChildItem->setData(0,Qt::UserRole,QVariant((unsigned int)(pResDIREntry->OffsetToDirectory)));
        ui->RES_TREE->topLevelItem(nItemIndex)->addChild(pChildItem);
        //ui->RES_TREE->currentItem()->addChild();
    }

    return true;
}

bool MainWindow::AnalyseResTable()
{
    dwResTableFOA = (DWORD)(ImageRvaToVa(tagPEHeader, (PVOID)0,m_ResourceRVA,NULL));
    PIMAGE_RESOURCE_DIRECTORY  pRes = (PIMAGE_RESOURCE_DIRECTORY )(m_bFileBuffer.data() + dwResTableFOA);
    qDebug("ResEntry:%p",pRes);
    qDebug("dwResTableFOA:%p",dwResTableFOA);
    qDebug("NumberOfIdEntries:%d",pRes->NumberOfIdEntries);
    qDebug("NumberOfNamedEntries:%d",pRes->NumberOfNamedEntries);
    int nLoopCount = pRes->NumberOfIdEntries + pRes->NumberOfNamedEntries;
    pRes += 1;
    qDebug("ResEntry:%p",pRes);

    for(int i = 0; i < nLoopCount;i++)
    {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pResDIREntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY )((char*)pRes +  i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
        if(pResDIREntry->NameIsString == 0)
        {
            //qDebug("pResDIREntry->Id:%p",pResDIREntry->Id);
            switch (pResDIREntry->Id)
            {
            case RES_TYPE_CURSOR:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("CURSOR"))));
            }
                break;
            case RES_TYPE_BITMAP:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("BITMAP"))));
            }
                break;
            case RES_TYPE_ICON:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("ICON"))));
            }
                break;
            case RES_TYPE_MENU:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("MENU"))));
            }
                break;
            case RES_TYPE_DIALOG:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("DIALOG"))));
            }
                break;
            case RES_TYPE_STRING:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("STRING"))));
            }
                break;
            case RES_TYPE_FONTDIR:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("FONTDIR"))));
            }
                break;
            case RES_TYPE_FONT:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("FONT"))));
            }
                break;
            case RES_TYPE_ACCELERATOR:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("ACCELERATOR"))));
            }
                break;
            case RES_TYPE_RCDATA:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("RCDATA"))));
            }
                break;
            case RES_TYPE_MESSAGETABLE:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("MESSAGETABLE"))));
            }
                break;
            case RES_TYPE_GROUP_CURSOR:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("GROUP_CURSOR"))));
            }
                break;
            case RES_TYPE_GROUP_ICON:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("GROUP_ICON"))));
            }
                break;
            case RES_TYPE_VERSION:
            {
                ui->RES_TREE->addTopLevelItem(new QTreeWidgetItem(QStringList(QString("VERSION"))));
            }
                break;

            }
            if(pResDIREntry->DataIsDirectory)
            {

                //qDebug("pResDIREntry->OffsetToDirectory:%p",pResDIREntry->OffsetToDirectory);
                ResSecondLayer(pResDIREntry->OffsetToDirectory,dwResTableFOA,i);
            }
        }
        else if(pResDIREntry->NameIsString == 1)
        {
            QMessageBox::warning(NULL, "information", QStringLiteral("名称项未处理."), QMessageBox::Yes);
            break;
        }

    }


    return true;
}


//清除信息
void MainWindow::ClearInfo()
{
    ui->CREATE_TIME->clear();
    ui->DOS_HEADER_TABLE->clear();
    ui->FILE_MD5->clear();
    ui->FILE_SIZE->clear();
    ui->PE_STYPE->clear();
    ui->File_HEADER_TABLE->clear();
    ui->OPTIONAL_HEADER_TABLE->clear();
    ui->DATA_DIRECTORY_TABLE->clear();
    ui->SECTIONS_HEADER_TABLE->clear();
    ui->FILE_PATH->clear();
    ui->DLL_TABLE->setRowCount(0);
    ui->DLL_TABLE->clear();
    ui->FUNC_TABLE->setRowCount(0);
    ui->FUNC_TABLE->clear();
    m_IsFirstOpen = false;
    m_IsFileSave = false;
    m_IsFileChange = false;
    m_IsPEFile = false;
    m_CalcDialog.ClearData();
    m_bFileBuffer.clear();
    ui->RELOCDIR_TABLE->clear();
    ui->RELOC_TABLE->clear();
    m_SectionList.clear();
    m_mRelocTable.clear();
    ui->TLS_TABLE->clear();
    ui->TLS_TEXT_EDIT->clear();
    ui->RES_TREE->clear();
    ui->RES_DATA_EDIT->clear();
    ui->SizeEdit->clear();
    ui->OffsetToDataEdit->clear();
    ui->FOAEdit->clear();

    InitHeader();
    setWindowTitle(m_WindowTitel);
}

//关闭文件的处理
void MainWindow::ExitProcess()
{
    //如果有文件打开
    if(m_file.isOpen())
    {
        //如果文件内容被修改
        if(m_IsFileChange)
        {
            //如果文件修改后未保存
            if(!m_IsFileSave)
            {
                m_MessageDialog.move(this->x() + 50,this->y() + 50);
                m_MessageDialog.setWindowTitle(QStringLiteral("警告!"));
                m_MessageDialog.SetLabelText(QStringLiteral("当前文件被修改但是未保存.是否要保存后关闭?"));
                if(m_MessageDialog.exec() == QDialog::Accepted)
                {
                    //写文件并且关文件
                    m_file.seek(0);
                    m_file.write(m_bFileBuffer);
                    m_file.close();
                }
                else
                {
                    //直接关闭
                    m_file.close();
                }
            }
            else
            {
                //如果文件修改后被保存.直接关闭文件
                m_file.close();
            }
        }
        else
        {
            //如果文件内容没有被修改.直接关闭
            m_file.close();
        }
    }
    m_CalcDialog.close();
}


