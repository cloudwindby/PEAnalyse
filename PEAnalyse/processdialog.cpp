#include "processdialog.h"
#include "ui_processdialog.h"
#include <QDebug>
#include <QMessageBox>
#include <QFileDialog>

ProcessDialog::ProcessDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ProcessDialog)
{
    ui->setupUi(this);
    setWindowTitle("Process");
    setMinimumSize(600,400);
    resize(width(),height());
    setWindowFlags(Qt::WindowCloseButtonHint);

    //初始化表头
    InitTableHeader();

    //设置行数
    ui->processtable->setRowCount(GetProcessCount());

    //获取进程信息
    GetProcessInfo();

    //右键菜单
    m_menu = QSharedPointer<QMenu>(new QMenu());
    //结束进程
    QAction* pTerminate = m_menu->addAction(QStringLiteral("terminate"));
    //刷新
    QAction* pRefresh = m_menu->addAction(QStringLiteral("refresh"));
    //转储为exe
    QAction* pDump = m_menu->addAction(QStringLiteral("dump"));
    connect(pTerminate,SIGNAL(triggered()),this,SLOT(slot_terminate()));
    connect(pRefresh,SIGNAL(triggered()),this,SLOT(slot_refresh()));
    connect(pDump,SIGNAL(triggered()),this,SLOT(slot_dump()));
}

ProcessDialog::~ProcessDialog()
{
    delete ui;
}

//获取进程信息
bool ProcessDialog::GetProcessInfo()
{
    HANDLE hProcessSnap;
    HANDLE hProcess;
    PROCESSENTRY32 pe32;
    DWORD dwPriorityClass;
    wchar_t FileName[MAX_PATH] = { 0 };


    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return(FALSE);
    }

    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }
    // Now walk the snapshot of processes, and
    // display information about each process in turn
    int i = 0;
    do
    {
        // Retrieve the priority class.
        dwPriorityClass = 0;
        BOOL isWow64 = FALSE;
        hProcess = OpenProcess(/*PROCESS_QUERY_INFORMATION | PROCESS_VM_READ*/PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
        if (hProcess == NULL)
        {
            ui->processtable->setItem(i, 3, new QTableWidgetItem(QStringLiteral("拒绝访问!")));
        }
        else
        {
            DWORD size = MAX_PATH;
            memset(FileName, 0, sizeof(FileName));
            //GetProcessImageFileName(hProcess, FileName, MAX_PATH);
            //获取进程镜像全路径
            QueryFullProcessImageName(hProcess,0,FileName, &size);
            IsWow64Process(hProcess,&isWow64);
            ui->processtable->setItem(i, 3, new QTableWidgetItem(QStringLiteral("允许访问!")));
            dwPriorityClass = GetPriorityClass(hProcess);
            if (!dwPriorityClass)
                CloseHandle(hProcess);
        }

        //字符串转换
        QString qsExeFileName = QString::fromWCharArray(pe32.szExeFile);
        QString qsExePath = QString::fromWCharArray(FileName);
        QString qsProcessID = QString::number(pe32.th32ProcessID,10);

        ui->processtable->setItem(i, 0, new QTableWidgetItem(qsExeFileName));
        ui->processtable->setItem(i, 1, new QTableWidgetItem(qsProcessID));

        if(!isWow64)
        {
            ui->processtable->setItem(i, 2, new QTableWidgetItem(QStringLiteral("64位")));
        }
        else
        {
            ui->processtable->setItem(i, 2, new QTableWidgetItem(QStringLiteral("32位")));
        }
        ui->processtable->setItem(i, 4, new QTableWidgetItem(qsExePath));
        i++;
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return(TRUE);
}

//获取进程个数
DWORD ProcessDialog::GetProcessCount()
{
    //枚举所有进程
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 0;
    }
    cProcesses = cbNeeded / sizeof(DWORD);
    return cProcesses;
}

//初始化表头
bool ProcessDialog::InitTableHeader()
{
    QStringList labels;
    labels << QStringLiteral("进程名称")
           << QStringLiteral("进程ID")
           << QStringLiteral("平台")
           << QStringLiteral("运行权限")
           << QStringLiteral("可执行文件路径");

    ui->processtable->setHorizontalHeaderLabels(labels);//设置表头
    ui->processtable->setSortingEnabled(true);//设置排序
    ui->processtable->setEditTriggers(QAbstractItemView::NoEditTriggers);//禁止编辑
    ui->processtable->setSelectionBehavior(QAbstractItemView::SelectRows);  //整行选中的方式
    ui->processtable->setColumnWidth(0, 160);//设置第一列的宽度
    ui->processtable->setColumnWidth(1, 60);//设置第一列的宽度
    ui->processtable->setColumnWidth(2, 50);//设置第一列的宽度
    ui->processtable->setColumnWidth(3, 80);//设置第一列的宽度
    ui->processtable->setColumnWidth(4, 300);//设置第一列的宽度
    return true;
}

//获取PID
DWORD ProcessDialog::GetPID()
{
    int nIndex = ui->processtable->currentRow();
    qDebug() << nIndex;
    QTableWidgetItem *pItem = ui->processtable->item(nIndex,1);
    QString qsPID = pItem->text();
    m_ProcessName = ui->processtable->item(nIndex,0)->text();
    qDebug() << m_ProcessName;
    return qsPID.toUInt();
}

bool ProcessDialog::AnalyseData(HANDLE hProcess,char* pProcessMemoryFirstPage)
{
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pProcessMemoryFirstPage;
    qDebug("%p",pDOSHeader->e_magic);
    DWORD dwPEOffset = (DWORD)pDOSHeader->e_lfanew;
    qDebug() << "PEoffset" << dwPEOffset;

    PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)(pProcessMemoryFirstPage + dwPEOffset);
    DWORD dwSectionsCount =  pNTHeader->FileHeader.NumberOfSections;
    qDebug() << "dwSectionsCount" << dwSectionsCount;

    DWORD dwSectionOffset = pNTHeader->FileHeader.SizeOfOptionalHeader + sizeof(pNTHeader->FileHeader) + sizeof(pNTHeader->Signature) + dwPEOffset;
    qDebug() << "dwSectionOffset" << dwSectionOffset;
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pProcessMemoryFirstPage + dwSectionOffset);

    for(int n = 0;n < dwSectionsCount; n++)
    {
        m_SectionsVector.insert(n,pSectionHeader[n]);
    }

    QString SaveFileName = QFileDialog::getSaveFileName(this, tr("Save File"),"Save.exe","*.*");
    if(!SaveFileName.isEmpty())
    {
        QFile SaveFile(SaveFileName);
        if (!SaveFile.open(QIODevice::WriteOnly))
        {
            return false;
        }
        DWORD dwByteOfRead = 0;
        SaveFile.write(pProcessMemoryFirstPage,pNTHeader->OptionalHeader.SizeOfHeaders);

        qDebug("m_hImageBase:%p",m_hImageBase);
        for(auto Section : m_SectionsVector)
        {
            SaveFile.seek(Section.PointerToRawData);
            //从Memory Addr开始读File Size,写入到File Offset的地方
            if(Section.Misc.VirtualSize != 0)
            {
                char* szBuffer = new char[Section.Misc.VirtualSize];
                DWORD dwOffset = (DWORD)m_hImageBase + Section.VirtualAddress;
                ReadProcessMemory(hProcess,LPVOID(dwOffset),szBuffer,Section.Misc.VirtualSize,&dwByteOfRead);

                qDebug("dwOffset:%p",dwOffset);
                qDebug("dwByteOfRead:%p",dwByteOfRead);
                qDebug("szBuffer:%s",szBuffer);

                SaveFile.write(szBuffer,Section.SizeOfRawData);
                qDebug("Memory Size: %p",Section.Misc.VirtualSize);
                qDebug("File:%p",Section.PointerToRawData);
                qDebug("File Size:%p",Section.SizeOfRawData);
                qDebug("Memory Addr:%p",Section.VirtualAddress);
                if(szBuffer != nullptr)
                {
                    delete[] szBuffer;
                }
            }
        }

        SaveFile.close();
        QMessageBox msgBox;
        msgBox.setText("Dump Success!.");
        msgBox.exec();
    }
    return true;
}

//右键
void ProcessDialog::on_processtable_customContextMenuRequested(const QPoint &pos)
{
    if(ui->processtable->rowCount() < 1)
    {
        return;
    }
    else if(ui->processtable->itemAt(pos) != 0)
    {
        m_menu->exec(QCursor::pos());
    }
}

//结束进程
void ProcessDialog::slot_terminate()
{
    //    int nIndex = ui->processtable->currentRow();
    //    QTableWidgetItem *pItem = ui->processtable->item(nIndex,1);
    //    QString qsPID = pItem->text();
    //    DWORD dwPID = qsPID.toUInt();
    HANDLE hProcess =  OpenProcess(PROCESS_TERMINATE,FALSE,GetPID());
    if(hProcess == 0)
    {
        QMessageBox::warning(NULL, "warning", "OpenProcess Error", QMessageBox::Ok);
        return;
    }

    if(TerminateProcess(hProcess,0))
    {
        Sleep(1000);
        slot_refresh();
        return;
    }
    else
    {
        QMessageBox::warning(NULL, "warning", "TerminateProcess Error", QMessageBox::Ok);
        return;
    }

}

//刷新
void ProcessDialog::slot_refresh()
{

    ui->processtable->clear();

    //初始化表头
    InitTableHeader();

    //设置行数
    ui->processtable->setRowCount(GetProcessCount());

    //获取进程信息
    GetProcessInfo();
}

//转储
void ProcessDialog::slot_dump()
{
    DWORD dwPID = GetPID();
    DWORD dwByteOfRead = 0;
    char szBuffer[1024] = { 0 };
    HANDLE hProcess =  OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwPID);
    if(hProcess == 0)
    {
        QMessageBox::warning(NULL, "warning", "OpenProcess Error", QMessageBox::Ok);
        return;
    }
    DWORD dwcbNeeded = 0;
    bool bRet = EnumProcessModulesEx(hProcess, &m_hImageBase, sizeof(m_hImageBase),&dwcbNeeded,LIST_MODULES_ALL);
    qDebug() << m_hImageBase;
    if(bRet)
    {
        bRet = ReadProcessMemory(hProcess,m_hImageBase,szBuffer,1024,&dwByteOfRead);
        qDebug() << GetLastError();
        if(bRet)
        {
            qDebug() << GetLastError();
            qDebug() << szBuffer;
            AnalyseData(hProcess,szBuffer);
        }
    }

    if(hProcess != NULL)
    {
        CloseHandle(hProcess);
    }
}
