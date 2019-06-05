#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDragEnterEvent>
#include <QMimeData>
#include <QFile>
#include <QUrl>
#include <QDebug>
#include <QCryptographicHash>
#include <QFileInfo>
#include <QDateTime>
#include <QList>
#include <QFileDialog>
#include <QSharedPointer>
#include <QTableWidgetItem>
#include <QMessageBox>
#include <QVariant>
#include <QTreeWidgetItem>
#include <QImage>
#include "messagedialog.h"
#include "calcdialog.h"
#include "processdialog.h"
#include "addsectiondialog.h"
#include "addimportfuncdialog.h"

#define RES_TYPE_CURSOR           1
#define RES_TYPE_BITMAP           2
#define RES_TYPE_ICON             3
#define RES_TYPE_MENU             4
#define RES_TYPE_DIALOG           5
#define RES_TYPE_STRING           6
#define RES_TYPE_FONTDIR          7
#define RES_TYPE_FONT             8
#define RES_TYPE_ACCELERATOR      9
#define RES_TYPE_RCDATA           10
#define RES_TYPE_MESSAGETABLE     11

#define DIFFERENCE     11
#define RES_TYPE_GROUP_CURSOR (RES_TYPE_CURSOR + DIFFERENCE)
#define RES_TYPE_GROUP_ICON   (RES_TYPE_ICON + DIFFERENCE)
#define RES_TYPE_VERSION      16
#define RES_TYPE_DLGINCLUDE   17

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

protected:
    void dragEnterEvent(QDragEnterEvent *e);
    void dropEvent(QDropEvent *e);
    void closeEvent (QCloseEvent * e );


private slots:
    void on_DOS_HEADER_TABLE_cellChanged(int row, int column);

    void on_actionSave_File_triggered();

    void on_actionClose_File_triggered();

    void on_actionOpen_File_triggered();

    void on_actionCalc_triggered();

    void on_actionExit_triggered();

    void on_actionReload_triggered();

    void on_actionProcess_triggered();

    void on_SECTIONS_HEADER_TABLE_customContextMenuRequested(const QPoint &pos);

    void slot_AddSection();
    void slot_ExtendLastSection();

    void slot_AddImportFunc();

    void on_DLL_TABLE_itemClicked(QTableWidgetItem *item);

    void on_DLL_TABLE_customContextMenuRequested(const QPoint &pos);

    void on_RELOCDIR_TABLE_cellClicked(int row, int column);

    void on_RES_TREE_itemClicked(QTreeWidgetItem *item, int column);

private:
    //读文件
    bool ReadFile(QString);
    //解析DOS_HEADER
    bool AnalyseDOSHeader(QByteArray&);
    //解析NT_HEADER和OP_HEADER
    bool AnalysePEHeader(DWORD PE_Offset);
    //解析区段
    bool AnalyseSessionHeader(DWORD SectionsOffset,DWORD  SectionsNumber);
    //解析导入表
    bool AnalyseImportTbale();
    //清除信息
    void ClearInfo();
    //初始化表头
    void InitHeader();
    //初始化表头
    void InitFuncTable();
    //退出
    void ExitProcess();

    bool ImportInjack();

    //重定位表
    void InitRelocHeader();
    DWORD m_RelocRVA;
    DWORD m_RelocSize;
    bool InsertRelocDirTable(PIMAGE_BASE_RELOCATION pRelocDir);
    unsigned int CreateRelocDirTable(DWORD dwRelocDirAddr, DWORD dwTypeSize);
    QMap<int, QWidget*> m_mRelocTable;

    //TLS表
    DWORD m_TlsRVA;
    DWORD m_TlsSize;
    bool AnalyseTlsTable();
    void InitTlsHeader();

    //资源表
    DWORD m_ResourceRVA;
    DWORD m_ResourceSize;
    bool AnalyseResTable();
    //处理第二层数据
    bool ResSecondLayer(DWORD,DWORD,int);
    DWORD dwResTableFOA;


    Ui::MainWindow *ui;

    //窗口标题
    QString m_WindowTitel;
    //文件
    QFile m_file;
    //文件缓存区
    QByteArray m_bFileBuffer;
    //最后一次打开的文件名.方便重新加载
    QString m_LastOpenFileName;
    //节名
    QByteArray m_bSectionName;
    //警告信息对话框
    MessageDialog m_MessageDialog;
    //计算RVA->FA对话框
    CalcDialog m_CalcDialog;
    //第一次打开
    bool m_IsFirstOpen;
    //文件是否保存
    bool m_IsFileSave;
    //文件是否被修改
    bool m_IsFileChange;
    //是否PE文件
    bool m_IsPEFile = false;


    QList<IMAGE_SECTION_HEADER> m_SectionList;
    QSharedPointer<QMenu> m_menu;
    QSharedPointer<QMenu> m_AddImportFunc;

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
    //头大小
    DWORD m_SectionHeaders = 0;
    //镜像大小
    DWORD m_SizeOfImage = 0;
    //PE偏移
    DWORD m_PEOffset = 0;

    DWORD m_ImportTableRva = 0;
    DWORD m_ImportTableSize = 0;

    //导入表的FOA
    DWORD ImportFOA;
    //导入表DLL的个数
    DWORD dwImportCount;
    PIMAGE_IMPORT_DESCRIPTOR pImportTable;
    PIMAGE_SECTION_HEADER pTagSectionHeader;

    PIMAGE_NT_HEADERS32 tagPEHeader;
    QSharedPointer<ProcessDialog> m_ProcessDialog;
    QSharedPointer<AddSectionDialog> m_AddSectionDialog;
    QSharedPointer<AddImportFuncDialog> m_AddImportFuncDialog;

    QString m_AddFuncName;
    QString m_AddFuncFileName;
    QString formatUInt(unsigned int n);
    QString formatUShort(unsigned short n);
};

#endif // MAINWINDOW_H
