#ifndef COMMON_H
#define COMMON_H

#endif // COMMON_H
//#include <windows.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SECTION_HEADER          40
#define IMAGE_SIZEOF_SHORT_NAME              8

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386                   0x014c  // Intel 386.
#define IMAGE_FILE_MACHINE_ALPHA                0x0184  // Alpha_AXP
#define IMAGE_FILE_MACHINE_POWERPC            0x01F0  // IBM PowerPC Little-Endian
#define IMAGE_FILE_MACHINE_AMD64                0x8664  // AMD64 (K8)


typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
typedef unsigned long long ULONGLONG;

//typedef struct _IMAGE_SECTION_HEADER {
//    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
//    union {
//            DWORD   PhysicalAddress;
//            DWORD   VirtualSize;
//    } Misc;
//    DWORD   VirtualAddress;
//    DWORD   SizeOfRawData;
//    DWORD   PointerToRawData;
//    DWORD   PointerToRelocations;
//    DWORD   PointerToLinenumbers;
//    WORD     NumberOfRelocations;
//    WORD     NumberOfLinenumbers;
//    DWORD   Characteristics;
//} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;             // 00000000  4D 5A，Magic number
    WORD   e_cblp;          // 00000002  90 00，Bytes on last page of file
    WORD   e_cp;             // 00000004  03 00，Pages in file
    WORD   e_crlc;            // 00000006  00 00，Relocations
    WORD   e_cparhdr;           // 00000008  04 00，Size of header in paragraphs
    WORD   e_minalloc;        // 0000000A  00 00，Minimum extra paragraphs needed
    WORD   e_maxalloc;          // 0000000C  FF FF，Maximum extra paragraphs needed
    WORD   e_ss;                // 0000000E  00 00，Initial (relative) SS value
    WORD   e_sp;             // 00000010  B8 00，Initial SP value
    WORD   e_csum;          // 00000012  00 00，Checksum
    WORD   e_ip;                // 00000014  00 00，Initial IP value
    WORD   e_cs;                // 00000016  00 00，Initial (relative) CS value
    WORD   e_lfarlc;        // 00000018  40 00，File address of relocation table
    WORD   e_ovno;           // 0000001A  00 00，Overlay number
    WORD   e_res[4];            // 0000001C  00 00 00 00，Reserved unsigned shorts
        // 00000020  00 00 00 00
    WORD   e_oemid;             // 00000024  00 00，OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;           // 00000026  00 00，OEM information; e_oemid specific
    WORD   e_res2[10];          // 00000028  00 00 00 00，Reserved unsigned shorts
        // 0000002C  00 00 00 00
        // 00000030  00 00 00 00
        // 00000034  00 00 00 00
        // 00000038  00 00 00 00
    DWORD    e_lfanew;           // 0000003C  F8 00 00 00，File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;



typedef struct _IMAGE_FILE_HEADER {
    WORD   Machine;               //运行平台
    WORD   NumberOfSections;     //块(section)数目
      DWORD    TimeDateStamp;        //时间日期标记
      DWORD   PointerToSymbolTable;    //COFF符号指针，这是程序调试信息
     DWORD   NumberOfSymbols;         //符号数
      WORD   SizeOfOptionalHeader;    //可选部首长度，是IMAGE_OPTIONAL_HEADER的长度
     WORD   Characteristics;         //文件属性
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY,  *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32,  *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {

    WORD          Magic;
    BYTE           MajorLinkerVersion;
    BYTE           MinorLinkerVersion;
    DWORD        SizeOfCode;
    DWORD        SizeOfInitializedData;
    DWORD        SizeOfUninitializedData;
    DWORD        AddressOfEntryPoint;
    DWORD        BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD        SectionAlignment;
    DWORD        FileAlignment;
    WORD          MajorOperatingSystemVersion;
    WORD          MinorOperatingSystemVersion;
    WORD          MajorImageVersion;
    WORD          MinorImageVersion;
    WORD          MajorSubsystemVersion;
    WORD          MinorSubsystemVersion;
    DWORD        Win32VersionValue;
    DWORD        SizeOfImage;
    DWORD        SizeOfHeaders;
    DWORD        CheckSum;
    WORD          Subsystem;
    WORD          DllCharacteristics;
    ULONGLONG  SizeOfStackReserve;
    ULONGLONG  SizeOfStackCommit;
    ULONGLONG  SizeOfHeapReserve;
    ULONGLONG  SizeOfHeapCommit;
    DWORD        LoaderFlags;
    DWORD        NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;


typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

