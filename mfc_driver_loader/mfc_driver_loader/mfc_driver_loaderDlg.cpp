
// mfc_driver_loaderDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "mfc_driver_loader.h"
#include "mfc_driver_loaderDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define DRIVER_PATH L"C:\\WinDriverCommunicate.sys"
#define DRIVER_NAME L"ThisIsDriver"

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Cmfc_driver_loaderDlg 对话框



Cmfc_driver_loaderDlg::Cmfc_driver_loaderDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cmfc_driver_loaderDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void Cmfc_driver_loaderDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(Cmfc_driver_loaderDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &Cmfc_driver_loaderDlg::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &Cmfc_driver_loaderDlg::OnBnClickedButton2)
	ON_BN_CLICKED(IDC_BUTTON3, &Cmfc_driver_loaderDlg::OnBnClickedButton3)
	ON_BN_CLICKED(IDC_BUTTON4, &Cmfc_driver_loaderDlg::OnBnClickedButton4)
END_MESSAGE_MAP()


// Cmfc_driver_loaderDlg 消息处理程序

BOOL Cmfc_driver_loaderDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void Cmfc_driver_loaderDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Cmfc_driver_loaderDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cmfc_driver_loaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void Cmfc_driver_loaderDlg::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = loadDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"当前监控状态：\n驱动已加载");
	}
}

// 停止驱动
void Cmfc_driver_loaderDlg::OnBnClickedButton4()
{
	// TODO:  在此添加控件通知处理程序代码
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = unloadDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"当前监控状态：\n驱动已停止");
	}
}

// 停止监控
void Cmfc_driver_loaderDlg::OnBnClickedButton2()
{
	// TODO:  在此添加控件通知处理程序代码
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = stopDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"当前监控状态：\n已关闭");
	}
}

void Cmfc_driver_loaderDlg::OnBnClickedButton3()
{
	// TODO:  在此添加控件通知处理程序代码
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = runDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"当前监控状态：\n已开启");
	}
}


LONG Cmfc_driver_loaderDlg::loadDriver(CString driverPath, CString driverName)
{
	// TODO:  加载驱动模块

	if (driverPath.IsEmpty() || driverName.IsEmpty())
	{
		MessageBox(L"检查驱动路径或者名称是否为空", L"提示：");
		return FALSE;
	}

	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager打开失败，检查权限", L"提示：");
		return FALSE;
	}
	
	SC_HANDLE serviceHandle = CreateService(this->scMageger, driverName, driverName, SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, NULL, NULL, NULL, NULL, NULL);

	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_EXISTS)
		{
			MessageBox(L"服务已经存在", L"提示：");
		}
		else
		{
			CString str;
			str.Format(L"CreateService 错误号为:%d", error);
			MessageBox(str, L"提示：");
			OutputDebugString(str);
		}
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}
	
	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(this->scMageger);
	this->scMageger = NULL;
	
	return TRUE;
}


LONG Cmfc_driver_loaderDlg::unloadDriver(CString driverPath, CString driverName)
{
	if (driverPath.IsEmpty() || driverName.IsEmpty())
	{
		MessageBox(L"检查驱动路径或者名称是否为空", L"提示：");
		return FALSE;
	}

	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager打开失败，检查权限", L"提示：");
		return FALSE;
	}

	SC_HANDLE serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"服务已经不存在", L"提示：");

		}
		else
		{
			CString str("OpenService 错误号为：" + error);
			MessageBox(str, L"提示：");
		}
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	if (!DeleteService(serviceHandle))
	{
		DWORD error = GetLastError();
		CString str;
		str.Format(L"DeleteService 错误号为：%d", error);
		MessageBox(str, L"提示");
		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(this->scMageger);
	this->scMageger = NULL;
	return TRUE;
}

LONG Cmfc_driver_loaderDlg::runDriver(CString driverPath, CString driverName)
{
	SC_HANDLE serviceHandle;

	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager打开失败，检查权限", L"提示：");
		return FALSE;
	}

	serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"服务已经不存在", L"提示：");
		}
		else
		{
			CString str("OpenService 错误号为:" + error);
			MessageBox(str, L"提示：");
		}
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	int result = StartService(serviceHandle, 0, NULL);
	if (result == 0)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_ALREADY_RUNNING)
		{
			MessageBox(L"服务已经运行", L"提示：");
			CloseServiceHandle(serviceHandle);
			CloseServiceHandle(this->scMageger);
			return FALSE;
		}
	}

	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(this->scMageger);
	this->scMageger = NULL;
	
	// start Monitor
	MessageBox(L"start Mointor", L"提示：");
	startMonitor();
	return TRUE;
}

LONG Cmfc_driver_loaderDlg::stopDriver(CString driverPath, CString driverName)
{
	SC_HANDLE serviceHandle;
	SERVICE_STATUS error = { 0 };
	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager打开失败，检查权限", L"提示：");
		return FALSE;
	}

	serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"服务已经不存在", L"提示：");
		}
		else
		{
			CString str("OpenService 错误号为:" + error);
			MessageBox(str, L"提示：");
		}
		
		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	MessageBox(L"stop Mointor", L"提示：");
	stopMonitor();

	if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &error))
	{
		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(this->scMageger);
		return TRUE;
	}

	return FALSE;
}
//////////////////////////////////////////

DWORD x86GetUser32()
{
	DWORD dwPEB;
	DWORD dwLDR;
	DWORD dwInitList;
	DWORD dwDllBase;//当前地址
	PIMAGE_DOS_HEADER pImageDosHeader;//指向DOS头的指针
	PIMAGE_NT_HEADERS pImageNtHeaders;//指向NT头的指针
	DWORD dwVirtualAddress;//导出表偏移地址s
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//指向导出表的指针
	PCHAR lpName;								  //指向dll名字的指针
	CHAR szKernel32[] = "USER32.dll";
	__asm
	{
		mov eax, FS:[0x30];//fs:[0x30]获取PEB所在地址
		mov dwPEB, eax;// eax 复制给dwPEB
	}
	dwLDR = *(PDWORD)(dwPEB + 0xc);//获取PEB_LDR_DATA 结构指针
	dwInitList = *(PDWORD)(dwLDR + 0x1c);//获取InInitializationOrderModuleList  链表头指针
	//第一个LDR_MODULE节点InInitializationOrderModuleList成员的指针
	for (;
		dwDllBase = *(PDWORD)(dwInitList + 8);//结构偏移0x8处存放模块基址
		dwInitList = *(PDWORD)dwInitList//结构偏移0处存放下一模块结构的指针
		)
	{
		pImageDosHeader = (PIMAGE_DOS_HEADER)dwDllBase;
		pImageNtHeaders = (PIMAGE_NT_HEADERS)(dwDllBase + pImageDosHeader->e_lfanew);
		dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;//导出表偏移
		pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwDllBase + dwVirtualAddress);//导出表地址
		lpName = (PCHAR)(dwDllBase + pImageExportDirectory->Name);//dll名字
		if (strlen(lpName) == 0xa && !strcmp(lpName, szKernel32))//判断是否为“KERNEL32.dll”
		{
			return dwDllBase;
		}
	}
	return 0;
}

DWORD x86GetApi(DWORD _hModule, PCHAR _lpApi)
{
	DWORD i;
	DWORD dwLen;
	PIMAGE_DOS_HEADER pImageDosHeader;//指向DOS头的指针
	PIMAGE_NT_HEADERS pImageNtHeaders;//指向NT头的指针
	DWORD dwVirtualAddress;//导出表偏移地址
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//指向导出表的指针
	CHAR** lpAddressOfNames;
	PWORD lpAddressOfNameOrdinals;//计算API字符串的长度
	for (i = 0; _lpApi[i]; ++i);
	dwLen = i;
	pImageDosHeader = (PIMAGE_DOS_HEADER)_hModule;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)(_hModule + pImageDosHeader->e_lfanew);
	dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;     //导出表偏移
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(_hModule + dwVirtualAddress);         //导出表地址
	lpAddressOfNames = (PCHAR*)(_hModule + pImageExportDirectory->AddressOfNames);         //按名字导出函数列表

	//遍历导出表的函数名来进行判断，然后返回指定函数名的函数地址
	for (i = 0; _hModule + lpAddressOfNames[i]; i++)
	{
		if (strlen(_hModule + lpAddressOfNames[i]) == dwLen && !strcmp(_hModule + lpAddressOfNames[i], _lpApi))//判断是否为_lpApi
		{
			lpAddressOfNameOrdinals = (PWORD)(_hModule + pImageExportDirectory->AddressOfNameOrdinals);//按名字导出函数索引列表
			return _hModule + ((PDWORD)(_hModule + pImageExportDirectory->AddressOfFunctions))[lpAddressOfNameOrdinals[i]];//根据函数索引找到函数地址
		}
	}
	return 0;
}

//////////////////////////////////////////
#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe

#define FILE_DEVICE_UNKNOWN             0x00000022

#define CTL_CODE( DeviceType, Function, Method, Access ) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))

#define SYMBOLICLINK_NAME L"\\\\.\\test"
#define OPER_OPEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IN_BUFFER_MAXLENGTH 4
#define OUT_BUFFER_MAXLENGTH 4

LONG Cmfc_driver_loaderDlg::startMonitor()
{
	// 获取设备句柄
	HANDLE hDevice = CreateFile(SYMBOLICLINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwError = GetLastError();
	if (hDevice == NULL)
	{
		printf("CreateFile Failed\n");
	}

	DWORD dwDllBase = x86GetUser32();
	DWORD dwAddr = x86GetApi(dwDllBase, "MessageBoxA");

	// 测试通信
	DWORD dwInBuffer = dwAddr;
	DWORD dwOutBuffer = 0xFFFFFFFF;
	DWORD dwOutNumber;
	DeviceIoControl(hDevice, OPER_OPEN, &dwInBuffer, IN_BUFFER_MAXLENGTH, &dwOutBuffer, OUT_BUFFER_MAXLENGTH, &dwOutNumber, NULL);
	printf("dwOutBuffer: %08X dwOutNumber: %08X\n", dwOutBuffer, dwOutNumber);
	// 关闭设备
	CloseHandle(hDevice);
	return TRUE;
}


LONG Cmfc_driver_loaderDlg::stopMonitor()
{
	// 获取设备句柄
	HANDLE hDevice = CreateFile(SYMBOLICLINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwError = GetLastError();
	if (hDevice == NULL)
	{
		MessageBoxW(0, 0, 0);
		printf("CreateFile Failed\n");
	}
	
	DWORD dwDllBase = x86GetUser32();
	DWORD dwAddr = x86GetApi(dwDllBase, "MessageBoxA");

	// 测试通信
	DWORD dwInBuffer = dwAddr;
	DWORD dwOutBuffer = 0xFFFFFFFF;
	DWORD dwOutNumber;
	DeviceIoControl(hDevice, OPER_CLOSE, &dwInBuffer, IN_BUFFER_MAXLENGTH, &dwOutBuffer, OUT_BUFFER_MAXLENGTH, &dwOutNumber, NULL);
	printf("dwOutBuffer: %08X dwOutNumber: %08X\n", dwOutBuffer, dwOutNumber);
	// 关闭设备
	CloseHandle(hDevice);
	return TRUE;
}