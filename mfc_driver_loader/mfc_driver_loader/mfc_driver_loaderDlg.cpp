
// mfc_driver_loaderDlg.cpp : ʵ���ļ�
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

// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// Cmfc_driver_loaderDlg �Ի���



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


// Cmfc_driver_loaderDlg ��Ϣ�������

BOOL Cmfc_driver_loaderDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO:  �ڴ���Ӷ���ĳ�ʼ������

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void Cmfc_driver_loaderDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR Cmfc_driver_loaderDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void Cmfc_driver_loaderDlg::OnBnClickedButton1()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = loadDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"��ǰ���״̬��\n�����Ѽ���");
	}
}

// ֹͣ����
void Cmfc_driver_loaderDlg::OnBnClickedButton4()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = unloadDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"��ǰ���״̬��\n������ֹͣ");
	}
}

// ֹͣ���
void Cmfc_driver_loaderDlg::OnBnClickedButton2()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = stopDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"��ǰ���״̬��\n�ѹر�");
	}
}

void Cmfc_driver_loaderDlg::OnBnClickedButton3()
{
	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	CWnd* pMonitorText = GetDlgItem(IDC_STATIC_MONITOR);
	LONG pRes = runDriver(DRIVER_PATH, DRIVER_NAME);
	if (pRes)
	{
		pMonitorText->SetWindowText(L"��ǰ���״̬��\n�ѿ���");
	}
}


LONG Cmfc_driver_loaderDlg::loadDriver(CString driverPath, CString driverName)
{
	// TODO:  ��������ģ��

	if (driverPath.IsEmpty() || driverName.IsEmpty())
	{
		MessageBox(L"�������·�����������Ƿ�Ϊ��", L"��ʾ��");
		return FALSE;
	}

	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager��ʧ�ܣ����Ȩ��", L"��ʾ��");
		return FALSE;
	}
	
	SC_HANDLE serviceHandle = CreateService(this->scMageger, driverName, driverName, SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driverPath, NULL, NULL, NULL, NULL, NULL);

	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_EXISTS)
		{
			MessageBox(L"�����Ѿ�����", L"��ʾ��");
		}
		else
		{
			CString str;
			str.Format(L"CreateService �����Ϊ:%d", error);
			MessageBox(str, L"��ʾ��");
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
		MessageBox(L"�������·�����������Ƿ�Ϊ��", L"��ʾ��");
		return FALSE;
	}

	this->scMageger = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (this->scMageger == NULL)
	{
		MessageBox(L"OpenSCManager��ʧ�ܣ����Ȩ��", L"��ʾ��");
		return FALSE;
	}

	SC_HANDLE serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"�����Ѿ�������", L"��ʾ��");

		}
		else
		{
			CString str("OpenService �����Ϊ��" + error);
			MessageBox(str, L"��ʾ��");
		}
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	if (!DeleteService(serviceHandle))
	{
		DWORD error = GetLastError();
		CString str;
		str.Format(L"DeleteService �����Ϊ��%d", error);
		MessageBox(str, L"��ʾ");
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
		MessageBox(L"OpenSCManager��ʧ�ܣ����Ȩ��", L"��ʾ��");
		return FALSE;
	}

	serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"�����Ѿ�������", L"��ʾ��");
		}
		else
		{
			CString str("OpenService �����Ϊ:" + error);
			MessageBox(str, L"��ʾ��");
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
			MessageBox(L"�����Ѿ�����", L"��ʾ��");
			CloseServiceHandle(serviceHandle);
			CloseServiceHandle(this->scMageger);
			return FALSE;
		}
	}

	CloseServiceHandle(serviceHandle);
	CloseServiceHandle(this->scMageger);
	this->scMageger = NULL;
	
	// start Monitor
	MessageBox(L"start Mointor", L"��ʾ��");
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
		MessageBox(L"OpenSCManager��ʧ�ܣ����Ȩ��", L"��ʾ��");
		return FALSE;
	}

	serviceHandle = OpenService(this->scMageger, driverName, SERVICE_ALL_ACCESS);
	if (serviceHandle == NULL)
	{
		DWORD error = GetLastError();
		if (error == ERROR_SERVICE_DOES_NOT_EXIST)
		{
			MessageBox(L"�����Ѿ�������", L"��ʾ��");
		}
		else
		{
			CString str("OpenService �����Ϊ:" + error);
			MessageBox(str, L"��ʾ��");
		}
		
		CloseServiceHandle(serviceHandle);
		CloseServiceHandle(this->scMageger);
		return FALSE;
	}

	MessageBox(L"stop Mointor", L"��ʾ��");
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
	DWORD dwDllBase;//��ǰ��ַ
	PIMAGE_DOS_HEADER pImageDosHeader;//ָ��DOSͷ��ָ��
	PIMAGE_NT_HEADERS pImageNtHeaders;//ָ��NTͷ��ָ��
	DWORD dwVirtualAddress;//������ƫ�Ƶ�ַs
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//ָ�򵼳����ָ��
	PCHAR lpName;								  //ָ��dll���ֵ�ָ��
	CHAR szKernel32[] = "USER32.dll";
	__asm
	{
		mov eax, FS:[0x30];//fs:[0x30]��ȡPEB���ڵ�ַ
		mov dwPEB, eax;// eax ���Ƹ�dwPEB
	}
	dwLDR = *(PDWORD)(dwPEB + 0xc);//��ȡPEB_LDR_DATA �ṹָ��
	dwInitList = *(PDWORD)(dwLDR + 0x1c);//��ȡInInitializationOrderModuleList  ����ͷָ��
	//��һ��LDR_MODULE�ڵ�InInitializationOrderModuleList��Ա��ָ��
	for (;
		dwDllBase = *(PDWORD)(dwInitList + 8);//�ṹƫ��0x8�����ģ���ַ
		dwInitList = *(PDWORD)dwInitList//�ṹƫ��0�������һģ��ṹ��ָ��
		)
	{
		pImageDosHeader = (PIMAGE_DOS_HEADER)dwDllBase;
		pImageNtHeaders = (PIMAGE_NT_HEADERS)(dwDllBase + pImageDosHeader->e_lfanew);
		dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;//������ƫ��
		pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(dwDllBase + dwVirtualAddress);//�������ַ
		lpName = (PCHAR)(dwDllBase + pImageExportDirectory->Name);//dll����
		if (strlen(lpName) == 0xa && !strcmp(lpName, szKernel32))//�ж��Ƿ�Ϊ��KERNEL32.dll��
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
	PIMAGE_DOS_HEADER pImageDosHeader;//ָ��DOSͷ��ָ��
	PIMAGE_NT_HEADERS pImageNtHeaders;//ָ��NTͷ��ָ��
	DWORD dwVirtualAddress;//������ƫ�Ƶ�ַ
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory;//ָ�򵼳����ָ��
	CHAR** lpAddressOfNames;
	PWORD lpAddressOfNameOrdinals;//����API�ַ����ĳ���
	for (i = 0; _lpApi[i]; ++i);
	dwLen = i;
	pImageDosHeader = (PIMAGE_DOS_HEADER)_hModule;
	pImageNtHeaders = (PIMAGE_NT_HEADERS)(_hModule + pImageDosHeader->e_lfanew);
	dwVirtualAddress = pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;     //������ƫ��
	pImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(_hModule + dwVirtualAddress);         //�������ַ
	lpAddressOfNames = (PCHAR*)(_hModule + pImageExportDirectory->AddressOfNames);         //�����ֵ��������б�

	//����������ĺ������������жϣ�Ȼ�󷵻�ָ���������ĺ�����ַ
	for (i = 0; _hModule + lpAddressOfNames[i]; i++)
	{
		if (strlen(_hModule + lpAddressOfNames[i]) == dwLen && !strcmp(_hModule + lpAddressOfNames[i], _lpApi))//�ж��Ƿ�Ϊ_lpApi
		{
			lpAddressOfNameOrdinals = (PWORD)(_hModule + pImageExportDirectory->AddressOfNameOrdinals);//�����ֵ������������б�
			return _hModule + ((PDWORD)(_hModule + pImageExportDirectory->AddressOfFunctions))[lpAddressOfNameOrdinals[i]];//���ݺ��������ҵ�������ַ
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
	// ��ȡ�豸���
	HANDLE hDevice = CreateFile(SYMBOLICLINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwError = GetLastError();
	if (hDevice == NULL)
	{
		printf("CreateFile Failed\n");
	}

	DWORD dwDllBase = x86GetUser32();
	DWORD dwAddr = x86GetApi(dwDllBase, "MessageBoxA");

	// ����ͨ��
	DWORD dwInBuffer = dwAddr;
	DWORD dwOutBuffer = 0xFFFFFFFF;
	DWORD dwOutNumber;
	DeviceIoControl(hDevice, OPER_OPEN, &dwInBuffer, IN_BUFFER_MAXLENGTH, &dwOutBuffer, OUT_BUFFER_MAXLENGTH, &dwOutNumber, NULL);
	printf("dwOutBuffer: %08X dwOutNumber: %08X\n", dwOutBuffer, dwOutNumber);
	// �ر��豸
	CloseHandle(hDevice);
	return TRUE;
}


LONG Cmfc_driver_loaderDlg::stopMonitor()
{
	// ��ȡ�豸���
	HANDLE hDevice = CreateFile(SYMBOLICLINK_NAME, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	DWORD dwError = GetLastError();
	if (hDevice == NULL)
	{
		MessageBoxW(0, 0, 0);
		printf("CreateFile Failed\n");
	}
	
	DWORD dwDllBase = x86GetUser32();
	DWORD dwAddr = x86GetApi(dwDllBase, "MessageBoxA");

	// ����ͨ��
	DWORD dwInBuffer = dwAddr;
	DWORD dwOutBuffer = 0xFFFFFFFF;
	DWORD dwOutNumber;
	DeviceIoControl(hDevice, OPER_CLOSE, &dwInBuffer, IN_BUFFER_MAXLENGTH, &dwOutBuffer, OUT_BUFFER_MAXLENGTH, &dwOutNumber, NULL);
	printf("dwOutBuffer: %08X dwOutNumber: %08X\n", dwOutBuffer, dwOutNumber);
	// �ر��豸
	CloseHandle(hDevice);
	return TRUE;
}