
// mfc_driver_loaderDlg.h : ͷ�ļ�
//

#pragma once
#include <WinSvc.h>
#include <Windows.h>
// Cmfc_driver_loaderDlg �Ի���
class Cmfc_driver_loaderDlg : public CDialogEx
{
// ����
public:
	Cmfc_driver_loaderDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_MFC_DRIVER_LOADER_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;
	SC_HANDLE scMageger;
	// ���ɵ���Ϣӳ�亯��
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg LONG loadDriver(CString driverPath, CString driverName);
	afx_msg LONG unloadDriver(CString driverPath, CString driverName);
	afx_msg LONG runDriver(CString driverPath, CString driverName);
	afx_msg LONG stopDriver(CString driverPath, CString driverName);
	afx_msg void OnBnClickedButton3();
	afx_msg void OnBnClickedButton4();
	// afx_msg LONG checkEmpty();
	LONG startMonitor();
	LONG stopMonitor();
};
