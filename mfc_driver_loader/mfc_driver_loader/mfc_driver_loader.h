
// mfc_driver_loader.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// Cmfc_driver_loaderApp: 
// �йش����ʵ�֣������ mfc_driver_loader.cpp
//

class Cmfc_driver_loaderApp : public CWinApp
{
public:
	Cmfc_driver_loaderApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern Cmfc_driver_loaderApp theApp;