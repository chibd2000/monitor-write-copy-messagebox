#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#define WRITE_SIZE 100
#define DEVICE_NAME L"\\Device\\MyDevice"
#define LINK_NAME L"\\??\\test" // \\\\.\\test

#define OPER_OPEN CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER_CLOSE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING g_SymbolicLinkName;
UNICODE_STRING g_DeviceName;
PDRIVER_OBJECT pDriverObject;

ULONG* getPDE(ULONG addr)
{
	ULONG PDI = addr >> 22;
	return (ULONG*)(0xC0300000 + PDI * 4);
}

ULONG* getPTE(ULONG addr)
{
	ULONG PDI = addr >> 22;
	ULONG PTI = (addr >> 12) & 0x000003FF;
	return (ULONG*)(0xC0000000 + PDI * 0x1000 + PTI * 4);
}

VOID UnDriver(PDRIVER_OBJECT driver)
{
	IoDeleteSymbolicLink(&g_SymbolicLinkName);
	IoDeleteDevice(pDriverObject->DeviceObject);
	DbgPrint("����ж�سɹ�\n");
}

NTSTATUS IrpCreateProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("IrpCreateProc...\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IrpCloseProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	DbgPrint("IrpCloseProc...\n");
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void recordMeesageBoxParamFunc(ULONG esp3, ULONG eip3)
{
	// ˼·���� https://blog.csdn.net/Kwansy/article/details/109313237
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK ioStatusBlock;
	NTSTATUS ntStatus;
	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING fileNameString;
	WCHAR writeBuffer[WRITE_SIZE] = { 0 };
	ULONG uWriteSize = 0;
	UNICODE_STRING destString;
	ULONG apiAddr;
	__asm
	{
		push fs;
	}
	RtlInitEmptyUnicodeString(&destString, writeBuffer, WRITE_SIZE * sizeof(WCHAR));
	apiAddr = eip3 - 2; // Ĭ��EIP���ص���HOOK�������ֽ�֮��ĵ�ַ������Ĭ�ϵ�MessageBoxA�ĵ�ַӦ�ü�2���������Ǻ���ͷ�ĵ�ַ
	DbgPrint("Func ApiAddr -> %x\n", apiAddr);
	if (apiAddr == 0x77D507EA) // �ж�API��ַ������� 0x77D507EA = MessageBoxA
	{ 
		__try
		{
			RtlInitUnicodeString(&fileNameString, L"\\??\\C:\\log.txt");//��ʼ���ļ���	
			InitializeObjectAttributes(&objectAttributes, &fileNameString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
			ZwCreateFile(&hFile,
				GENERIC_WRITE | GENERIC_READ,
				&objectAttributes,
				&ioStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN_IF,
				FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
				NULL,
				0);
			RtlStringCbPrintfW(destString.Buffer, WRITE_SIZE * sizeof(WCHAR), L"ApiAddr:0x%x Param1:0x%x Param2:0x%x Param3:0x%x Param4:0x%x",
				apiAddr, ((PULONG)esp3)[1], ((PULONG)esp3)[2], ((PULONG)esp3)[3], ((PULONG)esp3)[4]);
			uWriteSize = wcslen(destString.Buffer) * 2;
			if (uWriteSize > WRITE_SIZE*2)
			{
				DbgPrint("can't write size_t -> %d > 200\n", uWriteSize);
				ZwClose(hFile);
			}
			else
			{
				DbgPrint("write size_t -> 0x%x\n", uWriteSize);
				ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatusBlock, destString.Buffer, uWriteSize, NULL, NULL);
				ZwClose(hFile);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			DbgPrint("Exception Error...");
		}
	}
	__asm
	{
		pop fs;
	}
}

__declspec(naked) NTSTATUS hookFunc()
{
	__asm
	{
		pushad;
		pushfd;
		// SS(+F) ESP(+C) EFLAG(+8) CS(+4) EIP(+0)
		mov eax, [esp + 0x24]; // EIP3 = [ESP0+0x24]
		mov ecx, [esp + 0x24 + 0xC]; // ESP3 = [ESP0+0x24+0xC] 
		push eax; // ������EIP
		push ecx; // ������ESP
		call recordMeesageBoxParamFunc; // �������ͨ��������EIP��ESP����ȡ��¼��صĲ���
		popfd;
		popad;
		iretd;
	}
}

NTSTATUS IrpDeviceControlProc(PDEVICE_OBJECT pDevObj, PIRP pIrp)
{
	//�����Լ���ҵ��...
	NTSTATUS nStatus = STATUS_INVALID_DEVICE_REQUEST;
	PIO_STACK_LOCATION pIrpStack;
	ULONG uIoControlCode;
	PVOID pIoBuffer;
	ULONG uInLength;
	ULONG uOutLength;
	ULONG uRead;
	//////
	ULONG uFailWrite;
	ULONG uSuccessWrite;
	ULONG uMessageBox = 0;
	//////
	
	DbgPrint("IrpDeviceConrolProc...\n");

	// ������ʱ������ֵ
	uRead = 0;
	uSuccessWrite = 0x11111111;
	// ��ȡIRP����
	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	// ��ȡ������
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;
	// ��ȡ��������ַ�����������ͬһ����
	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	// Ring3 �������ݵĳ���
	uInLength = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	// Ring0 �������ݵĳ���
	uOutLength = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	DbgPrint("IrpDeviceControlProc -> uIoControlCode: %x\n", uIoControlCode);
	switch (uIoControlCode)
	{
		case OPER_OPEN:
		{
					  // ��ȡ����ص�MessageBox�ĵ�ַ��Ȼ�����Ӧ��PTE�����޸�U/Sλʵ���ƹ�д����
					  DbgPrint("IrpDeviceControlProc -> OPER_OPEN �����ֽ���: %d\n", uInLength);
					  DbgPrint("IrpDeviceControlProc -> OPER_OPEN ����ֽ���: %d\n", uOutLength);
					  memset(&uRead, 0, 4);
					  memcpy(&uRead, pIoBuffer, 4);
					  //---------------------------------------------
					  // uRead = MessageBox' addr
					  uMessageBox = uRead;
					  DbgPrint("IrpDeviceControlProc -> MessageBoxA's addr is %x\n", uMessageBox);
					  // д�����ƹ�
					  *getPDE(uRead) = (*getPDE(uRead)|0x00000002);
					  *getPTE(uRead) = (*getPTE(uRead)|0x00000002);
					  DbgPrint("IrpDeviceControlProc -> MessageBoxA's PDE %x, PTE %x...\n", *getPDE(uRead), *getPTE(uRead));
					  // �����ж��ţ�����ռ�����ֽ� mov edi,edi -> eq 8003f500 0040EE00`00081020
					  *(PLONG)0x8003f500 = 0x00080000 | ((LONG)hookFunc & 0x0000FFFF);
					  *(PLONG)(0x8003f500 + 0x4) = 0x0000EE00 | ((LONG)hookFunc & 0xFFFF0000);
					  DbgPrint("IrpDeviceControlProc -> hookFunc's addr %x\n", hookFunc);
					  // inline hook MessageBoxW ��ת�ж��� int 0x20
					  *(PCHAR)uMessageBox = 0xCD;
					  *(PCHAR)(uMessageBox + 1) = 0x20;
					  DbgPrint("IrpDeviceControlProc -> hookFunc bytes %x\n", *(PLONG)uMessageBox);
					  //---------------------------------------------
					  // д�뻺����
					  memset(&uRead, 0, 4);
					  memcpy(pIoBuffer, &uSuccessWrite, 4);
					  DbgPrint("IrpDeviceControlProc -> OPER_OPEN uWrite: %x\n", uSuccessWrite);
					  pIrp->IoStatus.Information = 4; // �������ֽ�
					  nStatus = STATUS_SUCCESS;
					  break;
		}
		case OPER_CLOSE:
		{
					  DbgPrint("IrpDeviceControlProc -> OPER_CLOSE �����ֽ���: %d\n", uInLength);
					  DbgPrint("IrpDeviceControlProc -> OPER_CLOSE ����ֽ���: %d\n", uOutLength);
					  //----------------��ȡ������-----------------
					  memset(&uRead, 0, 4);
					  memcpy(&uRead, pIoBuffer, 4);
					  //----------------��ȡҪHOOK MessageBoxA�ĵ�ַ---------------------
					  uMessageBox = uRead;
					  DbgPrint("IrpDeviceControlProc -> MessageBoxA's addr is %x\n", uMessageBox);
					  //----------------�޸�HOOK������ͷ�� 0xFF8B-------------------
					  *(PCHAR)uMessageBox = 0x8B;
					  *(PCHAR)(uMessageBox + 1) = 0xFF;
					  DbgPrint("IrpDeviceControlProc -> hookFunc bytes %x\n", *(PLONG)uMessageBox);
					  //----------------д�뻺����---------------
					  memset(&uRead, 0, 4);
					  memcpy(pIoBuffer, &uSuccessWrite, 4);
					  DbgPrint("IrpDeviceControlProc -> OPER_CLOSE uWrite: %x\n", uSuccessWrite);
					  //----------------����״̬---------------
					  pIrp->IoStatus.Information = 4; // �������ֽ�
					  nStatus = STATUS_SUCCESS;
					  break;
		}
		default:
			pIrp->IoStatus.Information = 0;
			break;
	}

	//���÷���״̬
	pIrp->IoStatus.Status = STATUS_SUCCESS;	//  getlasterror()�õ��ľ������ֵ
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS generateDevice()
{
	PDEVICE_OBJECT pDeviceObject = NULL;
	NTSTATUS nStatus;

	// �����豸
	RtlInitUnicodeString(&g_DeviceName, DEVICE_NAME);
	nStatus = IoCreateDevice(
		pDriverObject,				//��ǰ�豸��������������
		0,
		&g_DeviceName,			//�豸���������
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&pDeviceObject			//�豸����ָ��
	);
	
	if (nStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateDevice Failed\n");
		return -1;
	}

	// �������ݷ�ʽ
	pDeviceObject->Flags |= DO_BUFFERED_IO;

	// ����������������
	RtlInitUnicodeString(&g_SymbolicLinkName, LINK_NAME);
	nStatus = IoCreateSymbolicLink(&g_SymbolicLinkName, &g_DeviceName);
	if (nStatus != STATUS_SUCCESS)
	{
		DbgPrint("IoCreateSymbolicLink Failed\n");
		return -1;
	}
	
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = IrpCreateProc;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = IrpCloseProc;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDeviceControlProc;
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT Driver, PUNICODE_STRING RegistryPath)
{
	pDriverObject = Driver;
	DbgPrint(("������װ�ɹ�\n"));
	Driver->DriverUnload = UnDriver;
	generateDevice();
	return STATUS_SUCCESS;
}