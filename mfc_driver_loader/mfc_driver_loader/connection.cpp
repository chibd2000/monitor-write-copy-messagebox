#include "stdafx.h"
#include "Connection.h"

#define SYMBOLICLINK_NAME L"\\\\.\\test"
#define OPER1 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define OPER2 CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)


Connection::Connection()
{
}


Connection::~Connection()
{
}


