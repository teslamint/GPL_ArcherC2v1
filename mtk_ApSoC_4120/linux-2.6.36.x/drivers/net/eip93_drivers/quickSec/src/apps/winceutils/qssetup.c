/*
 *
 * qssetup.c
 *
 *  Copyright:
 *          Copyright (c) 2008 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Quicksec Install/Uninstall utility for Windows CE.
 * This is not supported by any means. Can be used only 
 * as reference to create real installer. 
 *
 */

#ifdef _WIN32_WCE

#include <windows.h>
#include <ntddndis.h>
#include <winioctl.h>
#include <strsafe.h>
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
#include <aygshell.h>
#include <tpcshell.h>
#pragma comment(lib, "aygshell")
#endif
#include <stdarg.h>

#include "sshdistdefs.h"
#include "qssetup.h"

/* By default, in Debug build DEBUG_LIGHT is defined, However,
   we are undefining it. In order to get the debug meessages
   enable this flag.
*/
#undef DEBUG_LIGHT

static HINSTANCE app_instance;

typedef struct 
  {
    const HKEY      Root;
    const wchar_t * Key_p;
    const wchar_t * Value_p;
    DWORD           Type;
    const void *    Data_p;
  }
qssetup_regentry_t;


static const qssetup_regentry_t RegistryValues[] =
  {
    {
      HKEY_LOCAL_MACHINE,
      L"Drivers\\BuiltIn\\QuickSec",
      L"Prefix",
      REG_SZ,
      L"QSI"
    },
    {
      HKEY_LOCAL_MACHINE,
      L"Drivers\\BuiltIn\\QuickSec",
      L"Dll",
      REG_SZ,
      L"quicksec.dll"
    },
    {
      HKEY_LOCAL_MACHINE,
      L"Drivers\\BuiltIn\\QuickSec",
      L"FriendlyName",
      REG_SZ,
      L"SafeNet QuickSec"
    },
    {
      HKEY_LOCAL_MACHINE,
      L"Drivers\\BuiltIn\\QuickSec",
      L"Order",
      REG_DWORD,
      (void *) 5
    },
    {
      HKEY_LOCAL_MACHINE,
      L"Drivers\\BuiltIn\\QuickSec",
      L"Index",
      REG_DWORD,
      (void *) 1
    },
  };


static void qssetup_mbox(HWND ParentWnd, TCHAR *tbuff, UINT mbtype)
{
  TCHAR caption_buf[64] = _T("NoTitle");
  int caption_len = sizeof caption_buf / sizeof caption_buf[0];

  LoadString(app_instance, IDS_TITLE, caption_buf, caption_len);

  MessageBox(ParentWnd,
             tbuff,
         caption_buf,
             mbtype);
}

static void qssetup_debug(HWND ParentWnd, TCHAR *tbuff)
{
#ifdef SSH_QSSETUP_DEBUG 
  qssetup_mbox(ParentWnd, tbuff, MB_OK);
#endif
}

static void qssetup_info(HWND ParentWnd, TCHAR *tbuff)
{

  qssetup_mbox(ParentWnd, tbuff, MB_OK);

}

static void qssetup_warn(HWND ParentWnd, TCHAR *tbuff)
{

  qssetup_mbox(ParentWnd, tbuff, MB_OK | MB_ICONWARNING);

}

static void qssetup_error(HWND ParentWnd, TCHAR *tbuff)
{
  qssetup_mbox(ParentWnd, tbuff, MB_OK | MB_ICONERROR);
}

BOOL APIENTRY 
DllMain(HANDLE hModule, DWORD event, LPVOID lpReserved)
{
  switch (event)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      app_instance = (HINSTANCE)hModule;
      break;
    }
  return TRUE;
}


static HKEY
qssetup_registry_open_key(
        HKEY hKey,
        LPCWSTR lpSubKey)
{
  HKEY ResultKey;

  if (RegOpenKeyEx(hKey, lpSubKey, 0, 0, &ResultKey) != ERROR_SUCCESS)
    {
      return NULL;
    } 

  return ResultKey;
}

static HKEY
qssetup_registry_create_key(
        HKEY hKey,
        LPCWSTR lpSubKey)
{
  HKEY ResultKey;

  if (RegCreateKeyEx(
              hKey, 
              lpSubKey, 
              0, 
              NULL, 
              0, 
              KEY_ALL_ACCESS, 
              NULL, 
              &ResultKey, 
              NULL)
      != ERROR_SUCCESS)
    {
      return NULL;
    } 

  return ResultKey;
}


static BOOL
qssetup_registry_get_multi_wcs(
        HKEY hKey,
        LPCWSTR lpValueName,
        wchar_t ** MultiWcs_pp,
        unsigned int * ByteCount_p)
{
  wchar_t * DataBuffer_p;
  DWORD DataLen = 64;       /* Should be enough */
  DWORD Type;
  DWORD Result;
  BOOL First = TRUE;

  DataBuffer_p = malloc(DataLen);
  
Retry:

  if (DataBuffer_p == NULL)
    {
      return FALSE;
    }

  Result = 
    RegQueryValueEx(
            hKey, 
            lpValueName, 
            NULL, 
            &Type, 
            (LPBYTE) DataBuffer_p, 
            &DataLen);

  if (Result == ERROR_MORE_DATA && First)
    {
      free(DataBuffer_p);
      DataBuffer_p = malloc(DataLen);
      First = FALSE;
      goto Retry;
    }

  if (Result != ERROR_SUCCESS)
    {
      free(DataBuffer_p);
      return FALSE;
    }

  if (Type != REG_MULTI_SZ || (DataLen & 1))
    {
      free(DataBuffer_p);
      SetLastError(ERROR_INVALID_DATA);
      return FALSE;
    }

  *MultiWcs_pp = DataBuffer_p;
  *ByteCount_p = DataLen;

  return TRUE;
}

static BOOL
qssetup_registry_set_value(
        HKEY hKey,
        LPCWSTR lpValueName,
        DWORD Type,
        const void * Data_p,
        unsigned int DataLen)
{
  LONG Result;

  Result =
      RegSetValueEx(
              hKey,
              lpValueName,
              0,
              Type,
              Data_p,
              DataLen);

  if (Result != ERROR_SUCCESS)
    {
      return FALSE;
    }
          
  return TRUE;
}


/*  qssetup_multi_sz_remove_entry

    Finds and removes string Entry_p from multistring MultiSz_p.
    Returns size in bytes of the possibly modified multistring in
    *NewByteCount_p.

    Returns TRUE when string is found and removed and FALSE when not.
*/
static BOOL
qssetup_multi_sz_remove_entry(
        wchar_t * MultiSz_p,
        const wchar_t * Entry_p,
        unsigned int * NewByteCount_p)
{
  wchar_t * p = MultiSz_p;
  wchar_t * EntryLoc_p = NULL;

  /* find the entry from multistring, if found save to EntryLoc_p */
  while (*p != 0)
    {
      if (!EntryLoc_p && !wcscmp(p, Entry_p))
        {
          EntryLoc_p = p;
        }

      p += wcslen(p) + 1;
    }

  p++;  /* Advance past ending zero */

  if (EntryLoc_p)
    {
      const int offset = wcslen(Entry_p) + 1;
      void * dst_p = (void *) EntryLoc_p;
      void * src_p = (EntryLoc_p + offset);
      size_t MoveByteCount = (p - (wchar_t *) src_p) * sizeof *p;

      if (MoveByteCount == sizeof(wchar_t) && EntryLoc_p == MultiSz_p)
        {
          memset(dst_p, 0, 2 * sizeof(wchar_t));
          *NewByteCount_p = 0;
        }
      else
        {
          memmove(dst_p, src_p, MoveByteCount);
          *NewByteCount_p = sizeof(wchar_t) * ((p - MultiSz_p) - offset);
        }

      return TRUE;
    }
  
  *NewByteCount_p = sizeof(wchar_t) * (p - MultiSz_p);

  return FALSE;
}

BOOL DeleteKey_i(HKEY hKeyRoot, LPTSTR lpSubKey)
{
  LPTSTR lpEnd;
  LONG lResult;
  DWORD dwSize;
  TCHAR szName[MAX_PATH];
  TCHAR valName[MAX_PATH];
  DWORD valNameLen = MAX_PATH;
  HKEY hKey;
  FILETIME ftWrite;

  /* Try to delete it straight away. */
  lResult = RegDeleteKey(hKeyRoot, lpSubKey);
  if (lResult == ERROR_SUCCESS)
    return TRUE;
  
  /* No luck, try with recursion. */
  lResult = RegOpenKeyEx (hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);
  if (lResult != ERROR_SUCCESS) 
    {
      if (lResult == ERROR_FILE_NOT_FOUND) 
    return TRUE;
      else 
    return FALSE;
    }
  
  lpEnd = lpSubKey + lstrlen(lpSubKey);
  if (*(lpEnd - 1) != TEXT('\\')) 
    {
      *lpEnd =  TEXT('\\');
      lpEnd++;
      *lpEnd =  TEXT('\0');
    }

  /* Delete all values for the Key. */
  lResult = RegEnumValue(hKey, 0, valName, &valNameLen, NULL, NULL, 
             NULL, NULL);
  if (lResult == ERROR_SUCCESS) 
    {
        do 
      {
        lResult = RegDeleteValue(hKey, valName);
        
        valNameLen = MAX_PATH;
        lResult = RegEnumValue(hKey, 0, valName, &valNameLen, NULL, 
                   NULL, NULL, NULL);
        
      } while (lResult == ERROR_SUCCESS);
      }


  /* Enumerate keys, do recurive delete if required. */
  dwSize = MAX_PATH;
  lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
             NULL, NULL, &ftWrite);
  
  if (lResult == ERROR_SUCCESS) 
    {
      do
    {
      StringCchCopy (lpEnd, MAX_PATH*2, szName);
      
      if (!DeleteKey_i(hKeyRoot, lpSubKey)) 
        break;
      
      dwSize = MAX_PATH;
      
      lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                 NULL, NULL, &ftWrite);
      
    } while (lResult == ERROR_SUCCESS);
    }

  lpEnd--;
  *lpEnd = TEXT('\0');
  
  RegCloseKey (hKey);
  
  /* And finally try to delete the key again. */
  lResult = RegDeleteKey(hKeyRoot, lpSubKey);

  if (lResult == ERROR_SUCCESS) 
    return TRUE;
  
  return FALSE;
}

static BOOL 
qssetup_registry_delete_key(
        HKEY hKeyRoot, 
        LPCTSTR lpSubKey)
{
  TCHAR szDelKey[2 * MAX_PATH];
  
  StringCchCopy (szDelKey, MAX_PATH*2, lpSubKey);
  return DeleteKey_i(hKeyRoot, szDelKey);
}

static void
qssetup_registry_close_key(
        HKEY hKey)
{
  RegCloseKey(hKey);
}

static BOOL
qssetup_write_regentry(
        const qssetup_regentry_t * RegEntry_p)
{
  HKEY hKey;
  DWORD ByteCount;
  BOOL Success = TRUE;
  const void * Data_p;
  DWORD Data;

  hKey = qssetup_registry_create_key(RegEntry_p->Root, RegEntry_p->Key_p);
  if (hKey == NULL)
    {
      return FALSE;
    }

  switch (RegEntry_p->Type)
    {
    case REG_SZ:
      ByteCount = sizeof (wchar_t);
      ByteCount *= wcslen(RegEntry_p->Data_p) + 1;
      Data_p = RegEntry_p->Data_p;
      break;
    case REG_DWORD:
      ByteCount = sizeof (DWORD);
      Data = (DWORD) RegEntry_p->Data_p;
      Data_p = &Data;
      break;
    default:
      Success = FALSE;
    }

  if (Success)
    {
      if (!qssetup_registry_set_value(
                  hKey, 
                  RegEntry_p->Value_p,
                  RegEntry_p->Type,
                  Data_p,
                  ByteCount))
        {
          Success = FALSE;
        }
    }

  qssetup_registry_close_key(hKey);

  return TRUE;
}


static HANDLE 
qssetup_find_device_handle(
        const wchar_t * NamePrefix_p) 
{
  int   Success = FALSE;
  HKEY  hActiveKey = 0;
  DWORD dwIndex;
  const int PrefixLen = wcslen(NamePrefix_p);
  HANDLE hDeviceHandle = 0;

  if (RegOpenKeyEx(
          HKEY_LOCAL_MACHINE, 
                  L"Drivers\\Active",
          0, 
                    KEY_READ,
          &hActiveKey) != ERROR_SUCCESS)
    {
      return NULL;
    }
  
  dwIndex = 0;
  while (!Success)
    {
      HKEY hDeviceKey;
      DWORD dwSize;
      DWORD dwType;
      wchar_t Buffer[MAX_PATH];

      dwSize = sizeof Buffer;
      if (RegEnumKeyEx(hActiveKey, dwIndex++, Buffer, &dwSize,
          NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
        {
          break;
        }

        if (RegOpenKeyEx(hActiveKey, Buffer, 0, KEY_READ, &hDeviceKey) 
            != ERROR_SUCCESS) 
        {
          break;
        }
          
        dwSize = sizeof Buffer;
        if (RegQueryValueEx(hDeviceKey, L"Name", NULL, &dwType, 
                     (LPBYTE) Buffer, &dwSize) == ERROR_SUCCESS)
        {
            if (!wcsnicmp(NamePrefix_p, Buffer, PrefixLen)) 
              {
  
              /* Retrieve the device handle and exit. */
                dwSize = sizeof (hDeviceHandle);
          
                if (RegQueryValueEx(hDeviceKey, L"Hnd", NULL, &dwType, 
                     (LPBYTE) &hDeviceHandle, &dwSize) == ERROR_SUCCESS)
                {
                    Success = TRUE;
                }
              }
        }

        RegCloseKey(hDeviceKey);
      }
      
  RegCloseKey (hActiveKey);
  
  return hDeviceHandle;
}


QS_SETUP_API
codeINSTALL_INIT
Install_Init(HWND hwndParent,
             BOOL fFirstCall,
             BOOL fPreviouslyInstalled,
             LPCTSTR pszInstallDir)
{
  unsigned int RegEntryCount = 
          sizeof(RegistryValues) / sizeof(RegistryValues[0]);
  unsigned int RegEntryIndex;

  qssetup_debug(hwndParent, _T("Install_Init()"));

  for (RegEntryIndex = 0; RegEntryIndex < RegEntryCount; ++RegEntryIndex)
    {
      if (!qssetup_write_regentry(&RegistryValues[RegEntryIndex]))
        {
          qssetup_error(hwndParent, _T("regentryerror"));
        }
    }

  return codeINSTALL_INIT_CONTINUE;
}


QS_SETUP_API
codeINSTALL_EXIT 
Install_Exit(HWND hwndParent,
             LPCTSTR pszInstallDir,
             WORD    cFailedDirs,
             WORD    cFailedFiles,
             WORD    cFailedRegKeys,
             WORD    cFailedRegVals,
             WORD    cFailedShortcuts)
{
  qssetup_debug(hwndParent, _T("Install_Exit()"));

  qssetup_info(
            hwndParent,
            _T("Restart is required to complete installation."));

  return codeINSTALL_EXIT_DONE;
}


/*
    qssetup_clear_recent_programs

    This functions searches a string match from paths listed in 
    "Recent Programs" menu under "Start Menu".

    The list is stored in binary data to a "Start MRU" value under 
    registry key "HKEY_CURRENT_USER\System\State\Shell". Below is 
    a quote from a post on MSDN.

    The contents of the value are as follows:
    DWORD numItems;
    MRUITEM mruItem[numItems];
 
    Where MRUITEM is a variable-sized structure defined as follows:
    DWORD cbItem; // number of bytes in MRUITEM
    DWORD dwReserved1 // set to -1
    DWORD dwReserved2 // set to -1
    WCHAR appPath[cbItem - 12]; // path to the executable
    // cbItem must be a multiple of 4
 
    Edit this value removing an item that has appPath matching your
    executable.  Don't forget to adjust numItems. Shell will pick the
    changes to this registry value automatically.
*/
static void
qssetup_clear_recent_programs(
        const wchar_t * const MatchString_p)
{
    HKEY hShellState;
    DWORD DataByteCount;

    if (RegOpenKeyEx(
                HKEY_CURRENT_USER, 
                _T("System\\State\\Shell"),
                0, 
                0, &hShellState) 
          != ERROR_SUCCESS) 
    {
        return;
    }

    if (RegQueryValueEx(
                hShellState,
                _T("Start MRU"),
                NULL,
                NULL, 
                NULL, 
                &DataByteCount)
        != ERROR_SUCCESS)
    {
        RegCloseKey(hShellState);
        return;
    }

    if (DataByteCount > 4)
    {
        DWORD ItemCount;
        int i;
        BYTE * Block_p;
        BYTE * Item_p;

        Block_p = malloc(DataByteCount);
        if (!Block_p)
        {
            RegCloseKey(hShellState);
            return;
        }

        if (RegQueryValueEx(
                    hShellState,
                    _T("Start MRU"),
                    NULL,
                    NULL, 
                    Block_p, 
                    &DataByteCount)
            != ERROR_SUCCESS)
        {
            RegCloseKey(hShellState);
            free(Block_p);
            return;
        }

        ItemCount = * (DWORD *) Block_p;
        Item_p = Block_p + 4;
        for (i = 0; i < ItemCount; i++)
        {
            wchar_t * Path_p = (wchar_t * ) (Item_p + 12);
            if (wcsstr(Path_p, MatchString_p) != NULL)
            {
                break;
            }

            Item_p += *((DWORD *) Item_p);
        }

        if (i < ItemCount)
        {
            BYTE * ItemEnd_p = Item_p + *((DWORD *) Item_p);
            memmove(Item_p, ItemEnd_p, DataByteCount - (ItemEnd_p - Block_p));
            DataByteCount -= ItemEnd_p - Item_p;
        
            *((DWORD *) Block_p) = ItemCount - 1;
            RegSetValueEx( 
                    hShellState, 
                    _T("Start MRU"),
                    0, 
                    REG_BINARY, 
                    Block_p, 
                    DataByteCount); 
        }

        free(Block_p);
    }

    RegCloseKey(hShellState);
}


QS_SETUP_API 
codeUNINSTALL_INIT
Uninstall_Init(HWND hwndParent,
               LPCTSTR pszInstallDir)
{
  BOOL Success = TRUE;
  HANDLE hNdis = INVALID_HANDLE_VALUE;

  qssetup_debug(hwndParent, _T("Uninstall_Init"));

    {
      HKEY hTcpIp = NULL;
      wchar_t * BindData_p = NULL;
      unsigned int BindDataByteCount;
      BOOL Ok = TRUE;

      if (Ok)
        {
          hTcpIp = 
              qssetup_registry_open_key(
                      HKEY_LOCAL_MACHINE,
                      L"Comm\\Tcpip\\Linkage");

          if (hTcpIp == NULL)
            {
              Ok = FALSE;
            }
         }

      if (Ok)
        {
          if (!qssetup_registry_get_multi_wcs(
                      hTcpIp,
                      L"Bind",
                      &BindData_p,
                      &BindDataByteCount))
            {
              Ok = FALSE;
            }
        }

      if (Ok)
       {
         const wchar_t DeviceName[] = L"QSVNIC1";

          if (qssetup_multi_sz_remove_entry(
                     BindData_p,
                     DeviceName,
                     &BindDataByteCount))
            {
              if (BindDataByteCount)
                {
                  Ok =
                      qssetup_registry_set_value(
                              hTcpIp,
                              L"Bind",
                              REG_MULTI_SZ,
                              BindData_p,
                              BindDataByteCount);
                }
              else
              if (RegDeleteValue(hTcpIp, L"Bind") != ERROR_SUCCESS)
                {
                  Ok = FALSE;
                }
            }
       }
  
      if (BindData_p)
       {
         free(BindData_p);
       }

      if (hTcpIp)
       {
         qssetup_registry_close_key(hTcpIp);
       }

      if (!Ok)
        {
          qssetup_warn(hwndParent, _T("Unbinding QSVNIC1 failed."));
        }
    }

    {
      HANDLE QsDeviceHandle = qssetup_find_device_handle(L"QSI");
      if (QsDeviceHandle)
        {
          if (DeactivateDevice(QsDeviceHandle) != TRUE)
            {
              qssetup_warn(
                      hwndParent, 
                      _T("Deactivating QuickSec Device failed."));
            }
        }
    }

    {
      BOOL Ok = TRUE;

      hNdis = 
          CreateFile(
                  DD_NDIS_DEVICE_NAME, 
                  (GENERIC_READ | GENERIC_WRITE), 
                  (FILE_SHARE_READ | FILE_SHARE_WRITE), 
                  NULL, 
                  OPEN_ALWAYS,
                  0, 
                  NULL);
      if (hNdis == INVALID_HANDLE_VALUE) 
        {
          qssetup_warn(hwndParent, _T("Obtaining ndis handle failed"));
          Ok = FALSE;
        }

      if (Ok)
        {
          DWORD BytesOut;
          wchar_t InBuffer[] = L"QSVNIC1";

          Ok = 
              DeviceIoControl(
                    hNdis,
                    IOCTL_NDIS_DEREGISTER_ADAPTER,
                    /* LPVOID lpInBuffer */ InBuffer,
                    /* DWORD nInBufferSize */ sizeof(InBuffer),
                    /* LPVOID lpOutBuffer */ NULL,
                    /* DWORD nOutBufferSize */ 0,
                    /* LPDWORD lpBytesReturned */ &BytesOut,
                    /* LPOVERLAPPED lpOverlapped */ NULL);


          if (!Ok)
            {
              qssetup_warn(hwndParent, 
                           _T("Adapter deregistration from NDIS failed"));
            }
        }

      if (hNdis != INVALID_HANDLE_VALUE) 
        {
          CloseHandle(hNdis);
        }
    }

    {
      BOOL Ok = TRUE;
      DWORD dwIndex = 0;    
      HKEY hCommKey = 
          qssetup_registry_open_key(
                  HKEY_LOCAL_MACHINE, 
                  L"Comm");

      if (!hCommKey)
        {
          Ok = FALSE;
        }

      while (Ok)
        {
          HKEY hParmsKey;
          DWORD dwSize;
          DWORD dwType;
          wchar_t Buffer[MAX_PATH];

          dwSize = sizeof Buffer;
          if (RegEnumKeyEx(hCommKey, dwIndex++, Buffer, &dwSize,
              NULL, NULL, NULL, NULL) != ERROR_SUCCESS)
            {
              break;
            }

          wcscat(Buffer, L"\\Parms");

          if (RegOpenKeyEx(hCommKey, Buffer, 0, KEY_READ | KEY_WRITE, 
                           &hParmsKey) 
              != ERROR_SUCCESS) 
            {
              continue;
            }

          dwSize = sizeof Buffer;
          if (RegQueryValueEx(hParmsKey, L"UpperBind", NULL, &dwType, 
                       (LPBYTE) Buffer, &dwSize) == ERROR_SUCCESS)
            {
              if (!wcsicmp(L"QSECLAN", Buffer) ||
                  !wcsicmp(L"QSECWAN", Buffer)) 
                {
                  DWORD stat;
                  dwSize = sizeof Buffer;

                  stat = RegQueryValueEx(
                          hParmsKey, 
                          L"OriginalUpperbind",
                          NULL, 
                          &dwType,
                          (LPBYTE) Buffer,
                          &dwSize);

                  if (stat != ERROR_SUCCESS)
                    {
                      RegDeleteValue(hParmsKey, L"UpperBind");
                    }
                  else
                    {
                      RegSetValueEx(
                              hParmsKey,
                              L"UpperBind",
                              0, 
                              dwType, 
                              (LPBYTE) Buffer,
                              dwSize);
                    }

                  RegDeleteValue(hParmsKey, L"OriginalUpperBind");
                }
            }

            RegCloseKey(hParmsKey);
        }

      if (hCommKey)
        {
          qssetup_registry_close_key(hCommKey);
        }
    }
  
    {
      static const wchar_t * const keys_to_delete_HKLM[] = 
        {
          L"Comm\\QSVNIC1",
          L"Comm\\QSVNIC",
          L"Comm\\QSEC",
          L"Comm\\QuickSec",
          L"Software\\SafeNet",
          L"Drivers\\BuiltIn\\QuickSec",
          NULL
        };

      int i;

      for (i = 0; keys_to_delete_HKLM[i]; i++)
        {
          qssetup_registry_delete_key(
                  HKEY_LOCAL_MACHINE, 
                  keys_to_delete_HKLM[i]);
        }
    }

    {
      HKEY hRndisParms = 
          qssetup_registry_open_key(
                  HKEY_LOCAL_MACHINE, 
                  L"Comm\\RNDISFN1\\Parms");

      if (hRndisParms)
        {
          RegDeleteValue(hRndisParms, L"UpperBind");
          qssetup_registry_close_key(hRndisParms);
        }
    }

    return codeUNINSTALL_INIT_CONTINUE;
}


QS_SETUP_API 
codeUNINSTALL_EXIT 
Uninstall_Exit(HWND hwndParent)
{
  WIN32_FIND_DATA fdata;
  HANDLE hSearch;

  qssetup_debug(hwndParent, _T("Uninstall_Exit"));

  DeleteFile(L"\\Windows\\quicksec.dll");
  DeleteFile(L"\\Windows\\qsvnic5.dll");

  memset(&fdata, 0x0, sizeof(fdata));

  while ((hSearch = FindFirstFile(L"\\Program Files\\QuickSec\\*", &fdata))
         != INVALID_HANDLE_VALUE)
    {
      wchar_t newpath[MAX_PATH];
      wsprintf(newpath, L"\\Program Files\\QuickSec\\%s", fdata.cFileName);

      if (!(fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
          DeleteFile(newpath);
        }

      memset(&fdata, 0x0, sizeof(fdata));
      FindClose(hSearch);
    }

  RemoveDirectory(L"\\Program Files\\QuickSec");

  qssetup_registry_delete_key(
          HKEY_LOCAL_MACHINE, 
          L"Drivers\\BuiltIn\\QuickSec");

  qssetup_clear_recent_programs(L"QuickSec");

  qssetup_info(hwndParent,_T("Restart is required to complete uninstall."));

  return codeUNINSTALL_EXIT_DONE;  
}

#endif /* _WIN32_WCE */
