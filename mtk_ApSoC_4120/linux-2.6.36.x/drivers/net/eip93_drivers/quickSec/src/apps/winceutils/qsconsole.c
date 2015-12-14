/*
 *
 * qsconsole.c
 *
 *  Copyright:
 *          Copyright (c) 2006 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Policy manager and engine admin utility for Windows CE.
 *
 */

#ifdef _WIN32_WCE

#include <windows.h>
#include <commctrl.h>
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
#include <aygshell.h>
#include <tpcshell.h>
#pragma comment(lib, "aygshell")
#endif
#include <msgqueue.h>
#include "qsconsole.h"

/*
 * This application.
 */
static TCHAR *application_name = _T("QSConsole");

/*
 * Path to policy manager executable and configuration file.
 */
static TCHAR *exec_path = _T("\\Program Files\\QuickSec\\quicksecpm.exe");
static TCHAR *config_path = _T("\\Program Files\\QuickSec\\quicksec.xml");

/*
 * Registry subkey used by policy manager and this application.
 */
static TCHAR *reg_app_subkey = _T("Software\\SafeNet\\QuickSec");

/*
 * Name of the named point-to-point message queue on which this
 * application sends commands to policy manager.
 */
static TCHAR *control_queue_name = _T("QuickSecPMControl");

/*
 * Interceptor driver names under the \Comm registry subkey.
 */
static TCHAR *icept_driver_name = _T("QuickSec");
static TCHAR *icept_instance_name = _T("QSEC");

/*
 * Policy manager process id from the previous and current run of the
 * periodic update procedure.
 */
static DWORD pm_pid_previous;
static DWORD pm_pid_current;

/*
 * Window message for POSIX signal emulation.
 */
static UINT pm_signal_msg;

/*
 * Handle to the point-to-point message queue between this app and
 * policy manager.
 */
static HANDLE control_handle;

/*
 * Log display state data.
 */
static TCHAR log_path[1024];    /* log file path read from registry */
static HANDLE log_handle;       /* log file handle */
static DWORD log_position;      /* how much of the log file has been read */

/*
 * Byte and TCHAR buffers for reading the log file and converting into
 * unicode.
 */
#define LOG_BUFFER_SIZE      1024
static char log_buffer[LOG_BUFFER_SIZE];
static TCHAR log_tbuffer[LOG_BUFFER_SIZE];

/*
 * Timer identifier.
 */
static UINT periodic_timer;

/*
 * Flag to prevent re-entering the periodic update procedure,
 * e.g. while it is suspended displaying a message box.
 */
static int periodic_busy;

/*
 * Various window etc.  handles.
 */
static HINSTANCE application_instance;
static HWND main_window;
static HWND menubar_window;
static HWND edit_window;
static HWND pm_status_window;
static HWND icept_status_window;
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
static SHACTIVATEINFO activate_info;
static SHACTIVATEINFO dialog_activate_info;
#endif

#define CHILD_ID_MENUBAR        1
#define CHILD_ID_EDIT           2

/*
 * Maximum and current length of text in the log file display area.
 */
static DWORD edit_maxlength = 32768;
static DWORD edit_length;

/*
 * Variables pertaining to window layout.
 */
static int char_width;
static int char_height;
static int first_x;
static int next_y;
static int available_width;
static int available_height;

/*
 * Data describing a simple dialog for entering a long string.
 */
typedef struct {
  TCHAR *title;
  TCHAR string[4096];
} dialog_param_t;

/*
 * Open a message box to output a formatted error message. If code is
 * nonzero, append ": " and the corresponding system error message, or
 * just the number if the system has no message database.
 */
static void verror(LPTSTR fmt, va_list ap, DWORD code)
{
  TCHAR buf[256];
  int len = sizeof buf / sizeof buf[0], pos = 0, n;

  if ((n = _vsntprintf(buf + pos, len - pos, fmt, ap)) >= 0)
    pos += n;
  else
    pos += len;

  if (code)
    {
      if ((n = _sntprintf(buf + pos, len - pos, _T(": "))) >= 0)
        pos += n;
      else
        pos += len;

      if ((n = FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            code,
            0,
            buf + pos,
            len - pos,
            NULL)) == 0)
        {
          if ((n = _sntprintf(buf + pos, len - pos,
                              _T("error %u"), (unsigned)code)) >= 0)
            pos += n;
          else
            pos += len;
        }
      SetLastError(ERROR_SUCCESS);
    }

  buf[len - 1] = _T('\0');

  MessageBox(
    main_window,
    buf,
    application_name,
    MB_OK | MB_ICONERROR);
}

/*
 * Output an error message.
 */
static void error(LPTSTR fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  verror(fmt, ap, 0);
  va_end(ap);
}

/*
 * Output an error message and if GetLastError() returns nonzero,
 * append ": " and the corresponding system message.
 */
static void error_system(LPTSTR fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  verror(fmt, ap, GetLastError());
  va_end(ap);
}

/*
 * Output an error message and if code is nonzero, append ": " and the
 * corresponding system message.
 */
static void error_code(DWORD code, LPTSTR fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  verror(fmt, ap, code);
  va_end(ap);
}

/*
 * Get a DWORD value from within the HKLM registry subtree into the
 * given buffer. Return TRUE on success.
 */
static BOOL get_reg_dword(const TCHAR *subkey, const TCHAR *value_name,
                          DWORD *value)
{
  HKEY key = NULL;
  DWORD type, size, code;

  if ((code = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        subkey,
        0,
        0,
        &key)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegOpenKeyEx: %s"), subkey);
      goto fail;
    }

  size = sizeof(DWORD);

  if ((code = RegQueryValueEx(
        key,
        value_name,
        NULL,
        &type,
        NULL,
        &size)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegQueryValueEx: %s"), value_name);
      goto fail;

    }

  if (type != REG_DWORD)
    goto fail;

  if (size != sizeof(DWORD))
    goto fail;

  if ((code = RegQueryValueEx(
        key,
        value_name,
        NULL,
        &type,
        (BYTE *)value,
        &size)) != ERROR_SUCCESS)
    {
      error_code(code, _T("RegQueryValueEx: %s"), value_name);
      goto fail;

    }

  RegCloseKey(key);
  return TRUE;

 fail:
  if (key)
    RegCloseKey(key);
  return FALSE;
}

/*
 * Get a TCHAR string value from within the HKLM registry subtree into
 * the given buffer. Return TRUE on success.
 */
static BOOL get_reg_sz(const TCHAR *subkey, const TCHAR *value_name,
                       TCHAR *string, DWORD maxlen)
{
  HKEY key = NULL;
  DWORD type, size, code;

  if ((code = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        subkey,
        0,
        0,
        &key)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegOpenKeyEx: %s"), subkey);
      goto fail;
    }

  if ((code = RegQueryValueEx(
        key,
        value_name,
        NULL,
        &type,
        NULL,
        &size)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegQueryValueEx: %s"), value_name);
      goto fail;

    }

  if (type != REG_SZ)
    goto fail;

  if (size > maxlen * sizeof string[0])
    goto fail;

  if ((code = RegQueryValueEx(
        key,
        value_name,
        NULL,
        &type,
        (BYTE *)string,
        &size)) != ERROR_SUCCESS)
    {
      error_code(code, _T("RegQueryValueEx: %s"), value_name);
      goto fail;

    }

  string[maxlen - 1] = _T('\0');
  RegCloseKey(key);
  return TRUE;

 fail:
  if (key)
    RegCloseKey(key);
  return FALSE;
}

/*
 * Set or create a TCHAR string value in registry under the HKLM
 * subtree. Return TRUE on success.
 */
static BOOL set_reg_sz(const TCHAR *subkey, const TCHAR *value_name,
                       TCHAR *string)
{
  HKEY key = NULL;
  DWORD size, code;

  if ((code = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        subkey,
        0,
        NULL,
        0,
        0,
        NULL,
        &key,
        NULL)) != ERROR_SUCCESS)
    {
      error_code(code, _T("RegCreateKeyEx: %s"), subkey);
      goto fail;
    }

  size = (_tcslen(string) + 1) * sizeof(TCHAR);

  if ((code = RegSetValueEx(
        key,
        value_name,
        0,
        REG_SZ,
        (BYTE *)string,
        size)) != ERROR_SUCCESS)
    {
      error_code(code, _T("RegSetValueEx: %s"), value_name);
      goto fail;
    }

  RegCloseKey(key);
  return TRUE;

 fail:
  if (key)
    RegCloseKey(key);
  return FALSE;
}

/*
 * Delete registry value within the HKLM subtree. Return TRUE on
 * success.
 */
static BOOL delete_reg_value(const TCHAR *subkey, const TCHAR *value_name)
{
  HKEY key = NULL;
  DWORD code;

  if ((code = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        subkey,
        0,
        0,
        &key)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegOpenKeyEx: %s"), subkey);
      goto fail;
    }

  if ((code = RegDeleteValue(
        key,
        value_name)) != ERROR_SUCCESS)
    {
      error_code(code, _T("RegDeleteValue: %s"), value_name);
      goto fail;
    }

  RegCloseKey(key);
  return TRUE;

 fail:
  if (key)
    RegCloseKey(key);
  return FALSE;
}

/*
 * Delete registry subkey within the HKLM subtree. Return TRUE on
 * success.
 */
static BOOL delete_reg_subkey(const TCHAR *subkey)
{
  DWORD code;

  if ((code = RegDeleteKey(HKEY_LOCAL_MACHINE, subkey)) != ERROR_SUCCESS)
    {
      if (code != ERROR_FILE_NOT_FOUND)
        error_code(code, _T("RegDeleteKey: %s"), subkey);
      return FALSE;
    }
  return TRUE;
}

/*
 * Read contents of an ASCII file into the given buffer as a
 * null-terminated TCHAR string. Return TRUE on success.
 */
static BOOL get_file(const TCHAR *path, TCHAR *string, DWORD maxlen)
{
  HANDLE h = INVALID_HANDLE_VALUE;
  char buffer[1024];
  DWORD size, read, rpos;

  if ((h = CreateFile(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        0,
        NULL)) == INVALID_HANDLE_VALUE)
    {
      if (GetLastError() != ERROR_FILE_NOT_FOUND)
        error_system(_T("CreateFile: %s"), path);
      goto fail;
    }

  if ((size = GetFileSize(h, NULL)) == 0xffffffff)
    {
      error_system(_T("GetFileSize: %s"), path);
      goto fail;
    }

  if (size + 1 > maxlen)
    {
      error(_T("%s: file too large"), path);
      goto fail;
    }

  rpos = 0;
  while (rpos < size)
    {
      if (!ReadFile(h, buffer, sizeof buffer, &read, NULL))
        {
          error_system(_T("ReadFile: %s"), path);
          goto fail;
        }
      if (read == 0)
        break;
      memset(string + rpos, 0, read);
      _sntprintf(string + rpos, read, _T("%hs"), buffer);
      rpos += read;
    }
  string[rpos] = _T('\0');

  CloseHandle(h);
  return TRUE;

fail:
  if (h != INVALID_HANDLE_VALUE)
    CloseHandle(h);
  return FALSE;
}

/*
 * Replace the contents of an ASCII file by the specified string
 * converted to ASCII. The terminating null character is not written
 * to the file.  null-terminate. Return TRUE on success. If the file
 * cannot be replaced because it is in use, try to rename the file and
 * write a new one.
 */
static BOOL set_file(const TCHAR *path, const TCHAR *string)
{
  DWORD string_len = _tcslen(string), wpos, towrite, written;
  HANDLE h = NULL;
  TCHAR path_new[256], path_old[256];
  char buffer[1024];
  BOOL new_created = FALSE;

  if (_tcslen(path) + 1 > sizeof path_new / sizeof path_new[0])
    {
      error_system(_T("%s: path too long"), path);
      goto fail;
    }

  _tcscpy(path_new, path);
  path_new[_tcslen(path_new) - 1] = _T('+');
  _tcscpy(path_old, path);
  path_old[_tcslen(path_old) - 1] = _T('_');

  /*
   * First write a new file containing the string. The name of the
   * file is the same as the name of the target file except that the
   * last character is replaced by a '+' character.
   */

  if ((h = CreateFile(
        path_new,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        0,
        NULL)) == INVALID_HANDLE_VALUE)
    {
      error_system(_T("CreateFile: %s"), path_new);
      goto fail;
    }
  new_created = TRUE;

  wpos = 0;
  while (wpos < string_len)
    {
      towrite = string_len - wpos;
      if (towrite > sizeof buffer)
        towrite = sizeof buffer;

      _snprintf(buffer, towrite, "%ls", string + wpos);

      if (!WriteFile(
            h,
            buffer,
            towrite,
            &written,
            NULL))
        {
          error_system(_T("WriteFile: %s"), path_new);
          goto fail;
        }
      if (written != towrite)
        {
          error_system(_T("%s: short write"), path_new);
          goto fail;
        }
      wpos += towrite;
    }

  CloseHandle(h);
  h = INVALID_HANDLE_VALUE;

  /*
   * Try to replace the target file with the new one.
   */

  if (!DeleteFile(path))
    {
      if (GetLastError() != ERROR_FILE_NOT_FOUND &&
          GetLastError() != ERROR_SHARING_VIOLATION)
        {
          error_system(_T("DeleteFile: %s"), path);
          goto fail;
        }
      if (GetLastError() == ERROR_SHARING_VIOLATION)
        {
          if (!DeleteFile(path_old))
            {
              if (GetLastError() != ERROR_FILE_NOT_FOUND)
                {
                  error_system(_T("DeleteFile: %s"), path_old);
                  goto fail;
                }
            }
          if (!MoveFile(path, path_old))
            {
              error_system(_T("MoveFile: %s"), path);
              goto fail;
            }
        }
    }

  if (!MoveFile(path_new, path))
    {
      error_system(_T("MoveFile: %s"), path);
      goto fail;
    }

  return TRUE;

fail:
  if (new_created)
    DeleteFile(path_new);
  if (h != INVALID_HANDLE_VALUE)
    CloseHandle(h);
  return FALSE;
}

/*
 * Periodic update of the policy manager process id variable
 * (pm_pid_current). Previous value is saved into pm_pid_previous. The
 * pid is read from registry and if the process is running (i.e. it
 * can be opened) the that pid is used. If no pid can be found or the
 * process is not running, pm_pid_current is set to zero.
 */
static void update_pid(void)
{
  DWORD pid;
  HANDLE h;

  if (!get_reg_dword(reg_app_subkey, _T("PolicyManagerPid"), &pid))
    goto fail;

  if (!(h = OpenProcess(0, FALSE, pid)))
    goto fail;

  CloseHandle(h);

  pm_pid_previous = pm_pid_current;
  pm_pid_current = pid;
  return;

 fail:
  pm_pid_previous = pm_pid_current;
  pm_pid_current = 0;
}

/*
 * Periodic check of the point-to-point message queue between this app
 * and the policy manager process. The queue will be opened/reopened
 * if it seems that a new policy manager process is running.
 */
static void update_control(void)
{
  MSGQUEUEOPTIONS mqo;

  if (control_handle && pm_pid_current != pm_pid_previous)
    {
      if (!CloseMsgQueue(control_handle))
        /* error_system(_T("CloseMsgQueue: %s"), control_queue_name) */;
      control_handle = NULL;
    }

  if (!pm_pid_current)
    return;

  if (control_handle)
    return;

  memset(&mqo, 0, sizeof mqo);
  mqo.dwSize = sizeof mqo;
  mqo.dwFlags = 0;
  mqo.dwMaxMessages = 1;
  mqo.cbMaxMessage = 1024;
  mqo.bReadAccess = FALSE;

  if (!(control_handle = CreateMsgQueue(control_queue_name, &mqo)))
    error_system(_T("CreateMsgQueue: %ls"), control_queue_name);
}

/*
 * Periodic update of the policy manager and interceptor status text
 * fields.
 */
static void update_status(void)
{
  if (pm_status_window)
    {
      if (pm_pid_current)
        SendMessage(pm_status_window, WM_SETTEXT, 0, (LPARAM)_T("Running"));
      else
        SendMessage(pm_status_window, WM_SETTEXT, 0,(LPARAM)_T("Not running"));
    }

  if (icept_status_window)
    {
      SendMessage(icept_status_window, WM_SETTEXT, 0,(LPARAM)_T("Unknown"));
    }
}

/*
 * Periodic update of the log file display.
 */
static void update_log(void)
{
  HANDLE h;
  DWORD size, desired, actual, remove;

  /*
   * Close log if a new policy manager process has started.
   */
  if (log_handle &&
      pm_pid_current != pm_pid_previous &&
      pm_pid_current)
    {
      if (!CloseHandle(log_handle))
        error_system(_T("CloseHandle: %s"), log_path);
      log_handle = NULL;
      log_position = 0;
      SendMessage(edit_window, WM_SETTEXT, 0, (LPARAM)_T(""));
      edit_length = 0;
    }

  /*
   * If no log is open try opening one, regardless of whether the
   * policy manager is running or not.
   */
  if (!log_handle)
    {
      if (!get_reg_sz(reg_app_subkey, _T("OutputFile"),
                      log_path, sizeof log_path / sizeof log_path[0]))
        return;

      if ((h = CreateFile(
            log_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL)) == INVALID_HANDLE_VALUE)
        {
          if (GetLastError() != ERROR_FILE_NOT_FOUND)
            error_system(_T("CreateFile: %s"), log_path);
          return;
        }
      log_handle = h;
    }

  /*
   * Get up-to-date file size.
   */
  if ((size = GetFileSize(log_handle, NULL)) == 0xffffffff)
    {
      error_system(_T("GetFileSize: %s"), log_path);
      goto fail;
    }

  /*
   * If nothing has been displayed yet and the file is big, skip
   * reading the portion that will not fit in the display buffer.
   */
  if (log_position == 0 && size > edit_maxlength)
    {
      if (SetFilePointer(log_handle, -(LONG)edit_maxlength, NULL,
                         FILE_END) == 0xffffffff)
        {
          error_system(_T("SetFilePointer: %s"), log_path);
          goto fail;
        }
      log_position = size - edit_maxlength;
    }

  /*
   * Get the unread portion of the file, one LOG_BUFFER_SIZE long
   * buffer at a time.
   */
  while (log_position < size)
    {
      desired = size - log_position;

      if (desired > LOG_BUFFER_SIZE - 1)
        desired = LOG_BUFFER_SIZE - 1;

      if (!ReadFile(log_handle, log_buffer, desired, &actual, NULL))
        {
          error_system(_T("ReadFile: %s"), log_path);
          goto fail;
        }

      if (actual == 0)
        break;

      log_position += actual;

      log_buffer[actual] = '\0';
      _sntprintf(log_tbuffer, LOG_BUFFER_SIZE, _T("%hs"), log_buffer);
      log_tbuffer[LOG_BUFFER_SIZE - 1] = _T('\0');

      /*
       * Update display. If the display buffer would exceed its
       * maximum length, first remove some text from the beginning.
       */
      if (edit_length + actual > edit_maxlength)
        {
          remove = edit_length + actual - edit_maxlength;
          SendMessage(edit_window, EM_SETSEL, (WPARAM)0, (LPARAM)remove);
          SendMessage(edit_window, EM_REPLACESEL, FALSE, (LPARAM)_T(""));
          edit_length -= remove;
          SendMessage(edit_window, EM_SETSEL,
                      (WPARAM)edit_length, (LPARAM)edit_length);
        }
      
      SendMessage(edit_window, EM_REPLACESEL, FALSE, (LPARAM)log_tbuffer);
      edit_length += actual;
    }

  return;

 fail:
  if (!CloseHandle(log_handle))
    error_system(_T("CloseHandle: %s"), log_path);
  log_handle = NULL;
  log_position = 0;
  SendMessage(edit_window, WM_SETTEXT, 0, (LPARAM)_T(""));
  edit_length = 0;
}

/*
 * Periodic update procedure.
 */
static void periodic_proc(HWND hwnd, UINT uMsg, UINT idEvent, DWORD dwTime)
{
  if (periodic_busy)
    return;

  periodic_busy = 1;

  update_pid();
  update_control();
  update_status();
  update_log();

  periodic_busy = 0;
}

/*
 * Init window layout.
 */
static void init_empty_area(void)
{
  LONG l;
  RECT rect;

  l = GetDialogBaseUnits();
  char_width = LOWORD(l);
  char_height = HIWORD(l);

  first_x = char_width;
  next_y = 0;

  GetClientRect(main_window, &rect);
  available_width = rect.right - rect.left - 2 * char_width;
  available_height = rect.bottom - rect.top;
}

/*
 * Create a menu bar.
 */
static BOOL create_menubar(void)
{
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)

  SHMENUBARINFO mbi;
#if defined(WIN32_PLATFORM_PSPC)
  RECT rect_main, rect_menubar;
#endif

  memset(&mbi, 0, sizeof mbi);
  mbi.cbSize = sizeof mbi;
  mbi.hwndParent = main_window;
  mbi.nToolBarId = IDR_MENU;
  mbi.hInstRes = application_instance;

  if (!SHCreateMenuBar(&mbi))
    {
      error(_T("Cannot create menubar"));
      return FALSE;
    }

  menubar_window = mbi.hwndMB;

#if defined(WIN32_PLATFORM_PSPC)

  GetClientRect(main_window, &rect_main);
  GetClientRect(menubar_window, &rect_menubar);

  rect_main.bottom -= rect_menubar.bottom - rect_menubar.top;
  available_height -= rect_menubar.bottom - rect_menubar.top;

  SetWindowPos(
    main_window,
    NULL,
    0,
    0,
    rect_main.right - rect_main.left,
    rect_main.bottom - rect_main.top,
    SWP_NOMOVE | SWP_NOZORDER);

#endif

  return TRUE;

#else

  RECT rect_menubar;

  if (!(menubar_window = CommandBar_Create(
        application_instance,
        main_window, CHILD_ID_MENUBAR)))
    {
      error_system(_T("CommandBar_Create"));
      return FALSE;
    }

  if (!CommandBar_InsertMenubar(
        menubar_window, application_instance,
        IDR_MENU,
        0))
    {
      error_system(_T("CommandBar_InsertMenubar"));
      return FALSE;
    }

  if (!CommandBar_AddAdornments(menubar_window, 0, 0))
    error_system(_T("CommandBar_AddAdornments"));

  GetClientRect(menubar_window, &rect_menubar);
  next_y += rect_menubar.bottom - rect_menubar.top;
  available_height -= rect_menubar.bottom - rect_menubar.top;

  return TRUE;

#endif
}

/*
 * Create policy manager and interceptor status text fields.
 */
static BOOL create_status(void)
{
  HDC dc;
  TCHAR *label;
  DWORD next_x;
  int label_width, value_width, remaining_width, height;
  SIZE size;
  HWND w;

  if (!(dc = GetDC(main_window)))
    {
      error_system(_T("GetDC: main_window"));
      return FALSE;
    }

  remaining_width = available_width;
  next_x = first_x;

  label = _T("Policy Manager:  ");
  if (!GetTextExtentPoint32(dc, label, _tcslen(label), &size))
    {
      error_system(_T("GetTextExtentPoint32: pm_status_label"));
      return FALSE;
    }
  height = size.cy;
  label_width = size.cx;
  value_width = 12 * char_width;

  if (!(w = CreateWindow(
        _T("static"),
        NULL,
        WS_CHILD | WS_VISIBLE,
        next_x,
        next_y + char_height,
        label_width,
        height,
        main_window,
        NULL,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: pm_status_label"));
      return FALSE;
    }
  SendMessage(w, WM_SETTEXT, 0, (LPARAM)label);

  next_x += label_width;
  remaining_width -= label_width;

  if (!(pm_status_window = CreateWindow(
        _T("static"),
        NULL,
        WS_CHILD | WS_VISIBLE,
        next_x,
        next_y + char_height,
        value_width,
        height,
        main_window,
        NULL,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: pm_status_window"));
      return FALSE;
    }

  next_x += value_width;
  remaining_width -= value_width;

#if 0
  label = _T("Engine: ");
  if (!GetTextExtentPoint32(dc, label, _tcslen(label), &size))
    {
      error_system(_T("GetTextExtentPoint32: icept_status_label"));
      return FALSE;
    }
  height = size.cy;
  label_width = size.cx;
  value_width = 12 * char_width;

  if (remaining_width < label_width + value_width)
    {
      next_x = first_x;
      remaining_width = available_width;
      next_y += 2 * char_height;
      available_height -= 2 * char_height;
    }

  if (!(w = CreateWindow(
        _T("static"),
        NULL,
        WS_CHILD | WS_VISIBLE,
        next_x,
        next_y + char_height,
        label_width,
        char_height,
        main_window,
        NULL,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: icept_status_label"));
      return FALSE;
    }
  SendMessage(w, WM_SETTEXT, 0, (LPARAM)label);

  next_x += label_width;
  remaining_width -= label_width;

  if (!(icept_status_window = CreateWindow(
        _T("static"),
        NULL,
        WS_CHILD | WS_VISIBLE,
        next_x,
        next_y + char_height,
        value_width,
        char_height,
        main_window,
        NULL,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: icept_status_window"));
      return FALSE;
    }
#endif /* 0 */

  next_y += char_height + char_height;
  available_height -= char_height + char_height;

  return TRUE;
}

/*
 * Create the log file display area.
 */
static BOOL create_edit(void)
{
  int height;

  height = available_height - 2 * char_height;

  if (!(edit_window = CreateWindow (
        _T("edit"),
        NULL,
        WS_CHILD | WS_VISIBLE | WS_HSCROLL | WS_VSCROLL |
        WS_BORDER | ES_LEFT | ES_MULTILINE | ES_NOHIDESEL |
        ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_READONLY,
        first_x,
        next_y + char_height,
        available_width,
        height,
        main_window,
        (HMENU)CHILD_ID_EDIT,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: edit_window"));
      return FALSE;
    }

  next_y += available_height;
  available_height -= available_height;
  return TRUE;
}

/*
 * Start the policy manager process if not already running.
 */
static void start_pm(void)
{
  PROCESS_INFORMATION pi;

  if (pm_pid_current)
    return;

  if (log_handle)
    {
      if (!CloseHandle(log_handle))
        {
          error_system(_T("CloseHandle: %s"), log_path);
          return;
        }
      log_handle = NULL;
      log_position = 0;

      SendMessage(edit_window, WM_SETTEXT, 0, (LPARAM)_T(""));
      edit_length = 0;

      if (!DeleteFile(log_path))
        {
          error_system(_T("DeleteFile: %s"), log_path);
          return;
        }
    }

  if (!CreateProcess(
        exec_path,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        NULL,
        &pi))
    {
      error_system(_T("CreateProcess: %s"), exec_path);
      return;
    }

  if (!CloseHandle(pi.hProcess))
      error_system(_T("CloseHandle: %s"), exec_path);

  if (!CloseHandle(pi.hThread))
      error_system(_T("CloseHandle: %s"), exec_path);
}

/*
 * Subroutine for EnumWindows(). If the process id corresponding to
 * the window being enumerated matches the process id given as
 * parameter then send a SIGINT emulation message to it and stop
 * enumeration.
 */
static BOOL interrupt_pm_proc(HWND hwnd, LPARAM lparam)
{
  DWORD pid;

  GetWindowThreadProcessId(hwnd, &pid);

  if (pid != lparam)
    return TRUE;

  if (!PostMessage(hwnd, pm_signal_msg, 2, 0))
    error_system(_T("PostMessage"));

  return FALSE;
}

/*
 * Send an interrupt to the policy manager process.
 */
static void interrupt_pm(void)
{
  if (!pm_pid_current)
    return;

  if (!EnumWindows(interrupt_pm_proc, pm_pid_current))
    error_system(_T("EnumWindows"));
}

/*
 * Terminate the policy manager process.
 */
static void terminate_pm(void)
{
  HANDLE h;

  if (!pm_pid_current)
    return;

  if (!(h = OpenProcess(0, FALSE, pm_pid_current)))
    {
      error_system(_T("OpenProcess: %s"), exec_path);
      return;
    }

  if (!TerminateProcess(h, 1))
    error_system(_T("TerminateProcess: %s"), exec_path);

  if (!CloseHandle(h))
    error_system(_T("CloseHandle: %s"), exec_path);
}

/*
 * Send a control message with no data to the policy manager process.
 */
static void control_nodata(DWORD message_type)
{
  control_msg_t msg;

  if (!control_handle)
    return;

  memset(&msg, 0, sizeof msg);
  msg.type = message_type;

  if (!WriteMsgQueue(control_handle, &msg, sizeof msg, 0, 0))
    error_system(_T("WriteMsgQueue"));
}

/*
 * Send a control message with string data to the policy manager
 * process.
 */
static void control_string(DWORD message_type, TCHAR *string)
{
  control_msg_t msg;

  if (!control_handle)
    return;

  memset(&msg, 0, sizeof msg);
  msg.type = message_type;

  if (_tcslen(string) >= sizeof msg.u.string)
    {
      error(_T("Debug string too long"));
      return;
    }

  _snprintf(msg.u.string, sizeof msg.u.string, "%ls", string);

  if (!WriteMsgQueue(control_handle, &msg, sizeof msg, 0, 0))
    error_system(_T("WriteMsgQueue"));
}

/*
 * Load the interceptor.
 */
static void load_icept(void)
{
  error(_T("Not implemented yet"));
}

/*
 * Unload the interceptor.
 */
static void unload_icept(void)
{
  error(_T("Not implemented yet"));
}

/*
 * Center or otherwise initialize a dialog window.
 */
static void init_dialog(HWND dialog, TCHAR *title)
{
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)

  HWND title_window;
  SHINITDLGINFO idi;
  SHMENUBARINFO mbi;
#if defined(WIN32_PLATFORM_WFSP)
  RECT rect_dialog, rect_menubar;
#endif

  if ((title_window = GetDlgItem(dialog, IDD_TITLE)))
    SendMessage(title_window, WM_SETTEXT, 0, (LPARAM)title);

  memset(&idi, 0, sizeof idi);
  idi.dwMask = SHIDIM_FLAGS;
  idi.hDlg = dialog;
#if defined(WIN32_PLATFORM_WFSP)
  idi.dwFlags = SHIDIF_SIZEDLGFULLSCREEN;
#else
  idi.dwFlags = SHIDIF_SIZEDLGFULLSCREEN | SHIDIF_DONEBUTTON;
#endif
  if (!SHInitDialog(&idi))
    error(_T("Cannot create dialog"));

  memset(&mbi, 0, sizeof mbi);
  mbi.cbSize = sizeof mbi;
  mbi.hwndParent = dialog;
#if defined(WIN32_PLATFORM_WFSP)
  mbi.dwFlags = 0;
  mbi.nToolBarId = IDR_DMENU;
#else
  mbi.dwFlags = SHCMBF_EMPTYBAR;
  mbi.nToolBarId = 0;
#endif
  mbi.hInstRes = application_instance;

  if (!SHCreateMenuBar(&mbi))
      error(_T("Cannot create menubar"));

#if defined(WIN32_PLATFORM_WFSP)

  /*
   * Smartphone: resize the window so that menu bar will not obscure
   * it. Also override the default back key behavior so that a
   * WM_HOTKEY message will be sent when it is pressed.
   */

  if (mbi.hwndMB)
    {
      GetClientRect(dialog, &rect_dialog);
      GetClientRect(mbi.hwndMB, &rect_menubar);

      rect_dialog.bottom -= rect_menubar.bottom - rect_menubar.top;

      SetWindowPos(
        dialog,
        NULL,
        0,
        0,
        rect_dialog.right - rect_dialog.left,
        rect_dialog.bottom - rect_dialog.top,
        SWP_NOMOVE | SWP_NOZORDER);

      SendMessage(mbi.hwndMB, SHCMBM_OVERRIDEKEY, VK_TBACK,
                  MAKELPARAM(SHMBOF_NODEFAULT | SHMBOF_NOTIFY,
                             SHMBOF_NODEFAULT | SHMBOF_NOTIFY));
    }

#endif

#else

  RECT rect_dialog, rect_parent;
  DWORD cxd, cxp, cyd, cyp;

  SetWindowText(dialog, title);

  GetClientRect(GetParent(dialog), &rect_parent);
  cxp = rect_parent.right - rect_parent.left;
  cyp = rect_parent.bottom - rect_parent.top;

  GetClientRect(dialog, &rect_dialog);
  cxd = rect_dialog.right - rect_dialog.left;
  cyd = rect_dialog.bottom - rect_dialog.top;

  SetWindowPos(
    dialog,
    NULL,
    (cxp - cxd) / 2,
    (cyp - cyd) / 2,
    0,
    0,
    SWP_NOACTIVATE | SWP_NOSIZE | SWP_NOZORDER);

#endif
}

/*
 * Resize a window to the right and downwards to fill its
 * parent. Assume the child is positioned with a one-character margin
 * and leave also one-character margin on the right and down.
 */
static void fill_parent(HWND window)
{
  RECT rect;
  RECT rect_parent;

  GetClientRect(window, &rect);
  GetClientRect(GetParent(window), &rect_parent);

  rect.right = rect_parent.right - 2 * char_width;
  rect.bottom = rect_parent.right - 2 * char_height;

  SetWindowPos(
    window,
    NULL,
    0,
    0,
    rect.right - rect.left,
    rect.bottom - rect.top,
    SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER);
}

/*
 * String-editing dialog procedure.
 */
static BOOL CALLBACK dialog_proc(HWND dialog, UINT msg,
                                 WPARAM wparam, LPARAM lparam)
{
  dialog_param_t *dp;
  HWND string_window;

  switch (msg)
    {
    case WM_INITDIALOG:
      dp = (dialog_param_t *)lparam;
      SetWindowLong(dialog, DWL_USER, (LONG)dp);

      init_dialog(dialog, dp->title);
      if (!(string_window = GetDlgItem(dialog, IDD_STRING)))
        {
          error(_T("Cannot find edit control in dialog"));
          SendMessage(dialog, WM_CLOSE, 0, 0);
          return FALSE;
        }
      fill_parent(string_window);

      SendMessage(string_window, WM_SETTEXT, 0, (LPARAM)dp->string);
      PostMessage(string_window, EM_SETSEL, (WPARAM)0, (LPARAM)0);
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
      memset(&dialog_activate_info, 0, sizeof dialog_activate_info);
      dialog_activate_info.cbSize = sizeof dialog_activate_info;
#endif
      return TRUE;
      break;

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
    case WM_ACTIVATE:
      SHHandleWMActivate(dialog, wparam, lparam, &dialog_activate_info, 0);
      return 0;
#endif

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
    case WM_SETTINGCHANGE:
      SHHandleWMSettingChange(dialog, wparam, lparam, &dialog_activate_info);
      return 0;
#endif

    case WM_COMMAND:
      switch(LOWORD(wparam))
        {
        case IDOK:
          dp = (dialog_param_t *)GetWindowLong(dialog, DWL_USER);

          if ((string_window = GetDlgItem(dialog, IDD_STRING)))
            SendMessage(
              string_window,
              WM_GETTEXT,
              (WPARAM)(sizeof dp->string / sizeof dp->string[0]),
              (LPARAM)dp->string);

          EndDialog(dialog, 0);
          return TRUE;

        case IDCANCEL:
          EndDialog(dialog, 0);
          return TRUE;
        }
      break;

    case WM_USER:
      /*
       * Standard SDK: Multiline edit control does not recognize the
       * OK button in the caption as the default pushbutton, i.e. when
       * the enter key is pressed it sends a WM_USER event.
       */
      dp = (dialog_param_t *)GetWindowLong(dialog, DWL_USER);

      if ((string_window = GetDlgItem(dialog, IDD_STRING)))
        SendMessage(
          string_window,
          WM_GETTEXT,
          (WPARAM)(sizeof dp->string / sizeof dp->string[0]),
           (LPARAM)dp->string);

      EndDialog(dialog, 0);
      return TRUE;        

#if defined(WIN32_PLATFORM_WFSP)
    case WM_HOTKEY:
      if (HIWORD(lparam) == VK_TBACK)
        {
          SHSendBackToFocusWindow(msg, wparam, lparam);
          return TRUE;
        }
      break;
#endif

    case WM_CLOSE:
      EndDialog(dialog, 0);
      return TRUE;
    }

    return FALSE;
}

/*
 * Event handler.
 */
static LRESULT CALLBACK window_proc(HWND window, UINT msg,
                                    WPARAM wparam, LPARAM lparam)
{
  dialog_param_t dp;

  switch (msg)
    {
    case WM_CREATE:
      main_window = window;
      init_empty_area();
      if (!create_menubar() ||
          !create_status() ||
          !create_edit())
        return -1;
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
      memset(&activate_info, 0, sizeof activate_info);
      activate_info.cbSize = sizeof activate_info;
#endif
      return 0;

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
    case WM_ACTIVATE:
      SHHandleWMActivate(window, wparam, lparam, &activate_info, 0);
      return 0;
#endif

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
    case WM_SETTINGCHANGE:
      SHHandleWMSettingChange(window, wparam, lparam, &activate_info);
      return 0;
#endif

    case WM_CLOSE:
      DestroyWindow(main_window);
      return 0;

    case WM_DESTROY:
      PostQuitMessage(0);
      return 0;

    case WM_CTLCOLORSTATIC:
      if ((HWND)lparam == edit_window)
        return (LRESULT)GetStockObject(WHITE_BRUSH);
      else
        break;

    case WM_COMMAND:
      switch (LOWORD(wparam))
        {
        case IDM_PM_START:
          start_pm();
          return 0;

        case IDM_PM_STOP:
          control_nodata(CONTROL_MSG_STOP);
          return 0;

        case IDM_PM_RECONFIGURE:
          control_nodata(CONTROL_MSG_RECONFIGURE);
          return 0;

        case IDM_PM_REDO_FLOWS:
          control_nodata(CONTROL_MSG_REDO_FLOWS);
          return 0;







        case IDM_PM_INTERRUPT:
          interrupt_pm();
          return 0;

        case IDM_PM_TERMINATE:
          terminate_pm();
          return 0;

        case IDM_ICEPT_LOAD:
          load_icept();
          return 0;

        case IDM_ICEPT_UNLOAD:
          unload_icept();
          return 0;

        case IDM_PM_ARGUMENTS:
          dp.title = _T("PM Arguments");
          dp.string[0] = _T('\0');
          get_reg_sz(reg_app_subkey, _T("Arguments"),
                     dp.string, sizeof dp.string / sizeof dp.string[0]);
          DialogBoxParam(
                application_instance,
                (TCHAR *)IDR_DIALOG,
                main_window,
                dialog_proc,
                (LPARAM)&dp);
          set_reg_sz(reg_app_subkey, _T("Arguments"), dp.string);
          return 0;

        case IDM_PM_CONFIGFILE:
          dp.title = _T("PM Config File");
          dp.string[0] = _T('\0');
          if (!get_file(config_path,
                        dp.string, sizeof dp.string / sizeof dp.string[0]))
            return 0;
          DialogBoxParam(
                application_instance,
                (TCHAR *)IDR_FDIALOG,
                main_window,
                dialog_proc,
                (LPARAM)&dp);
          set_file(config_path, dp.string);
          return 0;

        case IDM_PM_DEBUGSTRING:
          dp.title = _T("PM Debug String");
          dp.string[0] = _T('\0');
          get_reg_sz(reg_app_subkey, _T("UserModeDebugString"),
                     dp.string, sizeof dp.string / sizeof dp.string[0]);
          DialogBoxParam(
                application_instance,
                (TCHAR *)IDR_DIALOG,
                main_window,
                dialog_proc,
                (LPARAM)&dp);
          set_reg_sz(reg_app_subkey, _T("UserModeDebugString"), dp.string);
          control_string(CONTROL_MSG_DEBUGSTRING_USERMODE, dp.string);
          return 0;

        case IDM_ICEPT_DEBUGSTRING:
          dp.title = _T("Engine Debug String");
          dp.string[0] = _T('\0');
          get_reg_sz(reg_app_subkey, _T("KernelModeDebugString"),
                     dp.string, sizeof dp.string / sizeof dp.string[0]);
          DialogBoxParam(
                application_instance,
                (TCHAR *)IDR_DIALOG,
                main_window,
                dialog_proc,
                (LPARAM)&dp);
          set_reg_sz(reg_app_subkey, _T("KernelModeDebugString"), dp.string);
          control_string(CONTROL_MSG_DEBUGSTRING_KERNELMODE, dp.string);
          return 0;

        case IDM_FILE_CLEAR:
          SendMessage(edit_window, WM_SETTEXT, 0, (LPARAM)_T(""));
          edit_length = 0;
          return 0;

        case IDOK:
        case IDM_FILE_QUIT:
#if defined(WIN32_PLATFORM_WFSP)
        case IDM_QUIT:
#endif
          SendMessage(window, WM_CLOSE, 0, 0);
          return 0;
        }
      break;
    }

  return DefWindowProc(main_window, msg, wparam, lparam);
}

/*
 * Program start.
 */
int WINAPI WinMain(HINSTANCE instance,
                   HINSTANCE prev_instance,
                   LPWSTR cmd_line,
                   int cmd_show)
{
  HWND w;
  WNDCLASS wc;
#if !defined(WIN32_PLATFORM_WFSP) && !defined(WIN32_PLATFORM_PSPC)
  HACCEL accel;
#endif
  MSG msg;
  int result = 0;

  SetLastError(ERROR_SUCCESS);

  application_instance = instance;

  /*
   * If the program is already running, just bring it to foreground.
   */
  if ((w = FindWindow(application_name, application_name)))
    {
      SetForegroundWindow((HWND)((DWORD)w | 0x00000001));
      return 0;
    }

  /*
   * Register application class.
   */
  wc.style = CS_HREDRAW | CS_VREDRAW;
  wc.lpfnWndProc = window_proc;
  wc.cbClsExtra = 0;
  wc.cbWndExtra = 0;
  wc.hInstance = application_instance;
  wc.hIcon = NULL;
  wc.hCursor = LoadCursor(NULL, IDC_ARROW);
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
  wc.hbrBackground = (HBRUSH) GetStockObject(WHITE_BRUSH);
#else
  wc.hbrBackground = (HBRUSH)(COLOR_WINDOW);
#endif
  wc.lpszMenuName = NULL;
  wc.lpszClassName = application_name;

  if (!RegisterClass(&wc))
    {
      error_system(_T("RegisterClass"));
      goto end;
    }

  /*
   * Register signal emulation message.
   */
  if (!(pm_signal_msg = RegisterWindowMessage(_T("SSH SIGNAL MESSAGE"))))
    {
      error_system(_T("RegisterWindowMessage"));
      goto end;
    }

  /*
   * Create main window.
   */
  if (!(main_window = CreateWindow(
        application_name,
        application_name,
        WS_VISIBLE,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        NULL,
        NULL,
        application_instance,
        NULL)))
    {
      error_system(_T("CreateWindow: main_window"));
      goto end;
    }

  if (!SetFocus(edit_window))
    {
      error_system(_T("SetFocus: main_window"));
      goto end;
    }

#if !defined(WIN32_PLATFORM_WFSP) && !defined(WIN32_PLATFORM_PSPC)
  /*
   * Load accelerator keys.
   */
  if (!(accel = LoadAccelerators(application_instance, (LPCTSTR)IDR_ACCEL)))
    {
      error_system(_T("LoadAccelerators"));
      goto end;
    }
#endif

  /*
   * Make main window visible.
   */
  ShowWindow(main_window, cmd_show);
  UpdateWindow(main_window);

  /*
   * Start periodic timer.
   */
  if (!(periodic_timer = SetTimer(NULL, 0, 1000, periodic_proc)))
    {
      error_system(_T("SetTimer"));
      goto end;
    }

  /*
   * Run until WM_QUIT received.
   */
  while (GetMessage(&msg, NULL, 0, 0))
    {
#if !defined(WIN32_PLATFORM_WFSP) && !defined(WIN32_PLATFORM_PSPC)
      if (TranslateAccelerator(main_window, accel, &msg))
        continue;
#endif

      TranslateMessage(&msg);
      DispatchMessage(&msg);
    }

  /*
   * Return whatever was in WM_QUIT.
   */
  result = msg.wParam;

 end:
  if (periodic_timer)
    KillTimer(NULL, periodic_timer);

  if (control_handle)
    CloseMsgQueue(control_handle);

  if (log_handle)
    CloseHandle(log_handle);

  return result;
}

#else /* _WIN32_WCE */

#include <windows.h>

int WINAPI WinMain(HINSTANCE instance,
                   HINSTANCE prev_instance,
                   LPTSTR cmd_line,
                   int cmd_show)
{
  MessageBox(
    NULL,
    TEXT("Application supported on Windows CE only"),
    TEXT("QSConsole"),
    MB_OK);

  return 0;
}

#endif /* _WIN32_WCE */
