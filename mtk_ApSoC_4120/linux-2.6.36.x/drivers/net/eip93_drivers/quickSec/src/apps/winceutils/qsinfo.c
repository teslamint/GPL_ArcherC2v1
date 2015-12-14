/*
 *
 * qsinfo.c
 *
 *  Copyright:
 *          Copyright (c) 2007 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Information retrieval utility for Windows CE.
 *
 */

#ifdef _WIN32_WCE

#include <windows.h>
#include <commctrl.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2")
#include <iphlpapi.h>
#pragma comment(lib, "iphlpapi")
#include <pm.h>
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
#include <eap.h>
#if _WIN32_CE >= 0x502
#include <wzcsapi.h>
#pragma comment(lib, "wzcsapi")
#endif
#include <aygshell.h>
#include <tpcshell.h>
#pragma comment(lib, "aygshell")
#include <connmgr.h>
#include <connmgr_status.h>
#pragma comment(lib, "cellcore")
#endif
#include <ntddndis.h>
#include <nuiouser.h>
#include "qsinfo.h"

/*
 * This application.
 */
static TCHAR *application_name = _T("QSInfo");

/*
 * Various window etc.  handles.
 */
static HINSTANCE application_instance;
static HWND main_window;
static HWND menubar_window;
static HWND edit_window;

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
static SHACTIVATEINFO activate_info;
#endif

#define CHILD_ID_MENUBAR        1
#define CHILD_ID_EDIT           2

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
 * Text buffer.
 */
static char *text_buf;
static const UINT text_max = 65536;

/*
 * Integer-to-description mapping.
 */

typedef struct {
  int value;
  const char *text;
} symdef_t;

typedef struct {
  symdef_t *tab;
  int num;
} symmap_t;

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

      n = FormatMessage(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            code,
            0,
            buf + pos,
            len - pos,
            NULL);
      pos += n;

      if ((n = _sntprintf(buf + pos, len - pos,
                          _T("Error 0x%08X."), (unsigned)code)) >= 0)
        pos += n;
      else
        pos += len;

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
 * Create IP address display area.
 */
static BOOL create_edit(void)
{
  int height;
  LOGFONT lf;
  HFONT font;

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

  memset(&lf, 0, sizeof lf);
  lf.lfPitchAndFamily = FIXED_PITCH;
  if (!(font = CreateFontIndirect(&lf)))
    {
      error_system(_T("CreateFontIndirect"));
      return FALSE;
    }
  SendMessage(edit_window, WM_SETFONT, (WPARAM)font, 0);

  return TRUE;
}

/*
 * Append text in a buffer.
 */
static void append(char **buf, size_t *len, const char *fmt, ...)
{
  va_list ap;
  int n;

  if (*len <= 0)
    return;

  va_start(ap, fmt);
  n = _vsnprintf(*buf, *len, fmt, ap);
  va_end(ap);

  if (n < 0 || n >= (int)*len)
    {
      (*buf)[*len - 1] = '\0';
      *buf += *len - 1;
      *len = 0;
    }
  else
    {
      *buf += n;
      *len -= n;
    }
}

/*
 * Append hex string in a buffer.
 */
static void append_hex(char **buf, size_t *len, const char *prefix,
                           unsigned char *hexbuf, int hexlen)
{
  int i;

  append(buf, len, "%s", prefix);
  if (hexlen)
    {
      append(buf, len, "0x");
      for (i = 0; i < hexlen; i++)
        append(buf, len, "%02X", (unsigned)hexbuf[i]);
    }
  else
    {
      append(buf, len, "none");
    }
  append(buf, len, "\r\n");
}

/*
 * Append hex and ASCII dump in a buffer.
 */
static void append_hexdump(char **buf, size_t *len,
                           unsigned char *hexbuf, int hexlen)
{
  unsigned char b;
  int i, j;

  if (!hexbuf || !hexlen)
    {
      append(buf, len, "    none\r\n");
      return;
    }

  for (i = 0; i < hexlen; i++)
    {
      if ((i & 7) == 0)
        append(buf, len, "   ");

      append(buf, len, " %02X", (unsigned)hexbuf[i]);

      if ((i & 7) == 7) {
        for (j = i - 7; j <= i; j++)
          {
            b = hexbuf[j];
            if (b >= 0x20 && b < 0x7f)
              append(buf, len, " %c", (unsigned)b);
            else
              append(buf, len, " .", (unsigned)b);
          }
        append(buf, len, "\r\n");
      }
    }

  if ((i & 7) != 0)
    {
      for (j = (i & 7); j < 8; j++)
        append(buf, len, "   ");
      for (j = i - (i & 7); j < i; j++)
        {
          b = hexbuf[j];
          if (b >= 0x20 && b < 0x7f)
            append(buf, len, " %c", (unsigned)b);
          else
            append(buf, len, " .", (unsigned)b);
        }
      append(buf, len, "\r\n");
    }
}

/*
 * Append the description of an integer value into a buffer.
 */
static void append_choice(char **buf, size_t *len, const char *prefix,
                          symmap_t *symmap, int value)
{
  int i;

  for (i = 0; i < symmap->num; i++)
    if (value == symmap->tab[i].value)
      break;

  if (i < symmap->num)
    append(buf, len, "%s%s\r\n", prefix, symmap->tab[i].text);
  else
    append(buf, len, "%sunknown\r\n", prefix);
}

/*
 * Append comma-separated list of descriptions of the one bits of an
 * integer value into a buffer.
 */
static void append_flags(char **buf, size_t *len, const char *prefix,
                         symmap_t *symmap, int value)
{
  int bit, n, i;
  char *sep = "";

  append(buf, len, "%s", prefix);

  if (!value)
    {
      append(buf, len, "none\r\n");
      return;
    }

  for (n = 0; n < 32; n++)
    {
      bit = 1 << n;
      if (!(value & bit))
        continue;
      for (i = 0; i < symmap->num; i++)
        if (bit == symmap->tab[i].value)
          break;
      if (i < symmap->num)
        append(buf, len, "%s%s", sep, symmap->tab[i].text);
      else
        append(buf, len, "%sunknown%d", sep, n);
      sep = ", ";
    }

  append(buf, len, "\r\n");
}

/*
 * Append GUID in a buffer.
 */
static void append_guid(char **buf, size_t *len, const char *prefix,
                        GUID *guid)
{
  DWORD d1 = guid->Data1;
  WORD d2 = guid->Data2;
  WORD d3 = guid->Data3;
  BYTE *d4 = guid->Data4;

  append(
    buf, len,
    "%s%02X%02X%02X%02X-%02X%02X-%02X%02X-"
    "%02X%02X-%02X%02X%02X%02X%02X%02X\r\n",
    prefix,
    d1 >> 24 & 0xff, d1 >> 16 & 0xff, d1 >> 8 & 0xff, d1 & 0xff,
    d2 >> 8 & 0xff, d2 & 0xff, d3 >> 8 & 0xff, d3 & 0xff,
    d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]);
}

/*
 * Append system time in a buffer.
 */
static void append_time(char **buf, size_t *len, const char *prefix,
                        SYSTEMTIME *time)
{
  append(
    buf, len, "%s%04hu-%02hu-%02hu %02hu:%02hu:%02hu\r\n",
    prefix,
    time->wYear, time->wMonth, time->wDay,
    time->wHour, time->wMinute, time->wSecond);
}

/*
 * Append IP address string in a buffer.
 */
static void append_addrstr(
  char **buf, size_t *len, const char *prefix, IP_ADDR_STRING *addrstr)
{
  if (addrstr && addrstr->IpAddress.String[0])
    append(buf, len, "%s%s\r\n", prefix, addrstr->IpAddress.String);
  else
    append(buf, len, "%snone\r\n", prefix);
}

/*
 * Append IP address string with mask and context in a buffer.
 */
static void append_addrstr_full(
  char **buf, size_t *len, const char *prefix, IP_ADDR_STRING *addrstr)
{
  if (addrstr && addrstr->IpAddress.String[0])
    append(
      buf, len, "%s%s/%s (0x%08lX)\r\n", prefix,
      addrstr->IpAddress.String, addrstr->IpMask.String, addrstr->Context);
  else
    append(buf, len, "%snone\r\n", prefix);
}

/*
 * Append an IPv4/IPv6 socket address in a buffer.
 */
static void append_ipaddr(
  char **buf, size_t *len, const char *prefix, PSOCKADDR sockaddr)
{
  DWORD size, length;
  TCHAR string[64];

  switch (sockaddr->sa_family)
    {
    case AF_INET:
      size = sizeof (SOCKADDR_IN);
      break;
    case AF_INET6:
      size = sizeof (SOCKADDR_IN6);
      break;
    default:
      error(_T("Bad IP address family %hu"), sockaddr->sa_family);
      return;
    }

  length = sizeof string / sizeof string[0];
  if (WSAAddressToString(sockaddr, size, NULL, string, &length))
    {
      error_code(WSAGetLastError(), _T("WSAAddressToString"));
      return;
    }
  append(buf, len, "%s%ls\r\n", prefix, string);
}

#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)

/*
 * Connection manager values.
 */

static symdef_t cm_conntype_tab[] = {
  {CM_CONNTYPE_UNKNOWN, "unknown"},
  {CM_CONNTYPE_CELLULAR, "cellular"},
  {CM_CONNTYPE_NIC, "NIC"},
  {CM_CONNTYPE_BLUETOOTH, "bluetooth"},
  {CM_CONNTYPE_UNIMODEM, "unimodem"},
  {CM_CONNTYPE_VPN, "VPN"},
  {CM_CONNTYPE_PROXY, "proxy"},
  {CM_CONNTYPE_PC, "PC"}
};
symmap_t cm_conntype_map = {
  cm_conntype_tab,
  sizeof cm_conntype_tab / sizeof cm_conntype_tab[0]
};

static symdef_t cm_connsubtype_cellular_tab[] = {
  {CM_CONNSUBTYPE_CELLULAR_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_CELLULAR_CSD, "CSD"},
  {CM_CONNSUBTYPE_CELLULAR_GPRS, "GPRS"},
  {CM_CONNSUBTYPE_CELLULAR_1XRTT, "1xRTT"},
  {CM_CONNSUBTYPE_CELLULAR_1XEVDO, "1xEVDO"},
  {CM_CONNSUBTYPE_CELLULAR_1XEVDV, "1xEVDV"},
  {CM_CONNSUBTYPE_CELLULAR_EDGE, "EDGE"},
  {CM_CONNSUBTYPE_CELLULAR_UMTS, "UMTS"},
  {CM_CONNSUBTYPE_CELLULAR_VOICE, "voice"},
  {CM_CONNSUBTYPE_CELLULAR_PTT, "push-to-talk"},
#ifdef CM_CONNSUBTYPE_CELLULAR_HSDPA
  {CM_CONNSUBTYPE_CELLULAR_HSDPA, "HSDPA"}
#endif
};
symmap_t cm_connsubtype_cellular_map = {
  cm_connsubtype_cellular_tab,
  sizeof cm_connsubtype_cellular_tab / sizeof cm_connsubtype_cellular_tab[0]
};

static symdef_t cm_connsubtype_nic_tab[] = {
  {CM_CONNSUBTYPE_NIC_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_NIC_ETHERNET, "ethernet"},
  {CM_CONNSUBTYPE_NIC_WIFI, "Wi-Fi"}
};
symmap_t cm_connsubtype_nic_map = {
  cm_connsubtype_nic_tab,
  sizeof cm_connsubtype_nic_tab / sizeof cm_connsubtype_nic_tab[0]
};

static symdef_t cm_connsubtype_bluetooth_tab[] = {
  {CM_CONNSUBTYPE_BLUETOOTH_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_BLUETOOTH_RAS, "RAS"},
  {CM_CONNSUBTYPE_BLUETOOTH_PAN, "PAN"}
};
symmap_t cm_connsubtype_bluetooth_map = {
  cm_connsubtype_bluetooth_tab,
  sizeof cm_connsubtype_bluetooth_tab / sizeof cm_connsubtype_bluetooth_tab[0]
};

static symdef_t cm_connsubtype_unimodem_tab[] = {
  {CM_CONNSUBTYPE_UNIMODEM_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_UNIMODEM_CSD, "CSD"},
  {CM_CONNSUBTYPE_UNIMODEM_OOB_CSD, "OOB CSD"},
  {CM_CONNSUBTYPE_UNIMODEM_NULL_MODEM, "null modem"},
  {CM_CONNSUBTYPE_UNIMODEM_EXTERNAL_MODEM, "external modem"},
  {CM_CONNSUBTYPE_UNIMODEM_INTERNAL_MODEM, "internal modem"},
  {CM_CONNSUBTYPE_UNIMODEM_PCMCIA_MODEM, "PCMCIA modem"},
  {CM_CONNSUBTYPE_UNIMODEM_IRCOMM_MODEM, "IrComm modem"},
  {CM_CONNSUBTYPE_UNIMODEM_DYNAMIC_MODEM, "bluetooth modem"},
  {CM_CONNSUBTYPE_UNIMODEM_DYNAMIC_PORT, "bluetooth port"}
};
symmap_t cm_connsubtype_unimodem_map = {
  cm_connsubtype_unimodem_tab,
  sizeof cm_connsubtype_unimodem_tab / sizeof cm_connsubtype_unimodem_tab[0]
};

static symdef_t cm_connsubtype_vpn_tab[] = {
  {CM_CONNSUBTYPE_VPN_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_VPN_L2TP, "L2TP"},
  {CM_CONNSUBTYPE_VPN_PPTP, "PPTP"}
};
symmap_t cm_connsubtype_vpn_map = {
  cm_connsubtype_vpn_tab,
  sizeof cm_connsubtype_vpn_tab / sizeof cm_connsubtype_vpn_tab[0]
};

static symdef_t cm_connsubtype_proxy_tab[] = {
  {CM_CONNSUBTYPE_PROXY_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_PROXY_NULL, "null"},
  {CM_CONNSUBTYPE_PROXY_HTTP, "HTTP"},
  {CM_CONNSUBTYPE_PROXY_WAP, "WAP"},
  {CM_CONNSUBTYPE_PROXY_SOCKS4, "SOCKS4"},
  {CM_CONNSUBTYPE_PROXY_SOCKS5, "SOCKS5"}
};
symmap_t cm_connsubtype_proxy_map = {
  cm_connsubtype_proxy_tab,
  sizeof cm_connsubtype_proxy_tab / sizeof cm_connsubtype_proxy_tab[0]
};

static symdef_t cm_connsubtype_pc_tab[] = {
  {CM_CONNSUBTYPE_PC_UNKNOWN, "unknown"},
  {CM_CONNSUBTYPE_PC_DESKTOPPASSTHROUGH, "desktop passthrough"},
  {CM_CONNSUBTYPE_PC_IR, "infrared"},
  {CM_CONNSUBTYPE_PC_MODEM_LINK, "modem link"}
};
symmap_t cm_connsubtype_pc_map = {
  cm_connsubtype_pc_tab,
  sizeof cm_connsubtype_pc_tab / sizeof cm_connsubtype_pc_tab[0]
};

static symdef_t cm_dsf_tab[] = {
  {CM_DSF_BILLBYTIME, "bill by time"},
  {CM_DSF_ALWAYSON, "always on"},
  {CM_DSF_SUSPENDRESUME, "suspend/resume"}
};
symmap_t cm_dsf_map = {
  cm_dsf_tab,
  sizeof cm_dsf_tab / sizeof cm_dsf_tab[0]
};

static symdef_t connmgr_status_tab[] = {
  {CONNMGR_STATUS_UNKNOWN, "unknown"},
  {CONNMGR_STATUS_CONNECTED, "connected"},
  {CONNMGR_STATUS_SUSPENDED, "suspended"},
  {CONNMGR_STATUS_DISCONNECTED, "disconnected"},
  {CONNMGR_STATUS_CONNECTIONFAILED, "connection failed"},
  {CONNMGR_STATUS_CONNECTIONCANCELED, "connection canceled"},
  {CONNMGR_STATUS_CONNECTIONDISABLED, "connection disabled"},
  {CONNMGR_STATUS_NOPATHTODESTINATION, "no path to destination"},
  {CONNMGR_STATUS_WAITINGFORPATH, "waiting for path"},
  {CONNMGR_STATUS_WAITINGFORPHONE, "waiting for phone"},
  {CONNMGR_STATUS_PHONEOFF, "phone off"},
  {CONNMGR_STATUS_EXCLUSIVECONFLICT, "exclusive conflict"},
  {CONNMGR_STATUS_NORESOURCES, "no resources"},
  {CONNMGR_STATUS_CONNECTIONLINKFAILED, "connection link failed"},
  {CONNMGR_STATUS_AUTHENTICATIONFAILED, "authentication failed"},
#ifdef CONNMGR_STATUS_NOPATHWITHPROPERTY
  {CONNMGR_STATUS_NOPATHWITHPROPERTY, "no path with property"},
#endif
  {CONNMGR_STATUS_WAITINGCONNECTION, "waiting connection"},
  {CONNMGR_STATUS_WAITINGFORRESOURCE, "waiting for resource"},
  {CONNMGR_STATUS_WAITINGFORNETWORK, "waiting for network"},
  {CONNMGR_STATUS_WAITINGDISCONNECTION, "waiting disconnection"},
  {CONNMGR_STATUS_WAITINGCONNECTIONABORT, "waiting connection abort"}
};
symmap_t connmgr_status_map = {
  connmgr_status_tab,
  sizeof connmgr_status_tab / sizeof connmgr_status_tab[0]
};

/*
 * Append Connection Manager connections in a buffer.
 */
static int append_connmgr_connections(char **b, size_t *l)
{
  CONNMGR_CONNECTION_DETAILED_STATUS *data, *d;
  HRESULT result;
  DWORD size;
  symmap_t *symmap;
  int i;

  size = 0;
  if ((result = ConnMgrQueryDetailedStatus(NULL, &size)) !=
      HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER))
    {
      if (result == S_OK)
        return 0;
      error_code(result, _T("ConnMgrQueryDetailedStatus"));
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((result = ConnMgrQueryDetailedStatus(data, &size)) != S_OK)
    {
      error_code(result, _T("ConnMgrQueryDetailedStatus"));
      LocalFree(data);
      return -1;
    }

  for (d = data; d; d = d->pNext)
    {
      append(b, l, "ConnMgr Connection Detailed Status\r\n");
      append(b, l, "  Version: %lu\r\n", d->dwVer);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_TYPE))
        {
          append_choice(b, l, "  Type: ", &cm_conntype_map, d->dwType);
          if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_SUBTYPE))
            {
              switch (d->dwType)
                {
                case CM_CONNTYPE_CELLULAR:
                  symmap = &cm_connsubtype_cellular_map;
                  break;
                case CM_CONNTYPE_NIC:
                  symmap = &cm_connsubtype_nic_map;
                  break;
                case CM_CONNTYPE_BLUETOOTH:
                  symmap = &cm_connsubtype_bluetooth_map;
                  break;
                case CM_CONNTYPE_UNIMODEM:
                  symmap = &cm_connsubtype_unimodem_map;
                  break;
                case CM_CONNTYPE_VPN:
                  symmap = &cm_connsubtype_vpn_map;
                  break;
                case CM_CONNTYPE_PROXY:
                  symmap = &cm_connsubtype_proxy_map;
                  break;
                case CM_CONNTYPE_PC:
                  symmap = &cm_connsubtype_pc_map;
                  break;
                default:
                  symmap = NULL;
                  break;
                }
              if (symmap)
                append_choice(b, l, "  Subtype: ", symmap, d->dwSubtype);
              else
                append(b, l, "  Subtype: unknown\r\n");
            }
        }
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_FLAGS))
        append_flags(b, l, "  Flags: ", &cm_dsf_map, d->dwFlags);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_SECURE))
        {
          if (d->dwSecure)
            append(b, l, "  Secure: yes\r\n");
          else
            append(b, l, "  Secure: no\r\n");
        }
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_DESTNET))
        append_guid(b, l, "  Destination Network: ", &d->guidDestNet);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_SOURCENET))
        append_guid(b, l, "  Source Network: ", &d->guidSourceNet);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_DESCRIPTION))
        append(b, l, "  Description: %ls\r\n", d->szDescription);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_ADAPTERNAME))
        append(b, l, "  Adapter Name: %ls\r\n", d->szAdapterName);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_CONNSTATUS))
        append_choice(
          b, l, "  Connection Status: ",
          &connmgr_status_map, d->dwConnectionStatus);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_LASTCONNECT))
        append_time(b, l, "  Last Connect: ", &d->LastConnectTime);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_SIGNALQUALITY))
        append(b, l, "  Signal Quality: %lu\r\n", d->dwSignalQuality);
      if ((d->dwParams & CONNMGRDETAILEDSTATUS_PARAM_IPADDR) && d->pIPAddr)
        {
          append(b, l, "  IP Addresses:\r\n");
          for (i = 0; i < d->pIPAddr->cIPAddr; i++)
            append_ipaddr(b, l, "    ", (PSOCKADDR)&d->pIPAddr->IPAddr[i]);
        }
        
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

#if _WIN32_CE >= 0x502
/*
 * WZC values.
 */

static symdef_t intf_mediastate_tab[] = {
  {MEDIA_STATE_CONNECTED, "connected"},
  {MEDIA_STATE_DISCONNECTED, "disconnected"},
  {MEDIA_STATE_UNKNOWN, "unknown"}
};
symmap_t intf_mediastate_map = {
  intf_mediastate_tab,
  sizeof intf_mediastate_tab / sizeof intf_mediastate_tab[0]
};

static symdef_t intf_mediatype_tab[] = {
  {NdisMedium802_3, "802.3"},
  {NdisMedium802_5, "802.5"},
  {NdisMediumFddi, "FDDI"},
  {NdisMediumWan, "WAN"},
  {NdisMediumLocalTalk, "LocalTalk"},
  {NdisMediumDix, "DIX"},
  {NdisMediumArcnetRaw, "raw ARCNET"},
  {NdisMediumArcnet878_2, "Arcnet 878.2"},
  {NdisMediumAtm, "ATM"},
  {NdisMediumWirelessWan, "wireless WAN"},
  {NdisMediumIrda, "IrDA"},
  {NdisMediumBpc, "broadcast PC"},
  {NdisMediumCoWan, "connection-oriented WAN"},
  {NdisMedium1394, "IEEE 1394"},
  {NdisMediumInfiniBand, "InfiniBand"},
  {NdisMediumTunnel, "tunnel"},
  {NdisMediumNative802_11, "native 802.11"}
};
symmap_t intf_mediatype_map = {
  intf_mediatype_tab,
  sizeof intf_mediatype_tab / sizeof intf_mediatype_tab[0]
};

static symdef_t intf_physicalmediatype_tab[] = {
  {NdisPhysicalMediumUnspecified, "unspecified"},
  {NdisPhysicalMediumWirelessLan, "wireless LAN"},
  {NdisPhysicalMediumCableModem, "cable modem"},
  {NdisPhysicalMediumPhoneLine, "phone line"},
  {NdisPhysicalMediumPowerLine, "power line"},
  {NdisPhysicalMediumDSL, "DSL"},
  {NdisPhysicalMediumFibreChannel, "fibre channel"},
  {NdisPhysicalMedium1394, "IEEE 1394"},
  {NdisPhysicalMediumWirelessWan, "wireless WAN"},
  {NdisPhysicalMediumNative802_11, "native 802.11"}
};
symmap_t intf_physicalmediatype_map = {
  intf_physicalmediatype_tab,
  sizeof intf_physicalmediatype_tab / sizeof intf_physicalmediatype_tab[0]
};

static symdef_t intf_inframode_tab[] = {
  {Ndis802_11IBSS, "IBSS"},
  {Ndis802_11Infrastructure, "infrastructure"},
  {Ndis802_11AutoUnknown, "auto unknown"}
};
symmap_t intf_inframode_map = {
  intf_inframode_tab,
  sizeof intf_inframode_tab / sizeof intf_inframode_tab[0]
};

static symdef_t intf_authmode_tab[] = {
  {Ndis802_11AuthModeOpen, "open"},
  {Ndis802_11AuthModeShared, "shared"},
  {Ndis802_11AuthModeAutoSwitch, "auto switch"},
  {Ndis802_11AuthModeWPA, "WPA"},
  {Ndis802_11AuthModeWPAPSK, "WPA-PSK"},
  {Ndis802_11AuthModeWPANone, "WPA none"},
  {Ndis802_11AuthModeWPA2, "WPA2"},
  {Ndis802_11AuthModeWPA2PSK, "WPA2-PSK"}
};
symmap_t intf_authmode_map = {
  intf_authmode_tab,
  sizeof intf_authmode_tab / sizeof intf_authmode_tab[0]
};

static symdef_t intf_wepstatus_tab[] = {
  {Ndis802_11WEPEnabled, "WEP enabled"},
  {Ndis802_11WEPDisabled, "WEP disabled"},
  {Ndis802_11WEPKeyAbsent, "WEP key absent"},
  {Ndis802_11WEPNotSupported, "WEP not supported"},
  {Ndis802_11Encryption2Enabled, "TKIP and WEP enabled"},
  {Ndis802_11Encryption2KeyAbsent, "TKIP and WEP key absent"},
  {Ndis802_11Encryption3Enabled, "AES, TKIP and WEP enabled"},
  {Ndis802_11Encryption3KeyAbsent, "AES, TKIP and WEP key absent"}
};
symmap_t intf_wepstatus_map = {
  intf_wepstatus_tab,
  sizeof intf_wepstatus_tab / sizeof intf_wepstatus_tab[0]
};

static symdef_t intf_ctl_cm_tab[] = {
  {Ndis802_11IBSS, "IBSS"},
  {Ndis802_11Infrastructure, "infrastructure"},
  {Ndis802_11AutoUnknown, "IBSS/infrastructure"}
};
symmap_t intf_ctl_cm_map = {
  intf_ctl_cm_tab,
  sizeof intf_ctl_cm_tab / sizeof intf_ctl_cm_tab[0]
};

static symdef_t intf_ctl_tab[] = {
  {INTFCTL_ENABLED, "WZC enabled"},
  {INTFCTL_FALLBACK, "fallback to non-preferred"},
  {INTFCTL_OIDSSUPP, "WZC OIDs supported"},
  {INTFCTL_VOLATILE, "parameters volatile"},
  {INTFCTL_POLICY, "parameters policy enforced"},
  {INTFCTL_8021XSUPP, "802.1X enabled"}
};
symmap_t intf_ctl_map = {
  intf_ctl_tab,
  sizeof intf_ctl_tab / sizeof intf_ctl_tab[0]
};

static symdef_t intf_cap_cipher_tab[] = {
  {Ndis802_11WEPEnabled, "WEP"},
  {Ndis802_11Encryption2Enabled, "TKIP and WEP"},
  {Ndis802_11Encryption3Enabled, "AES, TKIP and WEP"}
};
symmap_t intf_cap_cipher_map = {
  intf_cap_cipher_tab,
  sizeof intf_cap_cipher_tab / sizeof intf_cap_cipher_tab[0]
};

static symdef_t intf_cap_tab[] = {
  {INTFCAP_SSN, "WPA (SSN)"},
  {INTFCAP_80211I, "802.11I"}
};
symmap_t intf_cap_map = {
  intf_cap_tab,
  sizeof intf_cap_tab / sizeof intf_cap_tab[0]
};

/*
 * Append WZC context in a buffer.
 */
static int append_wzc_context(char **b, size_t *l)
{
  PWZC_CONTEXT data;
  DWORD code, flags;

  if (!(data = LocalAlloc(0, sizeof *data)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = WZCQueryContext(NULL, ~0, data, &flags)) != ERROR_SUCCESS)
    {
      error_code(code, _T("WZCQueryContext"));
      LocalFree(data);
      return -1;
    }

  append(b, l, "WZC Context\r\n");
  append(b, l, "  Rescan Timeout: %lu\r\n", data->tmTr);
  append(b, l, "  Retry Valid Config Timeout: %lu\r\n", data->tmTc);
  append(b, l, "  Media Connect Timeout: %lu\r\n", data->tmTp);
  append(b, l, "  Recover Invalid Config Timeout: %lu\r\n", data->tmTf);
  append(b, l, "  State Soft Reset Timeout: %lu\r\n", data->tmTd);
  append(b, l, "\r\n");

  LocalFree(data);
  return 0;
}

/*
 * Append WZC interfaces in a buffer.
 */
static int append_wzc_interfaces(char **b, size_t *l)
{
  PINTFS_KEY_TABLE keys;
  PINTF_KEY_ENTRY key;
  PINTF_ENTRY data;
  DWORD code, flags;
  int i;

  if (!(keys = LocalAlloc(0, sizeof *keys)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }

  if (!(data = LocalAlloc(0, sizeof *data)))
    {
      error_system(_T("LocalAlloc"));
      LocalFree(keys);
      return -1;
    }

  if ((code = WZCEnumInterfaces(NULL, keys)) != ERROR_SUCCESS)
    {
      error_code(code, _T("WZCEnumInterfaces"));
      LocalFree(data);
      LocalFree(keys);
      return -1;
    }

  for (i = 0; i < (int)keys->dwNumIntfs; i++)
    {
      key = &keys->pIntfs[i];
      memset(data, 0, sizeof *data);
      data->wszGuid = key->wszGuid;
      if ((code = WZCQueryInterface(NULL, ~0, data, &flags)) !=
          ERROR_SUCCESS)
        {
          error_code(code, _T("WZCQueryInterface"));
          LocalFree(data);
          LocalFree(keys);
          return -1;
        }
      append(b, l, "WZC Interface\r\n");
      append(b, l, "  GUID: %ls\r\n", data->wszGuid);
      append(b, l, "  Description: %ls\r\n", data->wszDescr);
      append_choice(
        b, l, "  Media State: ", &intf_mediastate_map, data->ulMediaState);
      append_choice(
        b, l, "  Media Type: ", &intf_mediatype_map, data->ulMediaType);
      append_choice(
        b, l, "  Physical Media Type: ",
        &intf_physicalmediatype_map, data->ulPhysicalMediaType);
      append_choice(
        b, l, "  Infrastrucure Mode: ", &intf_inframode_map, data->nInfraMode);
      append_choice(
        b, l, "  Authentication Mode: ", &intf_authmode_map, data->nAuthMode);
      append_choice(
        b, l, "  WEP Status: ", &intf_wepstatus_map, data->nWepStatus);
      append_choice(
        b, l, "  Configuration Mode: ", &intf_ctl_cm_map,
        data->dwCtlFlags & INTFCTL_CM_MASK);
      append_flags(
        b, l, "  Control Flags: ", &intf_ctl_map,
        data->dwCtlFlags & ~INTFCTL_CM_MASK);
      append_choice(
        b, l, "  Max Cipher: ", &intf_cap_cipher_map,
        data->dwCapabilities & INTFCAP_MAX_CIPHER_MASK);
      append_flags(
        b, l, "  Capabilities: ", &intf_cap_map,
        data->dwCapabilities & ~INTFCAP_MAX_CIPHER_MASK);
      append(b, l, "  SSID:\r\n");
      append_hexdump(b, l, data->rdSSID.pData, data->rdSSID.dwDataLen);
      append(b, l, "  BSSID:\r\n");
      append_hexdump(b, l, data->rdBSSID.pData, data->rdBSSID.dwDataLen);
      append(b, l, "  BSSID List:\r\n");
      append_hexdump(b, l,
                     data->rdBSSIDList.pData, data->rdBSSIDList.dwDataLen);
      append(b, l, "  St SSID List:\r\n");
      append_hexdump(b, l,
                     data->rdStSSIDList.pData,
                     data->rdStSSIDList.dwDataLen);
      append(b, l, "  Control Data:\r\n");
      append_hexdump(b, l,
                     data->rdCtrlData.pData, data->rdCtrlData.dwDataLen);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  LocalFree(keys);
  return 0;
}
#endif /* _WIN32_CE >= 0x502 */
#endif /* defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC) */

static symdef_t power_state_tab[] = {
  {PwrDeviceUnspecified, "unspecified"},
  {D0, "full power"},
  {D1, "low power"},
  {D2, "standby"},
  {D3, "sleep"},
  {D4, "off"}
};
symmap_t power_state_map = {
  power_state_tab,
  sizeof power_state_tab / sizeof power_state_tab[0]
};

/*
 * Append adapter power states in a buffer.
 */
static int append_adapter_power(char **b, size_t *l)
{
  PIP_ADAPTER_INFO data, d;
  WCHAR device[40 + MAX_ADAPTER_NAME_LENGTH + 6];
  CEDEVICE_POWER_STATE ps;
  ULONG size;
  DWORD code;

  size = 0;
  if ((code = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetAdaptersInfo"));
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetAdaptersInfo(data, &size)) != NO_ERROR)
    {
      error_code(code, _T("GetAdaptersInfo"));
      LocalFree(data);
      return -1;
    }

  for (d = data; d; d = d->Next)
    {
      _snwprintf(
        device, sizeof device / sizeof device[0],
        L"{98C5250D-C29A-4985-AE5F-AFE5367E5006}\\%hs", d->AdapterName);
      device[sizeof device / sizeof device[0] - 1] = L'\0';
      if ((code = GetDevicePower(device, POWER_NAME, &ps)) != ERROR_SUCCESS)
        {
          if (code != ERROR_FILE_NOT_FOUND)
            {
              error_code(code, _T("GetDevicePower: %ls"), device);
              LocalFree(data);
              return -1;
            }
          continue;
        }
      append(b, l, "Device Power\r\n");
      append(b, l, "  Adapter Name: %s\r\n", d->AdapterName);
      append_choice(b, l, "  Power State: ", &power_state_map, ps);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append per adapter info in a buffer.
 */
static int append_per_adapter_info(char **b, size_t *l, ULONG index)
{
  PIP_PER_ADAPTER_INFO data;
  PIP_ADDR_STRING addrstr;
  ULONG size;
  DWORD code;

  size = 0;
  if ((code = GetPerAdapterInfo(index, NULL, &size)) !=
      ERROR_BUFFER_OVERFLOW)
    {
      error_code(code, _T("GetPerAdapterInfo"));
      return -1;
    }

  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }

  if ((code = GetPerAdapterInfo(index, data, &size)) != NO_ERROR)
    {
      error_code(code, _T("GetPerAdapterInfo"));
      LocalFree(data);
      return -1;
    }

  append(b, l, "  Autoconfig Enabled: %u\r\n", data->AutoconfigEnabled);
  append(b, l, "  Autoconfig Active: %u\r\n", data->AutoconfigActive);
  append_addrstr(b, l, "  Current DNS Server: ", data->CurrentDnsServer);
  append(b, l, "  All DNS Servers:\r\n");
  for (addrstr = &data->DnsServerList; addrstr; addrstr = addrstr->Next)
    append_addrstr(b, l, "    ", addrstr);

  LocalFree(data);
  return 0;
}

/*
 * Append adapter info in a buffer.
 */
static int append_adapter_info(char **b, size_t *l)
{
  PIP_ADAPTER_INFO data, d;
  PIP_ADDR_STRING addrstr;
  ULONG size;
  DWORD code;

  size = 0;
  if ((code = GetAdaptersInfo(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetAdaptersInfo"));
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetAdaptersInfo(data, &size)) != NO_ERROR)
    {
      error_code(code, _T("GetAdaptersInfo"));
      LocalFree(data);
      return -1;
    }

  for (d = data; d; d = d->Next)
    {
      append(b, l, "Adapter Info\r\n");
      append(b, l, "  Name: %s\r\n", d->AdapterName);
      append(b, l, "  Description: %s\r\n", d->Description);
      append_hex(b, l, "  Hw Address: ", d->Address, d->AddressLength);
      append(b, l, "  Index: 0x%08lX\r\n", d->Index);
      append(b, l, "  Type: %u\r\n", d->Type);
      append(b, l, "  DHCP Enabled: %u\r\n", d->DhcpEnabled);
      append_addrstr_full(b, l, "  Current IP Address: ", d->CurrentIpAddress);
      append(b, l, "  All IP Addresses:\r\n");
      for (addrstr = &d->IpAddressList; addrstr; addrstr = addrstr->Next)
        append_addrstr_full(b, l, "    ", addrstr);
      append_addrstr(b, l, "  Default Gateway: ", &d->GatewayList);
      append_addrstr(b, l, "  DHCP Server: ", &d->DhcpServer);
      append(b, l, "  Have WINS: %u\r\n", d->HaveWins);
      append_addrstr(b, l, "  Primary WINS Server: ", &d->PrimaryWinsServer);
      append_addrstr(
        b, l, "  Secondary WINS Server: ", &d->SecondaryWinsServer);
      append(b, l, "  Lease Obtained: %lu\r\n",
             (unsigned long)d->LeaseObtained);
      append(b, l, "  Lease Expires: %lu\r\n",
             (unsigned long)d->LeaseExpires);
      append_per_adapter_info(b, l, d->Index);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append adapter addresses in a buffer.
 */
static int append_adapter_addresses(char **b, size_t *l)
{
  PIP_ADAPTER_ADDRESSES data, d;
  PIP_ADAPTER_UNICAST_ADDRESS uni;
  PIP_ADAPTER_ANYCAST_ADDRESS any;
  PIP_ADAPTER_MULTICAST_ADDRESS multi;
  PIP_ADAPTER_DNS_SERVER_ADDRESS dns;
  ULONG size;
  DWORD code;

  size = 0;
  if ((code = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &size)) !=
      ERROR_BUFFER_OVERFLOW)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetAdaptersAddresses"));
      return -1;
    }

  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }

  if ((code = GetAdaptersAddresses(AF_UNSPEC, 0, NULL, data, &size)) !=
      NO_ERROR)
    {
      error_code(code, _T("GetAdaptersAddresses"));
      LocalFree(data);
      return -1;
    }

  for (d = data; d; d = d->Next)
    {
      append(b, l, "Adapter Addresses\r\n");
      append(b, l, "  If Index: 0x%08lX\r\n", d->IfIndex);
      append(b, l, "  Adapter Name: %s\r\n", d->AdapterName);

      for (uni = d->FirstUnicastAddress; uni; uni = uni->Next)
        {
          append(b, l, "  Unicast Address:\r\n");
          append(b, l, "    Flags: 0x%08lX\r\n", uni->Flags);
          append_hex(b, l, "    Address: ",
                     (unsigned char *)uni->Address.lpSockaddr,
                     uni->Address.iSockaddrLength);
          append(b, l, "    Prefix Origin: %u\r\n", uni->PrefixOrigin);
          append(b, l, "    Suffix Origin: %u\r\n", uni->SuffixOrigin);
          append(b, l, "    DAD State: %u\r\n", uni->DadState);
          append(b, l, "    Valid Lifetime: %lu\r\n", uni->ValidLifetime);
          append(b, l, "    Preferred Lifetime: %lu\r\n",
                 uni->PreferredLifetime);
          append(b, l, "    Lease Lifetime: %lu\r\n", uni->LeaseLifetime);
        }

      for (any = d->FirstAnycastAddress; any; any = any->Next)
        {
          append(b, l, "  Anycast Address:\r\n");
          append(b, l, "    Flags: 0x%08lX\r\n", any->Flags);
          append_hex(b, l, "    Address: ",
                     (unsigned char *)any->Address.lpSockaddr,
                     any->Address.iSockaddrLength);
        }

      for (multi = d->FirstMulticastAddress; multi; multi = multi->Next)
        {
          append(b, l, "  Multicast Address:\r\n");
          append(b, l, "    Flags: 0x%08lX\r\n", multi->Flags);
          append_hex(b, l, "    Address: ",
                     (unsigned char *)multi->Address.lpSockaddr,
                     multi->Address.iSockaddrLength);
        }

      for (dns = d->FirstDnsServerAddress; dns; dns = dns->Next)
        {
          append(b, l, "  DNS Server Address:\r\n");
          append_hex(b, l, "    Address: ",
                     (unsigned char *)dns->Address.lpSockaddr,
                     dns->Address.iSockaddrLength);
        }

      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append network parameters in a buffer.
 */
static int append_network_params(char **b, size_t *l)
{
  PFIXED_INFO data;
  PIP_ADDR_STRING addrstr;
  ULONG size;
  DWORD code;

  size = 0;
  if ((code = GetNetworkParams(NULL, &size)) != ERROR_BUFFER_OVERFLOW)
    {
      error_code(code, _T("GetNetworkParams"), (unsigned)code);
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetNetworkParams(data, &size)) != NO_ERROR)
    {
      error_code(code, _T("GetNetworkParams"));
      LocalFree(data);
      return -1;
    }

  append(b, l, "Network Parameters\r\n");
  append(b, l, "  Host Name: %s\r\n", data->HostName);
  append(b, l, "  Domain Name: %s\r\n", data->DomainName);
  append_addrstr(b, l, "  Current DNS Server: ", data->CurrentDnsServer);
  append(b, l, "  All DNS Servers:\r\n");
  for (addrstr = &data->DnsServerList; addrstr; addrstr = addrstr->Next)
    append_addrstr(b, l, "    ", addrstr);
  append(b, l, "  Node Type: %u\r\n", data->NodeType);
  append(b, l, "  Scope ID: %s\r\n", data->ScopeId);
  append(b, l, "  Enable Routing: %u\r\n", data->EnableRouting);
  append(b, l, "  Enable Proxy: %u\r\n", data->EnableProxy);
  append(b, l, "  Enable DNS: %u\r\n", data->EnableDns);
  append(b, l, "\r\n");

  LocalFree(data);
  return 0;
}

/*
 * Append interface info in a buffer.
 */
static int append_interface_info(char **b, size_t *l)
{
  PIP_INTERFACE_INFO data;
  PIP_ADAPTER_INDEX_MAP map;
  ULONG size;
  DWORD code;
  int i;

  size = 0;
  if ((code = GetInterfaceInfo(NULL, &size)) != ERROR_INSUFFICIENT_BUFFER)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetInterfaceInfo"), (unsigned)code);
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetInterfaceInfo(data, &size)) != NO_ERROR)
    {
      error_code(code, _T("GetInterfaceInfo"));
      LocalFree(data);
      return -1;
    }

  for (i = 0; i < (int)data->NumAdapters; i++)
    {
      append(b, l, "Adapter Interface Index\r\n");
      map = &data->Adapter[i];
      append(b, l, "  Index: 0x%08lX\r\n", map->Index);
      append(b, l, "  Name: %ls\r\n", map->Name);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append interface table in a buffer.
 */
static int append_interface_table(char **b, size_t *l)
{
  PMIB_IFTABLE data;
  PMIB_IFROW row;
  ULONG size;
  DWORD code;
  int i;

  size = 0;
  if ((code = GetIfTable(NULL, &size, FALSE)) != ERROR_INSUFFICIENT_BUFFER)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetIfTable"), (unsigned)code);
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetIfTable(data, &size, FALSE)) != NO_ERROR)
    {
      error_code(code, _T("GetIfTable"));
      LocalFree(data);
      return -1;
    }

  for (i = 0; i < (int)data->dwNumEntries; i++)
    {
      append(b, l, "Interface Entry\r\n");
      row = &data->table[i];
      append(b, l, "  Name: %ls\r\n", row->wszName);
      append(b, l, "  Index: 0x%08lX\r\n", row->dwIndex);
      append(b, l, "  Type: %lu\r\n", row->dwType);
      append(b, l, "  MTU: %lu\r\n", row->dwMtu);
      append(b, l, "  Speed: %lu\r\n", row->dwSpeed);
      append_hex(b, l, "  Physical Address: ",
                 row->bPhysAddr, row->dwPhysAddrLen);
      append(b, l, "  AdminStatus: %lu\r\n", row->dwAdminStatus);
      append(b, l, "  OperStatus: %lu\r\n", row->dwOperStatus);
      append(b, l, "  LastChange: %lu\r\n", row->dwLastChange);
      append(b, l, "  InOctets: %lu\r\n", row->dwInOctets);
      append(b, l, "  InUcastPkts: %lu\r\n", row->dwInUcastPkts);
      append(b, l, "  InNUcastPkts: %lu\r\n", row->dwInNUcastPkts);
      append(b, l, "  InDiscards: %lu\r\n", row->dwInDiscards);
      append(b, l, "  InErrors: %lu\r\n", row->dwInErrors);
      append(b, l, "  InUnknownProtos: %lu\r\n", row->dwInUnknownProtos);
      append(b, l, "  OutOctets: %lu\r\n", row->dwOutOctets);
      append(b, l, "  OutUcastPkts: %lu\r\n", row->dwOutUcastPkts);
      append(b, l, "  OutNUcastPkts: %lu\r\n", row->dwOutNUcastPkts);
      append(b, l, "  OutDiscards: %lu\r\n", row->dwOutDiscards);
      append(b, l, "  OutErrors: %lu\r\n", row->dwOutErrors);
      append(b, l, "  OutQLen: %lu\r\n", row->dwOutQLen);
      append(b, l, "  Description: %*s\r\n", row->dwDescrLen, row->bDescr);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append IP address table in a buffer.
 */
static int append_ip_address_table(char **b, size_t *l)
{
  PMIB_IPADDRTABLE data;
  PMIB_IPADDRROW row;
  ULONG size;
  DWORD code;
  int i;

  size = 0;
  if ((code = GetIpAddrTable(NULL, &size, FALSE)) != ERROR_INSUFFICIENT_BUFFER)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetIpAddrTable"));
      return -1;
    }

  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }

  if ((code = GetIpAddrTable(data, &size, FALSE)) != NO_ERROR)
    {
      error_code(code, _T("GetIpAddrTable"));
      LocalFree(data);
      return -1;
    }

  for (i = 0; i < (int)data->dwNumEntries; i++)
    {
      append(b, l, "IP Address Entry\r\n");
      row = &data->table[i];
      append(b, l, "  Address: 0x%08lX\r\n", row->dwAddr);
      append(b, l, "  Index: 0x%08lX\r\n", row->dwIndex);
      append(b, l, "  Mask: 0x%08lX\r\n", row->dwMask);
      append(b, l, "  Broadcast Address: 0x%08lX\r\n", row->dwBCastAddr);
      append(b, l, "  Reassembly Size: %lu\r\n", row->dwReasmSize);
      append(b, l, "  Unused1: 0x%04hX\r\n", row->unused1);
      append(b, l, "  Type: 0x%04hX\r\n", row->wType);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append IP net table in a buffer.
 */
static int append_ip_net_table(char **b, size_t *l)
{
  PMIB_IPNETTABLE data;
  PMIB_IPNETROW row;
  ULONG size;
  DWORD code;
  int i;

  size = 0;
  if ((code = GetIpNetTable(NULL, &size, FALSE)) != ERROR_INSUFFICIENT_BUFFER)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetIpNetTable"), (unsigned)code);
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetIpNetTable(data, &size, FALSE)) != NO_ERROR)
    {
      error_code(code, _T("GetIpNetTable"));
      LocalFree(data);
      return -1;
    }

  for (i = 0; i < (int)data->dwNumEntries; i++)
    {
      append(b, l, "IP Net Entry\r\n");
      row = &data->table[i];
      append(b, l, "  Index: 0x%08lX\r\n", row->dwIndex);
      append_hex(b, l, "  Physical Address: ",
                 row->bPhysAddr, row->dwPhysAddrLen);
      append(b, l, "  Address: 0x%08lX\r\n", row->dwAddr);
      append(b, l, "  Type: %lu\r\n", row->dwType);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Append IP forward table in a buffer.
 */
static int append_ip_forward_table(char **b, size_t *l)
{
  PMIB_IPFORWARDTABLE data;
  PMIB_IPFORWARDROW row;
  ULONG size;
  DWORD code;
  int i;

  size = 0;
  if ((code = GetIpForwardTable(NULL, &size, FALSE)) !=
      ERROR_INSUFFICIENT_BUFFER)
    {
      if (code == ERROR_NO_DATA)
        return 0;
      error_code(code, _T("GetIpForwardTable"), (unsigned)code);
      return -1;
    }
  if (!(data = LocalAlloc(0, size)))
    {
      error_system(_T("LocalAlloc"));
      return -1;
    }
  if ((code = GetIpForwardTable(data, &size, FALSE)) != NO_ERROR)
    {
      error_code(code, _T("GetIpForwardTable"));
      LocalFree(data);
      return -1;
    }

  for (i = 0; i < (int)data->dwNumEntries; i++)
    {
      append(b, l, "IP Forward Entry\r\n");
      row = &data->table[i];
      append(b, l, "  Destination: 0x%08lX\r\n", row->dwForwardDest);
      append(b, l, "  Mask: 0x%08lX\r\n", row->dwForwardMask);
      append(b, l, "  Policy: %lu\r\n", row->dwForwardPolicy);
      append(b, l, "  Next Hop: 0x%08lX\r\n", row->dwForwardNextHop);
      append(b, l, "  If Index: 0x%08lX\r\n", row->dwForwardIfIndex);
      append(b, l, "  Type: %lu\r\n", row->dwForwardType);
      append(b, l, "  Protocol: %lu\r\n", row->dwForwardProto);
      append(b, l, "  Age: %lu\r\n", row->dwForwardAge);
      append(b, l, "  Next Hop AS: %lu\r\n", row->dwForwardNextHopAS);
      append(b, l, "  Metric 1: %lu\r\n", row->dwForwardMetric1);
      append(b, l, "  Metric 2: %lu\r\n", row->dwForwardMetric2);
      append(b, l, "  Metric 3: %lu\r\n", row->dwForwardMetric3);
      append(b, l, "  Metric 4: %lu\r\n", row->dwForwardMetric4);
      append(b, l, "  Metric 5: %lu\r\n", row->dwForwardMetric5);
      append(b, l, "\r\n");
    }

  LocalFree(data);
  return 0;
}

/*
 * Refresh information.
 */
static void refresh(void)
{
  TCHAR *text_tbuf = NULL;
  char *b;
  size_t l;

  if (!(text_tbuf = LocalAlloc(0, text_max * sizeof *text_tbuf)))
    {
      error_system(_T("LocalAlloc"));
      goto end;
    }

  b = text_buf;
  l = text_max;

  if (
#if defined(WIN32_PLATFORM_WFSP) || defined(WIN32_PLATFORM_PSPC)
      append_connmgr_connections(&b, &l) ||
#if _WIN32_CE >= 0x502
      append_wzc_context(&b, &l) ||
      append_wzc_interfaces(&b, &l) ||
#endif
#endif
      append_adapter_power(&b, &l) ||
      append_adapter_info(&b, &l) ||
      append_adapter_addresses(&b, &l) ||
      append_network_params(&b, &l) ||
      append_interface_info(&b, &l) ||
      append_interface_table(&b, &l) ||
      append_ip_address_table(&b, &l) ||
      append_ip_net_table(&b, &l) ||
      append_ip_forward_table(&b, &l))
    return;

  _sntprintf(text_tbuf, text_max, _T("%hs"), text_buf);
  text_tbuf[text_max - 1] = _T('\0');

  SendMessage(edit_window, WM_SETTEXT, 0, (LPARAM)text_tbuf);

 end:
  if (text_tbuf)
    LocalFree(text_tbuf);
}

/*
 * Save information.
 */
static void save(void)
{
  TCHAR *tpath = NULL;
  SYSTEMTIME time;
  HANDLE h;
  DWORD dummy;

  GetSystemTime(&time);

  if (!(tpath = LocalAlloc(0, MAX_PATH * sizeof *tpath)))
    {
      error_system(_T("LocalAlloc"));
      goto end;
    }
  _sntprintf(tpath, MAX_PATH, _T("%s-%04hu%02hu%02hu%02hu%02hu%02hu.txt"),
             application_name,
             time.wYear, time.wMonth, time.wDay,
             time.wHour, time.wMinute, time.wSecond);
  tpath[MAX_PATH - 1] = _T('\0');

  if ((h = CreateFile(tpath,
                      GENERIC_WRITE,
                      0,
                      NULL,
                      CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL,
                      0)) == INVALID_HANDLE_VALUE)
    {
      error_system(_T("CreateFile"));
      goto end;
    }

  if (!WriteFile(h, text_buf, strlen(text_buf), &dummy, NULL))
    {
      error_system(_T("WriteFile"));
      goto end;
    }

 end:
  if (h)
    CloseHandle(h);
  if (tpath)
    LocalFree(tpath);
}

/*
 * Event handler.
 */
static LRESULT CALLBACK window_proc(HWND window, UINT msg,
                                    WPARAM wparam, LPARAM lparam)
{
  switch (msg)
    {
    case WM_CREATE:
      main_window = window;
      init_empty_area();
      if (!create_menubar() ||
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

    case WM_COMMAND:
      switch (LOWORD(wparam))
        {
        case IDOK:
        case IDM_QUIT:
          SendMessage(window, WM_CLOSE, 0, 0);
          return 0;
        case IDM_REFRESH:
          refresh();
          return 0;
        case IDM_SAVE:
          save();
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
  WSADATA wd;
  WNDCLASS wc;
#if !defined(WIN32_PLATFORM_WFSP) && !defined(WIN32_PLATFORM_PSPC)
  HACCEL accel;
#endif
  MSG msg;
  int result = 0, wsastarted = 0;

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
   * Allocate text buffer.
   */
  if (!(text_buf = LocalAlloc(0, text_max)))
    {
      error_system(_T("LocalAlloc"));
      goto end;
    }

  /*
   * Init winsock.
   */
  if (WSAStartup(MAKEWORD(2, 2), &wd))
    {
      error_code(WSAGetLastError(), _T("LocalAlloc"));
      goto end;
    }
  wsastarted = 1;

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
  if (wsastarted)
    WSACleanup();
  if (text_buf)
    LocalFree(text_buf);
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
    TEXT("QSInfo"),
    MB_OK);

  return 0;
}

#endif /* _WIN32_WCE */
