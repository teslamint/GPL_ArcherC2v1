/*
 *
 * qsconsole.h
 *
 *  Copyright:
 *          Copyright (c) 2006 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Policy manager and engine admin utility for Windows CE.
 *
 */

#ifdef _WIN32_WCE

#if defined(WIN32_PLATFORM_WFSP)

/*
 * SmartPhone resource identifiers.
 */

#define IDR_MENU			200
#define IDR_DIALOG			300
#define IDR_FDIALOG			400
#define IDR_DMENU			500

#define IDM_QUIT			201
#define IDM_MENU			202

#define IDM_FILE			210
#define IDM_FILE_CLEAR			211
#define IDM_FILE_QUIT			212

#define IDM_PM				220
#define IDM_PM_START			221
#define IDM_PM_STOP			222
#define IDM_PM_RECONFIGURE		223
#define IDM_PM_REDO_FLOWS		224



#define IDM_PM_INTERRUPT		226
#define IDM_PM_TERMINATE		227
#define IDM_PM_DEBUGSTRING		228
#define IDM_PM_ARGUMENTS		229
#define IDM_PM_CONFIGFILE		230

#define IDM_ICEPT			240
#define IDM_ICEPT_LOAD			241
#define IDM_ICEPT_UNLOAD		242
#define IDM_ICEPT_DEBUGSTRING		243

#define IDD_TITLE			301
#define IDD_STRING			302

#define IDS_QUIT			801
#define IDS_MENU			802
#define IDS_OK				803

#elif defined(WIN32_PLATFORM_PSPC)

/*
 * PocketPC resource identifiers.
 */

#define IDR_MENU			200
#define IDR_DIALOG			300
#define IDR_FDIALOG			400

#define IDM_FILE			210
#define IDM_FILE_CLEAR			211
#define IDM_FILE_QUIT			212

#define IDM_PM				220
#define IDM_PM_START			221
#define IDM_PM_STOP			222
#define IDM_PM_RECONFIGURE		223
#define IDM_PM_REDO_FLOWS		224



#define IDM_PM_INTERRUPT		226
#define IDM_PM_TERMINATE		227
#define IDM_PM_DEBUGSTRING		228
#define IDM_PM_ARGUMENTS		229
#define IDM_PM_CONFIGFILE		230

#define IDM_ICEPT			240
#define IDM_ICEPT_LOAD			241
#define IDM_ICEPT_UNLOAD		242
#define IDM_ICEPT_DEBUGSTRING		243

#define IDD_TITLE			301
#define IDD_STRING			302

#define IDS_FILE			801
#define IDS_PM				802
#define IDS_ICEPT			803

#else

/*
 * Standard CE resource identifiers.
 */

#define IDR_ACCEL			100
#define IDR_MENU			200
#define IDR_DIALOG			300
#define IDR_FDIALOG			400

#define IDM_FILE_CLEAR			211
#define IDM_FILE_QUIT			212

#define IDM_PM_START			221
#define IDM_PM_STOP			222
#define IDM_PM_RECONFIGURE		223
#define IDM_PM_REDO_FLOWS		224



#define IDM_PM_INTERRUPT		226
#define IDM_PM_TERMINATE		227
#define IDM_PM_DEBUGSTRING		228
#define IDM_PM_ARGUMENTS		229
#define IDM_PM_CONFIGFILE		230

#define IDM_ICEPT_LOAD			241
#define IDM_ICEPT_UNLOAD		242
#define IDM_ICEPT_DEBUGSTRING		243

#define IDD_STRING			302

#endif

/*
 * Process control message.
 */

#define CONTROL_MSG_STOP			0
#define CONTROL_MSG_RECONFIGURE			1
#define CONTROL_MSG_REDO_FLOWS			2



#define CONTROL_MSG_DEBUGSTRING_USERMODE	4
#define CONTROL_MSG_DEBUGSTRING_KERNELMODE	5

typedef struct {
  DWORD type;
  union {
    char string[1000];
  } u;
} control_msg_t;

#endif /* _WIN32_WCE */
