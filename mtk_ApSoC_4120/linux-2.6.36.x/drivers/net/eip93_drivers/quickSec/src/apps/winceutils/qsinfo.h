/*
 *
 * qsinfo.h
 *
 *  Copyright:
 *          Copyright (c) 2007 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Information retrieval utility for Windows CE.
 *
 */

#ifdef _WIN32_WCE

#if defined(WIN32_PLATFORM_WFSP)

/*
 * SmartPhone resource identifiers.
 */

#define IDR_MENU			200

#define IDM_REFRESH			201
#define IDM_MENU			202

#define IDM_SAVE			220
#define IDM_QUIT			230

#define IDS_REFRESH			801
#define IDS_MENU			802

#elif defined(WIN32_PLATFORM_PSPC)

/*
 * PocketPC resource identifiers.
 */

#define IDR_MENU			200

#define IDM_REFRESH			201
#define IDM_MENU			202

#define IDM_SAVE			220
#define IDM_QUIT			230

#define IDS_REFRESH			801
#define IDS_MENU			802

#else

/*
 * Standard CE resource identifiers.
 */

#define IDR_ACCEL			100
#define IDR_MENU			200

#define IDM_REFRESH			210
#define IDM_SAVE			220
#define IDM_QUIT			230

#endif

#endif /* _WIN32_WCE */
