/*
 *
 * qssetup.h
 *
 *  Copyright:
 *          Copyright (c) 2008 SFNT Finland Oy.
 *               All rights reserved.
 *
 * Quicksec Install/Uninstall utility for Windows CE.
 *
 */

#ifndef QS_SETUP_H
#define QS_SETUP_H

#ifdef _WIN32_WCE

#define IDS_TITLE 1

/* We are declaring types and functions which are equivalent to the 
   standard ce_setup.h */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Macro which makes exporting from a DLL easy. */
#ifdef QS_SETUP_EXPORTS
#define QS_SETUP_API __declspec(dllexport)
#else
#define QS_SETUP_API __declspec(dllimport)
#endif

/* Install_Init is called before any part of the application is installed */

typedef enum
{
  /* Continue with the installation */
  codeINSTALL_INIT_CONTINUE = 0,
  /* Immediately cancel the installation */
  codeINSTALL_INIT_CANCEL 
} codeINSTALL_INIT;

QS_SETUP_API
codeINSTALL_INIT 
Install_Init(HWND hwndParent,
             BOOL fFirstCall, 
             BOOL fPreviouslyInstalled,
             LPCTSTR pszInstallDir);

/* Install_Exit is called after the application is installed */
typedef enum
{
  /* Exit the installation successfully */
  codeINSTALL_EXIT_DONE = 0,
  /* Uninstall the application before exiting the installation */
  codeINSTALL_EXIT_UNINSTALL    
} codeINSTALL_EXIT;

QS_SETUP_API
codeINSTALL_EXIT 
Install_Exit(HWND hwndParent,
             LPCTSTR pszInstallDir, /* Final install directory */
             WORD cFailedDirs,
             WORD cFailedFiles,
             WORD cFailedRegKeys,
             WORD cFailedRegVals,
             WORD cFailedShortcuts);

/* Uninstall_Init is called before the application is uninstalled */
typedef enum
{
  /* Continue with the uninstallation */
  codeUNINSTALL_INIT_CONTINUE = 0,
  /* Immediately cancel the uninstallation */
  codeUNINSTALL_INIT_CANCEL
} codeUNINSTALL_INIT;

QS_SETUP_API 
codeUNINSTALL_INIT 
Uninstall_Init(HWND hwndParent,
               LPCTSTR pszInstallDir);

/* Uninstall_Exit is called after the application is uninstalled */
typedef enum
{
  /* Exit the uninstallation successfully */
  codeUNINSTALL_EXIT_DONE = 0
} codeUNINSTALL_EXIT;

QS_SETUP_API 
codeUNINSTALL_EXIT 
Uninstall_Exit(HWND hwndParent);

#ifdef __cplusplus
};
#endif

#endif /* _WIN32_WCE */

#endif /* QS_SETUP_H */


