////////////////////////////////////////////////////////////////////////////
// event_log_msg.mc
//
// Author: Timo Tuunanen <ttuunanen@safenet-inc.com>
//
// Copyright (c) 2000 - 2003 SFNT Finland Oy
// All rights reserved.
//
// This file contains the message definitions for Windows event logging
////////////////////////////////////////////////////////////////////////////

//
//  Values are 32 bit values layed out as follows:
//
//   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
//   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
//  +---+-+-+-----------------------+-------------------------------+
//  |Sev|C|R|     Facility          |               Code            |
//  +---+-+-+-----------------------+-------------------------------+
//
//  where
//
//      Sev - is the severity code
//
//          00 - Success
//          01 - Informational
//          10 - Warning
//          11 - Error
//
//      C - is the Customer code flag
//
//      R - is a reserved bit
//
//      Facility - is the facility code
//
//      Code - is the facility's status code
//
//
// Define the facility codes
//
#define FACILITY_RPC_STUBS               0x3
#define FACILITY_RPC_RUNTIME             0x2
#define FACILITY_SSHIPSEC_ERROR_CODE     0x7
#define FACILITY_IO_ERROR_CODE           0x4


//
// Define the severity codes
//


//
// MessageId: SSH_MSG_INFORMATIONAL
//
// MessageText:
//
//  SafeNet QuickSec (Info): %2
//
#define SSH_MSG_INFORMATIONAL            ((NTSTATUS)0x600703E8L)

//
// MessageId: SSH_MSG_NOTICE
//
// MessageText:
//
//  SafeNet QuickSec (Notice): %2
//
#define SSH_MSG_NOTICE                   ((NTSTATUS)0x600703E9L)

//
// MessageId: SSH_MSG_WARNING
//
// MessageText:
//
//  SafeNet QuickSec (Warning): %2
//
#define SSH_MSG_WARNING                  ((NTSTATUS)0xA00703EAL)

//
// MessageId: SSH_MSG_ERROR
//
// MessageText:
//
//  SafeNet QuickSec (Error): %2
//
#define SSH_MSG_ERROR                    ((NTSTATUS)0xE00703EBL)

//
// MessageId: SSH_MSG_CRITICAL
//
// MessageText:
//
//  SafeNet QuickSec (Fatal Error): %2
//
#define SSH_MSG_CRITICAL                 ((NTSTATUS)0xE00703ECL)

