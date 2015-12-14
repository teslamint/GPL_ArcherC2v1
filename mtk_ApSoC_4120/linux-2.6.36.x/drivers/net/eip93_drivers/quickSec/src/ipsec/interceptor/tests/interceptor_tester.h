/*

interceptor_tester.h

Author: Tatu Ylonen <ylo@ssh.fi>

  Copyright:
          Copyright (c) 2002, 2003 SFNT Finland Oy.
              All rights reserved.

Definitions for an interceptor tester packet processing engine.  This
file defines the communication protocol between the tester engine and
the tester policy manager.

*/

#ifndef INTERCEPTOR_TESTER_H
#define INTERCEPTOR_TESTER_H

/* Start basic test.
     uint32      test number */
#define SSH_ENGINE_IPM_TESTER_RUN               200

/* Test completed successfully. */
#define SSH_ENGINE_IPM_TESTER_OK                201

/* Test failed.
     str         message */
#define SSH_ENGINE_IPM_TESTER_FAIL              202


#define SSH_ENGINE_IPM_TESTER_SET_DEBUG         203

#define SSH_ENGINE_IPM_TESTER_NOTIFY_DEBUG      204
#define SSH_ENGINE_IPM_TESTER_NOTIFY_WARNING    205


#define SSH_INTERCEPTOR_TEST_BASIC              1

#define SSH_INTERCEPTOR_TEST_BASIC_PREPEND      0x01
#define SSH_INTERCEPTOR_TEST_BASIC_INSERT       0x02
#define SSH_INTERCEPTOR_TEST_BASIC_DELETE       0x04
#define SSH_INTERCEPTOR_TEST_BASIC_PULLUP       0x08
#define SSH_INTERCEPTOR_TEST_BASIC_ITERATE      0x10



#endif /* INTERCEPTOR_TESTER_H */
