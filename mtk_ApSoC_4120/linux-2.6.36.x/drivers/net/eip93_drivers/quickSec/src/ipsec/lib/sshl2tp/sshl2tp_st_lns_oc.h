/*
 *
 * sshl2tp_st_lns_oc.h
 *
 * Author: Markku Rossi <mtr@ssh.fi>
 *
*  Copyright:
*          Copyright (c) 2002, 2003 SFNT Finland Oy.
 *               All rights reserved.
 *
 * LNS outgoing call (initiator).
 *
 */

#ifndef SSHL2TP_ST_LNS_OC_H
#define SSHL2TP_ST_LNS_OC_H

/* Prototypes for state functions. */

SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_idle);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_tunnel);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_reply);
SSH_FSM_STEP(ssh_l2tp_fsm_lns_oc_wait_connect);

#endif /* not SSHL2TP_ST_LNS_OC_H */
