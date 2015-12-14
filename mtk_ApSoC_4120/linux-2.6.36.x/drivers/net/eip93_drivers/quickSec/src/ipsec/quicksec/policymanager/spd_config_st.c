/*
 * spd_config_st.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2005 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Configuration thread that schedules user's configuration changes to
 * the main thread.
 *
 */

#include "sshincludes.h"
#include "quicksecpm_internal.h"

#define SSH_DEBUG_MODULE "SshPmStConfig"

/*************************** Config thread states ***************************/

SSH_FSM_STEP(ssh_pm_st_config_start)
{
  SshPm pm = (SshPm) thread_context;
  SshADTHandle handle;
  SshPmRule rule;

  /* Wait until PM does not have an active configuration batch. */
  if (pm->batch_active)
    SSH_FSM_CONDITION_WAIT(&pm->main_thread_cond);

  /* Check policy manager shutdown. */
  if (ssh_pm_get_status(pm) == SSH_PM_STATUS_DESTROYED)
    {
      /* Abort this configuration update batch. */

      SSH_DEBUG(SSH_D_FAIL,
                ("Policy manager is shutting down: aborting batch"));

      /* Free pending additions and deletions. */
      ssh_adt_clear(pm->config_pending_additions);
      ssh_adt_clear(pm->config_pending_deletions);

      /* Notify user. */
      (*pm->config_callback)(pm, FALSE, pm->config_callback_context);

      /* Notify the main thread that we have finished. */
      pm->config_active = 0;
      SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

      /* We are done. */
      return SSH_FSM_FINISH;
    }


  /* Great, we got the next configuration batch. */
  SSH_ASSERT(pm->batch.additions == NULL);
  SSH_ASSERT(pm->batch.deletions == NULL);

  /* Schedule additions, this is done by stealing the configuration
     additions container. */
  pm->batch.additions = pm->config_pending_additions;
  pm->config_pending_additions = NULL;

  /* Convert delete requests into real delete flags.  Also mark that
     the rule belongs to the active batch. */
  if (pm->config_pending_deletions)
    {
      for (handle = ssh_adt_enumerate_start(pm->config_pending_deletions);
	   handle != SSH_ADT_INVALID;
	   handle = ssh_adt_enumerate_next(pm->config_pending_deletions, 
					   handle))
	{
	  rule = ssh_adt_get(pm->config_pending_deletions, handle);
	  rule->flags |= (SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);

	  SSH_DEBUG(SSH_D_MIDOK, ("Mark rule (id=%d) as deleted", 
				  rule->rule_id));

	  /* Mark subrules to be deleted. */
	  for (rule = rule->sub_rule; rule != NULL; rule = rule->sub_rule)
	    {
	      SSH_ASSERT(rule->flags & SSH_PM_RULE_I_SYSTEM);
	      SSH_DEBUG(SSH_D_MIDOK, 
			("Mark sub rule (id=%d) as deleted",
			 rule->rule_id));
	      rule->flags |=  
		(SSH_PM_RULE_I_IN_BATCH | SSH_PM_RULE_I_DELETED);
	      ssh_adt_insert(pm->config_pending_deletions, rule);
	    }
	}
    }

  pm->batch.deletions = pm->config_pending_deletions;
  pm->config_pending_deletions = NULL;

  /* Set completion callback. */
  pm->batch.status_cb = pm->config_callback;
  pm->batch.status_cb_context = pm->config_callback_context;

  /* The batch is now ready.  Let's notify the main thread. */
  pm->batch_active = 1;
  pm->batch_changes = 0;
  SSH_FSM_CONDITION_BROADCAST(&pm->main_thread_cond);

  /* And we are done. */
  pm->config_active = 0;

  return SSH_FSM_FINISH;
}
