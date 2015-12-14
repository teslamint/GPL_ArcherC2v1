/*
  File: ikev2-window.c

  Copyright:
        Copyright 2004 SFNT Finland Oy.
	All rights reserved.

  Description:
  	IKEv2 sliding window.


  Window is per IKE SA.
  For the IKE SA initiator it is populated as follows:

  On IKE SA initiator:

     exchange initiated by IKE SA initiator:
       request - stored in window_i_to_r/request
       response - stored in window_r_to_i/response
     exchange intiated by IKE SA responder
       request - stored in window_r_to_i/request
       response - stored in window_i_to_r/response

  sent request

     Stored into window until ack'd. Retransmited until released by
     response (from the next call to send) or timeout (causing SA
     delete).

  sent response

     Stored into window until overwritten, or the SA is deleted, or
     exchange timer expires. Retransmitted if requested.

  received request

     If the window already has a similar request with same M-ID,
     dropped. Else stored into window to wait for commitment in form
     of update.

  received response

     Stored into window to reject multiples. Release the corresponding
     request from the reverse window.
*/

#include "sshincludes.h"
#include "sshencode.h"
#include "sshikev2-initiator.h"
#include "sshikev2-exchange.h"
#include "sshikev2-util.h"
#include "ikev2-internal.h"


#define SSH_DEBUG_MODULE "SshIkev2NetWindow"

struct SshIkev2WindowFaceRec
{
  SshUInt32 next_id;

  SshUInt32 size;
  SshInt32 left;
  SshInt32 right;
  SshIkev2Packet *packets;

  SshTime last_packet_time; /* time when last packet entered window */
};

typedef struct SshIkev2WindowFaceRec  SshIkev2WindowFaceStruct;
typedef struct SshIkev2WindowFaceRec *SshIkev2WindowFace;

struct SshIkev2WindowRec
{
  SshIkev2WindowFaceStruct req[1]; /* requests */
  SshIkev2WindowFaceStruct rep[1]; /* responses */
};
typedef struct SshIkev2WindowRec  SshIkev2WindowStruct;

/* Requires label 'error' at the lexical scope */
#define ALLOCFACE(_face, _size)					\
do {								\
  if (((_face)->packets =					\
       ssh_calloc((_size), sizeof((_face)->packets[0]))) == NULL)	\
    goto error;							\
  (_face)->next_id = 0;                                         \
  (_face)->size = (_size);					\
  (_face)->left = 0;						\
  (_face)->right = 0;						\
  (_face)->last_packet_time = 0;                                \
} while (0)

#define FREEFACE(_face)	\
do { if ((_face)->packets) ssh_free((_face)->packets); } while (0)

#define IKEV2_PACKET_NONE     (SshIkev2Packet)NULL
#define IKEV2_PACKET_RESERVED (SshIkev2Packet)1

SshIkev2Error
ikev2_udp_window_init(SshIkev2Sa sa)
{
  SshUInt32 req = 1;
  SshUInt32 rep = 1;

  SSH_DEBUG(SSH_D_LOWSTART, ("Allocating transmission windows for SA %p", sa));

  if ((sa->window_i_to_r = ssh_calloc(1, sizeof(*sa->window_i_to_r))) == NULL)
    goto error;
  if ((sa->window_r_to_i = ssh_calloc(1, sizeof(*sa->window_r_to_i))) == NULL)
    goto error;

  ALLOCFACE(sa->window_i_to_r->req, req);
  ALLOCFACE(sa->window_i_to_r->rep, rep);
  ALLOCFACE(sa->window_r_to_i->req, req);
  ALLOCFACE(sa->window_r_to_i->rep, rep);

  return SSH_IKEV2_ERROR_OK;

 error:
  if (sa->window_i_to_r)
    {
      FREEFACE(sa->window_i_to_r->req);
      FREEFACE(sa->window_i_to_r->rep);
      ssh_free(sa->window_i_to_r);
      sa->window_i_to_r = NULL;
    }
  if (sa->window_r_to_i)
    {
      FREEFACE(sa->window_r_to_i->req);
      FREEFACE(sa->window_r_to_i->rep);
      ssh_free(sa->window_r_to_i);
      sa->window_r_to_i = NULL;
    }

  return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
}

static void
ikev2_udp_window_face_clear(SshIkev2Sa sa,
			    SshIkev2WindowFace face)
{
  int i;

  if (face)
    {
      for (i = 0; i < face->size; i++)
	{
	  if (face->packets[i] != IKEV2_PACKET_NONE
	      && face->packets[i] != IKEV2_PACKET_RESERVED)
	    {
	      face->packets[i]->in_window = 1;
	      ikev2_packet_done(sa->server->context, face->packets[i]);
	      face->packets[i] = IKEV2_PACKET_NONE;
	    }
	}
    }
}


static void
ikev2_udp_window_face_free(SshIkev2Sa sa,
			   SshIkev2WindowFace face)
{
  if (face)
    {
      ikev2_udp_window_face_clear(sa, face);
      FREEFACE(face);
    }
}

static void
ikev2_udp_window_face_copy(SshIkev2WindowFace src,
			   SshIkev2WindowFace dst)
{
  SshUInt32 msg, left = src->left;
  SshIkev2Packet packet;

  /* copy messages */
  for (msg = src->left; msg <= src->right; msg++)
    {
      dst->packets[msg % dst->size] = src->packets[msg % src->size];

      /* Patch the packets backpointer to window position. */
      packet = dst->packets[msg % dst->size];

      if (packet != IKEV2_PACKET_NONE
	  && packet != IKEV2_PACKET_RESERVED
	  && packet->in_window)
	{
	  SSH_ASSERT(packet->ed == NULL ||
		     packet->ed->magic == SSH_IKEV2_ED_MAGIC);
	  packet->wptr = &dst->packets[msg % dst->size];
	  SSH_DEBUG(SSH_D_LOWOK,
		    ("Adjust wptr for packet %p to %p %d %d",
		     packet, packet->wptr,
		     packet->in_window, packet->destroyed));
	}
    }

  /* update content */
  dst->left = left;
  dst->right = src->right;
  dst->next_id = src->next_id;
}

SshTime
ssh_ikev2_sa_last_input_packet_time(SshIkev2Sa sa)
{
#ifdef SSHDIST_IKEV1
  if (sa->flags & SSH_IKEV2_IKE_SA_ALLOCATE_FLAGS_IKEV1)
    {
      return sa->last_input_stamp;
    }

#endif /* SSHDIST_IKEV1 */
  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      /* for initiator: i_to_r: rep and r_to_i: req */
      if (sa->window_r_to_i)
	return SSH_MAX(sa->window_r_to_i->rep->last_packet_time,
		       sa->window_r_to_i->req->last_packet_time);
    }
  else
    {
      /* for responder: i_to_r: req and r_to_i: rep */
      if (sa->window_i_to_r)
	return SSH_MAX(sa->window_i_to_r->req->last_packet_time,
		       sa->window_i_to_r->rep->last_packet_time);
    }
  return 0;
}

/* This function encoded the window given at datum into space at char
   buf[len]. The function return the number of bytes required.  The
   window encoding puts in the encoded packets and original request
   hashes, but nothing else.*/
int
ikev2_udp_window_packets_encode(unsigned char *buf, size_t len,
				const void *datum)
{
  size_t offset = 0, total_len, i, n = 0;
  SshIkev2WindowFace face = (SshIkev2WindowFace)datum;
  SshIkev2Packet p;

  offset = ssh_encode_array(buf, len,
			    SSH_ENCODE_UINT32(0),
			    SSH_FORMAT_END);
  if (offset == 0)
    goto error;
  total_len = offset;

  for (i = 0; i < face->size; i++)
    {
      p = face->packets[i];
      if (p != NULL)
	{
	  SSH_DEBUG(SSH_D_LOWOK, ("Encoding packet %d: m-id %ld flags %08lx",
				  i, p->message_id, p->flags));

	  offset =
	    ssh_encode_array(buf + total_len, len - total_len,
			     SSH_ENCODE_UINT32(p->flags),
			     SSH_ENCODE_UINT32(p->message_id),
			     SSH_ENCODE_DATA(
			     p->hash, sizeof(p->hash)),
			     SSH_ENCODE_UINT32_STR(
			     p->encoded_packet, p->encoded_packet_len),
			     SSH_FORMAT_END);
	  if (offset == 0)
	    goto error;
	  total_len += offset;

	  n++;
	}
    }

  /* finally update count */
  SSH_PUT_32BIT(buf, n);

  return total_len;
  
 error:
  return len + 1;
}

static void
ikev2_udp_window_packets_restart_face(SshIkev2 ikev2,
				      SshIkev2Sa sa,
				      SshIkev2WindowFace face)
{
  int i;

  for (i = 0; i < face->size; i++)
    {
      SshIkev2Packet packet;

      packet = face->packets[i];
      if (packet != IKEV2_PACKET_NONE && packet != IKEV2_PACKET_RESERVED)
	{
	  ssh_adt_insert(ikev2->packets_used, packet);

	  packet->server = sa->server;
	  ssh_fsm_thread_init(ikev2->fsm, packet->thread,
			      ikev2_packet_st_done, NULL_FNPTR,
			      ikev2_packet_destroy,
			      packet);
	  ssh_fsm_set_thread_name(packet->thread, "packet thread");
	}
    }
}

void
ikev2_udp_window_packets_restart(SshIkev2Sa sa)
{
  SshIkev2 ikev2 = sa->server->context;

  ikev2_udp_window_packets_restart_face(ikev2, sa, sa->window_i_to_r->req);
  ikev2_udp_window_packets_restart_face(ikev2, sa, sa->window_i_to_r->rep);
  ikev2_udp_window_packets_restart_face(ikev2, sa, sa->window_r_to_i->req);
  ikev2_udp_window_packets_restart_face(ikev2, sa, sa->window_r_to_i->rep);
}

int
ikev2_udp_window_packets_decode(const unsigned char *buf, size_t len,
				void *datum)
{
  SshUInt32 i, n;
  size_t offset = 0, total_len;
  SshIkev2WindowFace face = (SshIkev2WindowFace)datum;
  SshIkev2Packet packet;

  offset = ssh_decode_array(buf, len,
			    SSH_DECODE_UINT32(&n),
			    SSH_FORMAT_END);
  if (offset == 0)
    goto error;
  total_len = offset;

  if (n > face->size)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Cannot fit %ld packets to window face (size %ld)", 
		 n, face->size));
      goto error;
    }

  for (i = 0; i < n; i++)
    {
      SshUInt32 flags, mid;
      size_t encoded_packet_len;
      unsigned char digest[20], *encoded_packet;

      offset =
	ssh_decode_array(buf + total_len, len - total_len,
			 SSH_DECODE_UINT32(&flags),
			 SSH_DECODE_UINT32(&mid),
			 SSH_DECODE_DATA(digest, 20),
			 SSH_DECODE_UINT32_STR_NOCOPY(
			 &encoded_packet, &encoded_packet_len),
			 SSH_FORMAT_END);
      if (offset == 0)
	goto error;
      total_len += offset;

      packet = ikev2_packet_allocate(NULL, NULL_FNPTR);
      if (packet != NULL)
	{
	  packet->flags = flags;
	  packet->message_id = mid;
	  memcpy(packet->hash, digest, sizeof(packet->hash));
	  if (encoded_packet_len)
	    {
	      packet->encoded_packet = ssh_memdup(encoded_packet,
						  encoded_packet_len);
	      if (packet->encoded_packet != NULL)
		packet->encoded_packet_len = encoded_packet_len;
	    }
	  face->packets[mid % face->size] = packet;
	  packet->wptr = &face->packets[mid % face->size];
	  packet->in_window = 1;

	  SSH_DEBUG(SSH_D_LOWOK, ("Decoded packet %d: m-id %ld flags %08lx",
				  i, packet->message_id, packet->flags));
	}
    }

  return total_len;

 error:
  return len + 1;
}

int
ikev2_udp_window_face_encode(unsigned char *buf, size_t len, const void *datum)
{
  SshIkev2WindowFace face = (SshIkev2WindowFace)datum;
  size_t total_len;

  total_len = 
    ssh_encode_array(buf, len,
		     SSH_ENCODE_UINT32(face->size),
		     SSH_ENCODE_UINT32(face->next_id),
		     SSH_ENCODE_UINT32(face->left),
		     SSH_ENCODE_UINT32(face->right),
		     SSH_ENCODE_UINT64(face->last_packet_time),
		     SSH_ENCODE_SPECIAL(
		     ikev2_udp_window_packets_encode, face),
		     SSH_FORMAT_END);
  if (total_len == 0)
    return len + 1;

  SSH_DEBUG(SSH_D_LOWOK,
	    ("Encoded window face: size %ld next_id %ld left %ld right %ld",
	     face->size, face->next_id, face->left, face->right));

  return total_len;
}

int
ikev2_udp_window_face_decode(const unsigned char *buf, size_t len, void *datum)
{
  SshIkev2WindowFace face = datum;
  SshUInt32 size;
  size_t offset = 0, total_len;

  offset = ssh_decode_array(buf, len,
			    SSH_DECODE_UINT32(&size),
			    SSH_FORMAT_END);
  if (offset == 0)
    goto error;
  total_len = offset;

  if (face->size < size)
    {
      FREEFACE(face);
      ALLOCFACE(face, size);
    }

  offset = ssh_decode_array(buf + total_len, len - total_len,
			    SSH_DECODE_UINT32(&face->next_id),
			    SSH_DECODE_UINT32(&face->left),
			    SSH_DECODE_UINT32(&face->right),
			    SSH_DECODE_UINT64(&face->last_packet_time),
			    SSH_DECODE_SPECIAL_NOALLOC(
			    ikev2_udp_window_packets_decode, face),
			    SSH_FORMAT_END);

  if (offset == 0)
    goto error;
  total_len += offset;

  SSH_DEBUG(SSH_D_LOWOK,
	    ("Decoded window face: size %ld next_id %ld left %ld right %ld",
	     face->size, face->next_id, face->left, face->right));

  return total_len;

 error:
  return len +1;
}

int
ikev2_udp_window_encode(unsigned char *buf, size_t len, const void *datum)
{
  SshIkev2Window window = (SshIkev2Window)datum;
  size_t total_len;
  
  total_len =
    ssh_encode_array(buf, len,
		     SSH_ENCODE_SPECIAL(
		     ikev2_udp_window_face_encode, window->rep),
		     SSH_ENCODE_SPECIAL(
		     ikev2_udp_window_face_encode, window->req),
		     SSH_FORMAT_END);
  if (total_len == 0)
    return len + 1;

  return total_len;
}

int
ikev2_udp_window_decode(const unsigned char *buf, size_t len, void *datum)
{
  SshIkev2Window window = datum;
  size_t total_len;

  if (window == NULL)
    return len + 1;

  total_len =
    ssh_decode_array(buf, len,
		     SSH_DECODE_SPECIAL_NOALLOC(
		     ikev2_udp_window_face_decode, &window->rep),
		     SSH_DECODE_SPECIAL_NOALLOC(
		     ikev2_udp_window_face_decode, &window->req),
		     SSH_FORMAT_END);

  if (total_len == 0)
    return len + 1;

  return total_len;
}

SshIkev2Error
ikev2_udp_window_configure(SshIkev2Sa sa,
			   SshUInt32 local, SshUInt32 remote)
{
  SshIkev2WindowFaceStruct faces[4];

  SSH_DEBUG(SSH_D_LOWSTART,
	    ("Reconfiguring transmission windows for SA %p local %d remote %d",
	     sa, (int) local, (int) remote));

  memset(faces, 0, sizeof(faces));

  if (local > SSH_IKEV2_MAX_WINDOW_SIZE)
    {
      SSH_DEBUG(SSH_D_FAIL,
		("Denying request to grow window beyond hard limit of %d",
		 SSH_IKEV2_MAX_WINDOW_SIZE));
      return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
    }

  if (remote > SSH_IKEV2_MAX_WINDOW_SIZE)
    remote = SSH_IKEV2_MAX_WINDOW_SIZE;

  /* Check we are not decreasing the size of the window */
  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      if ((local > 0 && local < sa->window_i_to_r->rep->size) ||
	  (remote > 0 && remote < sa->window_r_to_i->rep->size))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Denying request to reduce window"));
	  return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
	}
    }
  else
    {
      if ((local > 0 && local < sa->window_i_to_r->req->size) ||
	  (remote > 0 && remote < sa->window_r_to_i->req->size))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Denying request to reduce window"));
	  return SSH_IKEV2_ERROR_INVALID_ARGUMENT;
	}
    }

  if (local > 0)
    {
      ALLOCFACE(&faces[0], local);
      ALLOCFACE(&faces[2], local);
    }

  if (remote > 0)
    {
      ALLOCFACE(&faces[1], remote);
      ALLOCFACE(&faces[3], remote);
    }

  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    {
      /* Now move appropriate packets from old to new face. */
      if (local > 0)
	{
	  ikev2_udp_window_face_copy(sa->window_i_to_r->rep, &faces[0]);
	  FREEFACE(sa->window_i_to_r->rep);
	  *sa->window_i_to_r->rep = faces[0];

	  ikev2_udp_window_face_copy(sa->window_r_to_i->req, &faces[2]);
	  FREEFACE(sa->window_r_to_i->req);
	  *sa->window_r_to_i->req = faces[2];
	}

      if (remote > 0)
	{
	  ikev2_udp_window_face_copy(sa->window_i_to_r->req, &faces[1]);
	  FREEFACE(sa->window_i_to_r->req);
	  *sa->window_i_to_r->req = faces[1];

	  ikev2_udp_window_face_copy(sa->window_r_to_i->rep, &faces[3]);
	  FREEFACE(sa->window_r_to_i->rep);
	  *sa->window_r_to_i->rep = faces[3];
	}
    }
  else
    {
      if (local > 0)
	{
	  ikev2_udp_window_face_copy(sa->window_i_to_r->req, &faces[0]);
	  FREEFACE(sa->window_i_to_r->req);
	  *sa->window_i_to_r->req = faces[0];

	  ikev2_udp_window_face_copy(sa->window_r_to_i->rep, &faces[2]);
	  FREEFACE(sa->window_r_to_i->rep);
	  *sa->window_r_to_i->rep = faces[2];
	}

      if (remote > 0)
	{
	  ikev2_udp_window_face_copy(sa->window_i_to_r->rep, &faces[1]);
	  FREEFACE(sa->window_i_to_r->rep);
	  *sa->window_i_to_r->rep = faces[1];

	  ikev2_udp_window_face_copy(sa->window_r_to_i->req, &faces[3]);
	  FREEFACE(sa->window_r_to_i->req);
	  *sa->window_r_to_i->req = faces[3];
	}
    }

  return SSH_IKEV2_ERROR_OK;

 error:
  {
    int i;

    for (i = 0; i < 4; i++) FREEFACE(&faces[i]);
    return SSH_IKEV2_ERROR_OUT_OF_MEMORY;
  }
}

void
ikev2_udp_window_stop(SshIkev2Sa sa)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Clearing transmission windows for SA %p", sa));

  ikev2_udp_window_face_clear(sa, sa->window_i_to_r->req);
  ikev2_udp_window_face_clear(sa, sa->window_i_to_r->rep);
  ikev2_udp_window_face_clear(sa, sa->window_r_to_i->req);
  ikev2_udp_window_face_clear(sa, sa->window_r_to_i->rep);
}

void
ikev2_udp_window_uninit(SshIkev2Sa sa)
{
  SSH_DEBUG(SSH_D_LOWSTART, ("Freeing transmission windows for SA %p", sa));

  if (sa->window_i_to_r)
    {
      ikev2_udp_window_face_free(sa, sa->window_i_to_r->req);
      ikev2_udp_window_face_free(sa, sa->window_i_to_r->rep);
    }
  if (sa->window_r_to_i)
    {
      ikev2_udp_window_face_free(sa, sa->window_r_to_i->req);
      ikev2_udp_window_face_free(sa, sa->window_r_to_i->rep);
    }

  ssh_free(sa->window_r_to_i);
  ssh_free(sa->window_i_to_r);
}

SshIkev2Error
ikev2_udp_window_allocate_id(SshIkev2Sa sa, SshUInt32 *id)
{
  SshUInt32 idx;
  SshIkev2WindowFace window;

  if (sa->flags & SSH_IKEV2_IKE_SA_FLAGS_INITIATOR)
    window = sa->window_i_to_r->req;
  else
    window = sa->window_r_to_i->req;

  idx = window->next_id % window->size;

  if (window->next_id - window->left > window->size)
    {
      SSH_DEBUG(SSH_D_LOWOK,
		("Responder window is full: (size %ld left %ld right %ld)",
		 (long) window->size, (long) window->left,
		 (long) window->right));
      return SSH_IKEV2_ERROR_WINDOW_FULL;
    }

  if (window->packets[idx] == IKEV2_PACKET_NONE)
    {
      *id = window->next_id;
      window->next_id++;
      window->packets[idx] = IKEV2_PACKET_RESERVED;

      SSH_DEBUG(SSH_D_MIDSTART, ("Allocated m-id %ld SA %p",
				 (unsigned long) *id, sa));
      return SSH_IKEV2_ERROR_OK;
    }

  SSH_DEBUG(SSH_D_FAIL,
	    ("Window already contains a packet %p (m-id %ld) at slot %d",
	     window->packets[idx],
	     (long)
	     ((window->packets[idx] != IKEV2_PACKET_NONE &&
	       window->packets[idx] != IKEV2_PACKET_RESERVED)
	      ? window->packets[idx]->message_id : -1),
	     (int) idx));

  return SSH_IKEV2_ERROR_WINDOW_FULL;
}

static void
ikev2_udp_window_faces(SshIkev2Packet packet,
		       SshIkev2WindowFace *fface,
		       SshIkev2WindowFace *rface)
{
  Boolean initiator, response;
  SshIkev2Sa sa = packet->ike_sa;

  SSH_ASSERT(sa != NULL);

  initiator = (packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR);
  response = (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE);

  if (initiator)
    {
      if (response)
	{
	  *fface = sa->window_i_to_r->rep;
	  *rface = sa->window_r_to_i->req;
	}
      else
	{
	  *fface = sa->window_i_to_r->req;
	  *rface = sa->window_r_to_i->rep;
	}
    }
  else
    {
      if (response)
	{
	  *fface = sa->window_r_to_i->rep;
	  *rface = sa->window_i_to_r->req;
	}
      else
	{
	  *fface = sa->window_r_to_i->req;
	  *rface = sa->window_i_to_r->rep;
	}
    }
}

/* This function checks the transmission window for the received
   packet. If the input request packet yields into retransmission, the
   response packet to be retransmitted is returned. If the input
   packet is a response, this does not happen.

   If this yields into drop (e.g. the packet has been delivered to
   local, but not yet answered, or this is an unsolicited response),
   NULL is returned.

   If the packet is to be sent to local, the original input packet is
   returned. */

SshIkev2Packet
ikev2_udp_window_check(SshIkev2Packet packet)
{
  SshIkev2WindowFace fface, rface;
  SshUInt32 fidx, ridx, left;
  SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);
  Boolean initiator, response;

  SSH_ASSERT(packet->received);

  initiator = (packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR);
  response = (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE);

  ikev2_udp_window_faces(packet, &fface, &rface);

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART,
		  ("Window check (fwd=%p rev=%p): m-id %ld %s%s; %s",
		   fface, rface,
		   (long)
		   packet->message_id,
		   initiator ? "I" : " ",
		   response ? "R" : " ",
		   packet->received ? "received" : "sent"));

  /* Calculate hash of the packet, store it into packet. */
  ssh_hash_reset(ikev2->hash);
  ssh_hash_update(ikev2->hash,
		  packet->encoded_packet, packet->encoded_packet_len);
  ssh_hash_final(ikev2->hash, packet->hash);

  fidx = packet->message_id % fface->size;
  ridx = packet->message_id % rface->size;

  /* If we receive a packet that asserts response bit, we need to
     check if we have requested that response, e.g. sent a message
     with the same message id, and have not yet seen the same
     response.  */
  if (response)
    {
      SshIkev2Packet request;

      /* Check for duplicate responses */
      if (fface->packets[fidx] != IKEV2_PACKET_NONE
	  && fface->packets[fidx] != IKEV2_PACKET_RESERVED
	  && fface->packets[fidx]->message_id == packet->message_id
	  && memcmp(packet->hash,
		    fface->packets[fidx]->hash,
		    sizeof(packet->hash)) == 0)
	{
	  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			  ("DROP: Duplicate response: Already seen."));
	  return NULL;
	}

      /* Does ID from packet fall out of our send window? */
      if (packet->message_id < rface->left ||
	  packet->message_id > rface->right)
	{
	  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			  ("DROP: Unsolicit response: "
			   "Outside of window or not requested."));
	  return NULL;
	}

      /* Check for the matching request */
      request = rface->packets[ridx];
      if (request != IKEV2_PACKET_NONE && request != IKEV2_PACKET_RESERVED)
	{
	  if (request->sent == 0)
	    {
	      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
			      ("DROP: Response to unsent request %p "
			       "with m-id %ld",
			       request, (long) packet->message_id));
	      return NULL;
	    }

	  if (request->message_id == packet->message_id
	      && request->exchange_type == packet->exchange_type)
	    {
	      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			      ("PASS: Requested response for %p: "
			       "Sending to SM.",
			       rface->packets[ridx]));

	      /* Assign the exchange data from the sent
		 request. However, do not stop retransmissions yet, as
		 the packet may not get updated if authentication for
		 it response fails. */
	      packet->ed = request->ed;
	      ikev2_reference_exchange_data(request->ed);
	      SSH_ASSERT(packet->ed->magic == SSH_IKEV2_ED_MAGIC);
	      return packet;
	    }
	}

      /* Bad request packet, discard it. */
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
		      ("DROP: Response within window but no request, "
		       "or for non matching m-id or exchange"));
      return NULL;
    }
  else
    {
      /* Does Id from this request fall within the receive window? If
	 so, check if this is retransmitted request, and if we have
	 answered that */
      if (packet->message_id < fface->left)
	{
	  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			  ("DROP: "
			   "Too old request, left of window"));
	  return NULL;
	}

      if (packet->message_id <= fface->right)
	{
	  Boolean id_seen = FALSE;

	  /* Have we received packet with the same message id? */
	  if (fface->packets[fidx] != IKEV2_PACKET_NONE
	      && fface->packets[fidx] != IKEV2_PACKET_RESERVED
	      && fface->packets[fidx]->message_id == packet->message_id)
	    {
	      if (memcmp(packet->hash,
			 fface->packets[fidx]->hash,
			 sizeof(packet->hash)) == 0)
		{
		  /* We have seen the exact request. Did we send a
		     response? If so, retransmit the response and drop
		     this packet.*/

		  if (rface->left <= packet->message_id
		      && packet->message_id <= rface->right)
		    {
		      if (rface->packets[ridx] != NULL
			  && (rface->packets[ridx]->message_id ==
			      packet->message_id))
			{
			  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
					  ("RETRANSMIT: "
					   "Duplicate request: "
					   "Already responded with %p.",
					   rface->packets[ridx]));

			  /* We have sent a response, return that and
			     terminate this. */
			  if (rface->packets[ridx]->encoded_packet_len != 0)
			    {
			      ikev2_packet_done(packet->server->context,
						packet);
			      return rface->packets[ridx];
			    }
			  else
			    return NULL;
			}
		    }
		  else
		    {
		      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
				      ("DROP: "
				       "Duplicate request: "
				       "Currently being processed at SM or "
				       "already rejected as bad."));
		      return NULL;
		    }
		}
	      else
		{
		  /* We have seen a request with this ID, but it was
		     different */
		  id_seen = TRUE;
		}
	    } /* end of message id already seen */

	  /* If we did not retransmit or drop, store this request
	     packet */
	  if (fface->packets[fidx] == IKEV2_PACKET_NONE
	      || fface->packets[fidx] == IKEV2_PACKET_RESERVED)
	    {
	      packet->wptr = &fface->packets[fidx];
	      fface->packets[fidx] = packet;
	    }
	  else
	    {
	      if (id_seen)
		{
		  if (!fface->packets[fidx]->in_window)
		    {
		      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
				      ("HOLD: Duplicate request ID: "
				       "ID seen with different packet."));

		      packet->next = fface->packets[fidx]->next;
		      fface->packets[fidx] = packet;
		    }
		  else
		    {
		      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
				      ("DROP: Duplicate request ID: "
				       "ID seen with a committed packet"));
		    }

		  if (packet->ike_sa)
		    {
		      ssh_ikev2_ike_sa_free(packet->ike_sa);
		      packet->ike_sa = NULL;
		    }
		  return NULL;
		}
	      else
		{
		  /* Do we have old packet on this slot (already
		     fallen out from left hand side)? If so, release
		     the packet and let this packet in. */
		  if (fface->packets[fidx]
		      && fface->packets[fidx]->message_id < fface->left)
		    {
		      ikev2_packet_done(packet->server->context,
					fface->packets[fidx]);
		      fface->packets[fidx] = IKEV2_PACKET_NONE;
		    }
		}
	    }

	  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			  ("PASS: New request: inside the window."));
	  return packet;
	}

      /* Lookup first empty slot from left. */
      for (left = fface->left; left <= fface->left + fface->size; left++)
	{
	  /* Empty or reserved window slot: we have not received any 
	     authenticated packet with a message ID for that slot. */
	  if (fface->packets[left % fface->size] == IKEV2_PACKET_NONE
	      || fface->packets[left % fface->size] == IKEV2_PACKET_RESERVED)
	    break;
	  
	  /* Packet with left-of-window message-id: we have not received
	     a packet with in-window message-id for that slot. */
	  if (fface->packets[left % fface->size]->message_id < fface->left)
	    break;
	  
	  /* Right window side reached. */
	  if (left > fface->right)
	    break;
	}

      SSH_DEBUG(SSH_D_LOWOK,
		("Leftmost non-received message id %ld", (long) left));
      SSH_ASSERT(left <= (fface->right + 1));
      SSH_ASSERT(left >= fface->left);

      if ((left + fface->size) <= packet->message_id)
	{
	  SSH_IKEV2_DEBUG(SSH_D_LOWOK,
			  ("DROP: Peer does not obey window size "
			   "received packet with "
			   "m-id %ld left %ld right %ld size %ld",
			   (long) packet->message_id,
			   (long) fface->left,
			   (long) fface->right,
			   (long) fface->size));
	  return NULL;
	}

      SSH_ASSERT(packet->message_id > fface->right);
      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
		      ("PASS: New request: outside the window."));

      return packet;
    }
}

/* This function makes space for committed 'packet' on the given side
   'face' of the window, at slot 'idx'. It completes the packets
   possibly present at that slot (except the subject packet, which now
   gets accepted), and then forwards the window left and right hand
   appropriately. */
static void
ikev2_udp_window_make_space(SshIkev2WindowFace face, SshUInt32 idx,
			    SshIkev2Packet packet)
{
  SshIkev2Packet old;

  old = face->packets[idx];
  if (old != IKEV2_PACKET_NONE && old != IKEV2_PACKET_RESERVED)
    {
      SshIkev2Packet next;

      /* If this window slot contains multiple packets, get rid of all
	 of them (except for this - now accepted - packet). */
      while (old)
	{
	  next = old->next;

	  if (old == packet)
	    {
	      old = next;
	      continue;
	    }

	  SSH_IKEV2_DEBUG(SSH_D_LOWOK, ("Free old packet %p.", old));
	  if (old->in_window)
	    {
	      ikev2_packet_done(packet->server->context, old);
	    }
	  old = next;
	}
      face->packets[idx] = IKEV2_PACKET_NONE;
    }

  /* Check if to forward right hand */
  if (face->right < packet->message_id)
    face->right = packet->message_id;

  /* And left */
  if (face->size != 1)
    {
      if (face->right >= face->size)
	face->left = face->right - face->size + 1;
    }
  else
    {
      face->left = packet->message_id;
    }
}

/* Update window for sent packets, and complete processing for
   received packets. */
void
ikev2_udp_window_update(SshIkev2Packet packet)
{
  SshIkev2WindowFace fface, rface;
  SshUInt32 i, fidx, ridx;
  SshIkev2 ikev2 = ssh_fsm_get_gdata(packet->thread);
  Boolean initiator, response;

  initiator = (packet->flags & SSH_IKEV2_PACKET_FLAG_INITIATOR);
  response = (packet->flags & SSH_IKEV2_PACKET_FLAG_RESPONSE);

  ikev2_udp_window_faces(packet, &fface, &rface);

  SSH_IKEV2_DEBUG(SSH_D_MIDSTART,
		  ("Window update (fwd=%p, rev=%p): m-id %ld %s%s; %s",
		   fface, rface,
		   (long) packet->message_id,
		   initiator ? "I" : " ",
		   response ? "R" : " ",
		   packet->received ? "received" : "sent"));


  /* Calculate hash of the sent packet. */
  if (!packet->received)
    {
      ssh_hash_reset(ikev2->hash);
      ssh_hash_update(ikev2->hash,
		      packet->encoded_packet, packet->encoded_packet_len);
      ssh_hash_final(ikev2->hash, packet->hash);
    }

  fidx = packet->message_id % fface->size;
  ridx = packet->message_id % rface->size;

  if (packet->message_id < fface->left)
    {
      SSH_IKEV2_DEBUG(SSH_D_NETGARB,
		      ("WND: update with MId=%ld out of Wnd=[%ld,%ld]",
		       (long) packet->message_id,
		       (long) fface->left, (long) fface->right));
      return;
    }
  else
    {
      /* slide forward */
      ikev2_udp_window_make_space(fface, fidx, packet);
      SSH_IKEV2_DEBUG(SSH_D_LOWOK,
		      ("Packet in window (or cause slide): "
		       "m-id %ld left %ld right %ld size %ld",
		       (long) packet->message_id, (long) fface->left,
		       (long) fface->right, (long) fface->size));

    }

  if (response)
    {
      if (packet->received)
	{
	  SshIkev2Packet request;

	  /* We are committing to a received response. Now we stop
	     retransmission for the request this response ack's. Also
	     we Forward left and/or right hand of the send window to
	     indicate that we can send more. */

	  request = rface->packets[ridx];
	  if (request != IKEV2_PACKET_NONE && request != IKEV2_PACKET_RESERVED)
	    {
	      Boolean clear;

	      /* Stop the retransmissions on the next timer. Clear
		 exchange data pointer from the request. The request
		 will disappear when the packet gets destroyed at the
		 end of send-chain (or gets overwritten with a new
		 packet). */

	      SSH_ASSERT(request->message_id == packet->message_id);
	      SSH_ASSERT(request->ed->magic == SSH_IKEV2_ED_MAGIC);

	      request->response_received = 1;

	      if (request->ed)
		{
		  ikev2_free_exchange_data(request->ed->ike_sa, request->ed);
		  request->ed = NULL;
		}
	      request->wptr = NULL;
	      request->in_window = 0;

	      ssh_fsm_continue(request->thread);

	      /* Give up the eference to IKE SA taken when the packet
		 was sent and decrement packet reference count, so it
		 can be removed. */
	      if (request->ike_sa)
		{
		  ssh_ikev2_ike_sa_free(request->ike_sa);
		  request->ike_sa = NULL;
		}
	      rface->packets[ridx] = IKEV2_PACKET_NONE;

	      /* Check if we can forward the left hand, e.g. if we
		 ack'd packets prior to this. */
	      clear = TRUE;
	      for (i = rface->left; i <= rface->right; i++)
		{
		  if (rface->packets[i % rface->size] != IKEV2_PACKET_RESERVED
		      && rface->packets[i % rface->size] != IKEV2_PACKET_NONE)
		    {
		      rface->left =
			rface->packets[i % rface->size]->message_id;

		      clear = FALSE;
		      SSH_DEBUG(SSH_D_LOWOK,
				("forwarding left of requests to %ld",
				 (long) rface->left));
		      break;
		    }
		}
	      if (clear)
		rface->left = packet->message_id;

	      SSH_IKEV2_DEBUG(SSH_D_MIDOK,
			      ("STOP-RETRANSMIT: Response to request %p "
			       "with m-id %ld",
			       request, (long) packet->message_id));
	    }
	}
      else
	{
	  /* Sent responses do not have references to IKE SA's, nor do
	     they store ED. */
	}
    }

  SSH_ASSERT(packet->ed == NULL ||
	     packet->ed->magic == SSH_IKEV2_ED_MAGIC);
  /* Store packet into window */
  packet->wptr = &fface->packets[fidx];
  packet->in_window = 1;
  fface->packets[fidx] = packet;
  fface->last_packet_time = ssh_time();

  SSH_IKEV2_DEBUG(SSH_D_MIDOK, ("Stored packet into window %p", fface));
}

void
ikev2_window_set_retransmit_count(SshIkev2Sa ike_sa,
				  SshUInt16 retransmit_counter)
{
  int i;

  SSH_DEBUG(SSH_D_NICETOKNOW,
	    ("Setting retransmit count to %d for pending requests "
	     "of IKE SA %p",
	     (int) retransmit_counter, ike_sa));
  
  for (i = 0; i < ike_sa->window_i_to_r->req->size; i++)
    {
      if (ike_sa->window_i_to_r->req->packets[i] != IKEV2_PACKET_NONE
	  && ike_sa->window_i_to_r->req->packets[i] != IKEV2_PACKET_RESERVED
	  && (ike_sa->window_i_to_r->req->packets[i]->retransmit_counter
	      < retransmit_counter))
	ike_sa->window_i_to_r->req->packets[i]->retransmit_counter
	  = retransmit_counter;
    }

  for (i = 0; i < ike_sa->window_r_to_i->req->size; i++)
    {
      if (ike_sa->window_r_to_i->req->packets[i] != IKEV2_PACKET_NONE
	  && ike_sa->window_r_to_i->req->packets[i] != IKEV2_PACKET_RESERVED
	  && (ike_sa->window_r_to_i->req->packets[i]->retransmit_counter
	      < retransmit_counter))
	ike_sa->window_r_to_i->req->packets[i]->retransmit_counter
	  = retransmit_counter;
    }
}

#ifdef SSHDIST_IKE_MOBIKE
void 
ikev2_window_change_server(SshIkev2Sa ike_sa,
			   SshIkev2Server server)
{
  SshIkev2WindowFace face = NULL;
  SshUInt32 step, i;

  SSH_DEBUG(SSH_D_MIDOK, ("Moving IKE SA %p packets in window to server %p",
			  ike_sa, server));

  for (step = 0; step < 4; step++)
    {
      switch (step)
	{
	case 0:
	  face = ike_sa->window_r_to_i->req;
	  break;
	case 1:
	  face = ike_sa->window_r_to_i->rep;
	  break;
	case 2:
	  face = ike_sa->window_i_to_r->req;
	  break;
	case 3:
	  face = ike_sa->window_i_to_r->rep;
	  break;
	default:
	  SSH_NOTREACHED;
	  break;
	}
	  
      for (i = 0; i < face->size; i++)
	{
	  SSH_ASSERT(face->packets[i] != IKEV2_PACKET_RESERVED);

	  if (face->packets[i] == IKEV2_PACKET_NONE)
	    continue;

	  if (face->packets[i]->server != server) 
	    {
	      SSH_DEBUG(SSH_D_NICETOKNOW, ("Packet %p old server %p",
					   face->packets[i], 
					   face->packets[i]->server)); 
	      face->packets[i]->server = server;
	      if (face->packets[i]->ed)
		face->packets[i]->ed->multiple_addresses_used = 1;
	    }
	}
    }
}
#endif /* SSHDIST_IKE_MOBIKE */
/* eof */
