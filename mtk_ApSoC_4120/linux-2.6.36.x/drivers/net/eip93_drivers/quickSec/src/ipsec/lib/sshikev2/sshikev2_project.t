.set project_name sshikev2
.set project_type applib
.set project_platforms
.set project_guid 879259AB-46E4-3D7D-8900-5973249211C4
.set project_dir ipsec\\lib\\sshikev2
.set project_dir_inverse ..\\..\\..
.set project_incdirs \
	. \
	include \
	ipsec \
	ipsec\\lib\\sshisakmp \
	ipsec\\lib\\sshikev2
.set project_defs \
	SSH_BUILD_IPSEC \
	HAVE_CONFIG_H
.set project_cflags
.set project_rcflags
.set project_libdirs
.set project_ldflags
.set project_libs
.set project_dependencies
.set outdir .
.set srcs \
	ikev2-auth-init-in.c \
	ikev2-auth-init-out.c \
	ikev2-auth-resp-in.c \
	ikev2-auth-resp-out.c \
	ikev2-auth2-init-in.c \
	ikev2-auth2-init-out.c \
	ikev2-auth2-resp-in.c \
	ikev2-auth2-resp-out.c \
	ikev2-child-init-in.c \
	ikev2-child-init-out.c \
	ikev2-child-resp-in.c \
	ikev2-child-resp-out.c \
	ikev2-common-info.c \
	ikev2-confutil.c \
	ikev2-crypto.c \
	ikev2-decode.c \
	ikev2-eap-auth.c \
	ikev2-encode.c \
	ikev2-fb-cfgmode-conv.c \
	ikev2-fb-cfgmode.c \
	ikev2-fb-conv.c \
	ikev2-fb-id-conv.c \
	ikev2-fb-init-info.c \
	ikev2-fb-init-p1.c \
	ikev2-fb-init-qm.c \
	ikev2-fb-init.c \
	ikev2-fb-nat-t.c \
	ikev2-fb-policy-certs.c \
	ikev2-fb-policy-p1.c \
	ikev2-fb-policy-p2.c \
	ikev2-fb-policy-qm.c \
	ikev2-fb-sa-conv.c \
	ikev2-fb-ts-conv.c \
	ikev2-fb-util.c \
	ikev2-fb-xauth.c \
	ikev2-groups.c \
	ikev2-ike-rekey-init-in.c \
	ikev2-ike-rekey-init-out.c \
	ikev2-ike-rekey-resp-in.c \
	ikev2-ike-rekey-resp-out.c \
	ikev2-info-init-in.c \
	ikev2-info-init-out.c \
	ikev2-info-resp-in.c \
	ikev2-info-resp-out.c \
	ikev2-init-ike-sa.c \
	ikev2-init-info-sa.c \
	ikev2-init-ipsec-sa.c \
	ikev2-init.c \
	ikev2-ke-error-out.c \
	ikev2-linearize.c \
	ikev2-mobike.c \
	ikev2-multiple-auth.c \
	ikev2-nat-t.c \
	ikev2-packet-decode.c \
	ikev2-packet-encode.c \
	ikev2-pk-auth.c \
	ikev2-prfplus.c \
	ikev2-recv.c \
	ikev2-rekey-ike.c \
	ikev2-render-ike-spi.c \
	ikev2-render-payload.c \
	ikev2-request-cookie-out.c \
	ikev2-sa-init-error.c \
	ikev2-sa-init-init-in.c \
	ikev2-sa-init-init-out.c \
	ikev2-sa-init-resp-in.c \
	ikev2-sa-init-resp-out.c \
	ikev2-sautil.c \
	ikev2-send.c \
	ikev2-shared-key-auth.c \
	ikev2-state-common.c \
	ikev2-state.c \
	ikev2-string-attribute-type.c \
	ikev2-string-auth-method.c \
	ikev2-string-cert-encoding.c \
	ikev2-string-id.c \
	ikev2-string-notify.c \
	ikev2-string-payload.c \
	ikev2-string-protocol.c \
	ikev2-string-transform.c \
	ikev2-tables.c \
	ikev2-tsutil.c \
	ikev2-window.c
.set dir_ikev2-auth-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth2-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth2-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth2-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-auth2-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-child-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-child-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-child-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-child-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-common-info.c ipsec\\lib\\sshikev2 
.set dir_ikev2-confutil.c ipsec\\lib\\sshikev2 
.set dir_ikev2-crypto.c ipsec\\lib\\sshikev2 
.set dir_ikev2-decode.c ipsec\\lib\\sshikev2 
.set dir_ikev2-eap-auth.c ipsec\\lib\\sshikev2 
.set dir_ikev2-encode.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-cfgmode-conv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-cfgmode.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-conv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-id-conv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-init-info.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-init-p1.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-init-qm.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-init.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-nat-t.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-policy-certs.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-policy-p1.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-policy-p2.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-policy-qm.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-sa-conv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-ts-conv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-util.c ipsec\\lib\\sshikev2 
.set dir_ikev2-fb-xauth.c ipsec\\lib\\sshikev2 
.set dir_ikev2-groups.c ipsec\\lib\\sshikev2 
.set dir_ikev2-ike-rekey-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-ike-rekey-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-ike-rekey-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-ike-rekey-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-info-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-info-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-info-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-info-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-init-ike-sa.c ipsec\\lib\\sshikev2 
.set dir_ikev2-init-info-sa.c ipsec\\lib\\sshikev2 
.set dir_ikev2-init-ipsec-sa.c ipsec\\lib\\sshikev2 
.set dir_ikev2-init.c ipsec\\lib\\sshikev2 
.set dir_ikev2-ke-error-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-linearize.c ipsec\\lib\\sshikev2 
.set dir_ikev2-mobike.c ipsec\\lib\\sshikev2 
.set dir_ikev2-multiple-auth.c ipsec\\lib\\sshikev2 
.set dir_ikev2-nat-t.c ipsec\\lib\\sshikev2 
.set dir_ikev2-packet-decode.c ipsec\\lib\\sshikev2 
.set dir_ikev2-packet-encode.c ipsec\\lib\\sshikev2 
.set dir_ikev2-pk-auth.c ipsec\\lib\\sshikev2 
.set dir_ikev2-prfplus.c ipsec\\lib\\sshikev2 
.set dir_ikev2-recv.c ipsec\\lib\\sshikev2 
.set dir_ikev2-rekey-ike.c ipsec\\lib\\sshikev2 
.set dir_ikev2-render-ike-spi.c ipsec\\lib\\sshikev2 
.set dir_ikev2-render-payload.c ipsec\\lib\\sshikev2 
.set dir_ikev2-request-cookie-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sa-init-error.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sa-init-init-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sa-init-init-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sa-init-resp-in.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sa-init-resp-out.c ipsec\\lib\\sshikev2 
.set dir_ikev2-sautil.c ipsec\\lib\\sshikev2 
.set dir_ikev2-send.c ipsec\\lib\\sshikev2 
.set dir_ikev2-shared-key-auth.c ipsec\\lib\\sshikev2 
.set dir_ikev2-state-common.c ipsec\\lib\\sshikev2 
.set dir_ikev2-state.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-attribute-type.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-auth-method.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-cert-encoding.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-id.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-notify.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-payload.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-protocol.c ipsec\\lib\\sshikev2 
.set dir_ikev2-string-transform.c ipsec\\lib\\sshikev2 
.set dir_ikev2-tables.c ipsec\\lib\\sshikev2 
.set dir_ikev2-tsutil.c ipsec\\lib\\sshikev2 
.set dir_ikev2-window.c ipsec\\lib\\sshikev2 
.set custom_tags
.set rsrcs
.set hdrs \
	ikev2-fb-st.h \
	ikev2-fb.h \
	ikev2-internal.h \
	sshikev2-exchange.h \
	sshikev2-fallback.h \
	sshikev2-initiator.h \
	sshikev2-pad.h \
	sshikev2-payloads.h \
	sshikev2-sad.h \
	sshikev2-spd.h \
	sshikev2-util.h \
	sshsad.h
.set dir_ikev2-fb-st.h ipsec\\lib\\sshikev2 
.set dir_ikev2-fb.h ipsec\\lib\\sshikev2 
.set dir_ikev2-internal.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-exchange.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-fallback.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-initiator.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-pad.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-payloads.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-sad.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-spd.h ipsec\\lib\\sshikev2 
.set dir_sshikev2-util.h ipsec\\lib\\sshikev2 
.set dir_sshsad.h ipsec\\lib\\sshikev2 
