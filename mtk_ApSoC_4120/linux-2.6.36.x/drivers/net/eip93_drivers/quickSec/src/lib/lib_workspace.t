.set workspace_name lib
.set guid_sshcore 259EAF88-CA28-3380-9700-C18375175008
.set file_sshcore sshutil\\sshcore\\sshcore.vcproj
.set dependencies_sshcore \
	include
.set platforms_sshcore
.set build_sshcore yes
.set guid_sshadt 4F11E88E-9933-3BA0-9600-A983E1E53D1B
.set file_sshadt sshutil\\sshadt\\sshadt.vcproj
.set dependencies_sshadt \
	include
.set platforms_sshadt
.set build_sshadt yes
.set guid_ssheloop 6E65EAF3-0803-31A1-9400-C85DB357FF80
.set file_ssheloop sshutil\\ssheloop\\ssheloop.vcproj
.set dependencies_ssheloop \
	include
.set platforms_ssheloop
.set build_ssheloop yes
.set guid_sshstrutil 82FBF629-E182-3FB9-9F00-77FE7DA7D84A
.set file_sshstrutil sshutil\\sshstrutil\\sshstrutil.vcproj
.set dependencies_sshstrutil \
	include
.set platforms_sshstrutil
.set build_sshstrutil yes
.set guid_hello 5D41402A-BC4B-3A76-9900-9D911017C592
.set file_hello sshutil\\sshfsm\\tutorial\\hello.vcproj
.set dependencies_hello \
	include \
	sshadt \
	sshcore \
	ssheloop \
	sshfsm \
	sshstrutil
.set platforms_hello
.set build_hello yes
.set guid_hello2 6E809CBD-A073-3AC4-8400-16A59016F954
.set file_hello2 sshutil\\sshfsm\\tutorial\\hello2.vcproj
.set dependencies_hello2 \
	include \
	sshadt \
	sshcore \
	ssheloop \
	sshfsm \
	sshstrutil
.set platforms_hello2
.set build_hello2 yes
.set guid_yield 16F10DFD-541C-3336-8400-B4E513ADF0A1
.set file_yield sshutil\\sshfsm\\tutorial\\yield.vcproj
.set dependencies_yield \
	include \
	sshadt \
	sshcore \
	ssheloop \
	sshfsm \
	sshstrutil
.set platforms_yield
.set build_yield yes
.set guid_producer-consumer 07DD31B8-513F-3F71-8600-89B5654CD50D
.set file_producer-consumer sshutil\\sshfsm\\tutorial\\producer-consumer.vcproj
.set dependencies_producer-consumer \
	include \
	sshadt \
	sshcore \
	ssheloop \
	sshfsm \
	sshstrutil
.set platforms_producer-consumer
.set build_producer-consumer yes
.set guid_timeout 90272DDA-245A-31FB-9C00-97E91A8689DC
.set file_timeout sshutil\\sshfsm\\tutorial\\timeout.vcproj
.set dependencies_timeout \
	include \
	sshadt \
	sshcore \
	ssheloop \
	sshfsm \
	sshstrutil
.set platforms_timeout
.set build_timeout yes
.set guid_sshfsm 8900C0FD-960F-359A-8C00-9B420E706302
.set file_sshfsm sshutil\\sshfsm\\sshfsm.vcproj
.set dependencies_sshfsm \
	include
.set platforms_sshfsm
.set build_sshfsm yes
.set guid_sshstream BE7CDA3E-818D-3765-8C00-3A05D4B12F65
.set file_sshstream sshutil\\sshstream\\sshstream.vcproj
.set dependencies_sshstream \
	include
.set platforms_sshstream
.set build_sshstream yes
.set guid_sshsysutil 91AE84FB-3C30-3B57-8900-C794F1BE5CAD
.set file_sshsysutil sshutil\\sshsysutil\\sshsysutil.vcproj
.set dependencies_sshsysutil \
	include
.set platforms_sshsysutil
.set build_sshsysutil yes
.set guid_sshnet E6E2CD1C-CBDD-39F7-8900-1B19140A1334
.set file_sshnet sshutil\\sshnet\\sshnet.vcproj
.set dependencies_sshnet \
	include
.set platforms_sshnet
.set build_sshnet yes
.set guid_sshmisc E4CC88BD-FC51-30C8-9300-AA06B6E25C47
.set file_sshmisc sshutil\\sshmisc\\sshmisc.vcproj
.set dependencies_sshmisc \
	include
.set platforms_sshmisc
.set build_sshmisc yes
.set guid_sshaudit 76DEEAB9-A2D3-35A6-8400-EE313F932877
.set file_sshaudit sshutil\\sshaudit\\sshaudit.vcproj
.set dependencies_sshaudit \
	include
.set platforms_sshaudit
.set build_sshaudit yes
.set guid_sshpacketstream D3F312E3-B689-32DA-8500-B2A045D86CF3
.set file_sshpacketstream sshutil\\sshpacketstream\\sshpacketstream.vcproj
.set dependencies_sshpacketstream \
	include
.set platforms_sshpacketstream
.set build_sshpacketstream yes
.set guid_sshtestutil 199C3F03-A1E0-3EC2-8100-45998DD80F2A
.set file_sshtestutil sshutil\\sshtestutil\\sshtestutil.vcproj
.set dependencies_sshtestutil \
	include
.set platforms_sshtestutil
.set build_sshtestutil yes
.set guid_t-decay A7CBEEF6-FAB9-375C-8300-283063824B1C
.set file_t-decay sshutil\\tests\\t-decay.vcproj
.set dependencies_t-decay \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-decay
.set build_t-decay yes
.set guid_t-base64 415B5DF6-126B-3D0D-9800-16ED6A3FFB3A
.set file_t-base64 sshutil\\tests\\t-base64.vcproj
.set dependencies_t-base64 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-base64
.set build_t-base64 yes
.set guid_t-debug EE8A104B-7DBD-3171-9900-623FADC3F9C6
.set file_t-debug sshutil\\tests\\t-debug.vcproj
.set dependencies_t-debug \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-debug
.set build_t-debug yes
.set guid_t-c64 FCD88241-A8AE-3230-8B00-F26DCB1936E2
.set file_t-c64 sshutil\\tests\\t-c64.vcproj
.set dependencies_t-c64 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-c64
.set build_t-c64 yes
.set guid_t-ipaddr-print EE4D98F7-C326-30DD-8000-6352B7D6C39E
.set file_t-ipaddr-print sshutil\\tests\\t-ipaddr-print.vcproj
.set dependencies_t-ipaddr-print \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-ipaddr-print
.set build_t-ipaddr-print yes
.set guid_t-zlib E26A48F5-F6F6-353D-9A00-3EE21D108B02
.set file_t-zlib sshutil\\tests\\t-zlib.vcproj
.set dependencies_t-zlib \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-zlib
.set build_t-zlib yes
.set guid_t-tcpc D724E999-7346-3205-9E00-E88375286635
.set file_t-tcpc sshutil\\tests\\t-tcpc.vcproj
.set dependencies_t-tcpc \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-tcpc
.set build_t-tcpc yes
.set guid_t-udpc 8BB7E994-48BE-31CE-8600-399CCBA948C9
.set file_t-udpc sshutil\\tests\\t-udpc.vcproj
.set dependencies_t-udpc \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-udpc
.set build_t-udpc yes
.set guid_t-localstreamclient 71EEB24A-3E03-3DCE-8B00-4F612A5FD6FC
.set file_t-localstreamclient sshutil\\tests\\t-localstreamclient.vcproj
.set dependencies_t-localstreamclient \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-localstreamclient \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-localstreamclient yes
.set guid_t-localstreamserver 22985AB7-428E-387E-9600-F159B5BAA27D
.set file_t-localstreamserver sshutil\\tests\\t-localstreamserver.vcproj
.set dependencies_t-localstreamserver \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-localstreamserver \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-localstreamserver yes
.set guid_t-randspeed E0B56C8B-A62F-31CF-8600-CF932EB97026
.set file_t-randspeed sshutil\\tests\\t-randspeed.vcproj
.set dependencies_t-randspeed \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-randspeed
.set build_t-randspeed yes
.set guid_t-messenger DAFEDBCC-3B5F-3F4C-8700-1DA84FC36675
.set file_t-messenger sshutil\\tests\\t-messenger.vcproj
.set dependencies_t-messenger \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-messenger
.set build_t-messenger yes
.set guid_t-audit-format 6CC04429-1853-35C5-9E00-FB71E36B4A9E
.set file_t-audit-format sshutil\\tests\\t-audit-format.vcproj
.set dependencies_t-audit-format \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-audit-format
.set build_t-audit-format yes
.set guid_t-sshstr F8F9B343-C73A-34A6-9400-9B53B53FC1C6
.set file_t-sshstr sshutil\\tests\\t-sshstr.vcproj
.set dependencies_t-sshstr \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-sshstr
.set build_t-sshstr yes
.set guid_t-time E45003CA-D2A9-3D9D-9B00-61B36EBA248C
.set file_t-time sshutil\\tests\\t-time.vcproj
.set dependencies_t-time \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-time
.set build_t-time yes
.set guid_t-addr 1EF3C9CE-4925-342F-8400-260BD4859CF5
.set file_t-addr sshutil\\tests\\t-addr.vcproj
.set dependencies_t-addr \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-addr
.set build_t-addr yes
.set guid_t-addrencode 5CDCC49F-BD2F-304A-8800-A5AD391C9705
.set file_t-addrencode sshutil\\tests\\t-addrencode.vcproj
.set dependencies_t-addrencode \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-addrencode
.set build_t-addrencode yes
.set guid_t-debugwrite 28648F97-1D4A-3675-9B00-555D3C494674
.set file_t-debugwrite sshutil\\tests\\t-debugwrite.vcproj
.set dependencies_t-debugwrite \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-debugwrite \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-debugwrite yes
.set guid_t-dsprintf 8406BDA5-53F1-3356-9100-529DDDA1376F
.set file_t-dsprintf sshutil\\tests\\t-dsprintf.vcproj
.set dependencies_t-dsprintf \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-dsprintf
.set build_t-dsprintf yes
.set guid_t-encode D83AFAC7-8AC5-32A6-8C00-F00320CF57B3
.set file_t-encode sshutil\\tests\\t-encode.vcproj
.set dependencies_t-encode \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-encode
.set build_t-encode yes
.set guid_t-eprintf 1BCC905C-AE21-3D76-8000-93371092B620
.set file_t-eprintf sshutil\\tests\\t-eprintf.vcproj
.set dependencies_t-eprintf \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-eprintf
.set build_t-eprintf yes
.set guid_t-esnprintf CA064843-D0ED-3BFC-9700-80E00C7E036C
.set file_t-esnprintf sshutil\\tests\\t-esnprintf.vcproj
.set dependencies_t-esnprintf \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-esnprintf
.set build_t-esnprintf yes
.set guid_t-eventloop 4CBC4FCB-0D0A-353F-9400-0C1C521BCE93
.set file_t-eventloop sshutil\\tests\\t-eventloop.vcproj
.set dependencies_t-eventloop \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-eventloop
.set build_t-eventloop yes
.set guid_t-fsm CA76E77C-6157-32DC-9700-A87299197891
.set file_t-fsm sshutil\\tests\\t-fsm.vcproj
.set dependencies_t-fsm \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-fsm
.set build_t-fsm yes
.set guid_t-getput 8B8517FC-DDE9-3175-8000-99EDCCEC5338
.set file_t-getput sshutil\\tests\\t-getput.vcproj
.set dependencies_t-getput \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-getput
.set build_t-getput yes
.set guid_t-snprintf F3FD32D8-34D3-3D26-9700-9F1747F6F755
.set file_t-snprintf sshutil\\tests\\t-snprintf.vcproj
.set dependencies_t-snprintf \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-snprintf
.set build_t-snprintf yes
.set guid_t-snprintf2 C25B2317-DBAF-399D-9D00-927B184030F7
.set file_t-snprintf2 sshutil\\tests\\t-snprintf2.vcproj
.set dependencies_t-snprintf2 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-snprintf2
.set build_t-snprintf2 yes
.set guid_t-renderer 28777E3E-F052-30A1-9D00-031BDFDFC7CD
.set file_t-renderer sshutil\\tests\\t-renderer.vcproj
.set dependencies_t-renderer \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-renderer
.set build_t-renderer yes
.set guid_t-sshutf8 D64520CF-A703-34C1-8A00-FF7F1F6F5B45
.set file_t-sshutf8 sshutil\\tests\\t-sshutf8.vcproj
.set dependencies_t-sshutf8 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-sshutf8
.set build_t-sshutf8 yes
.set guid_t-threads F8A532C0-385C-33DE-9400-7FA94157DC71
.set file_t-threads sshutil\\tests\\t-threads.vcproj
.set dependencies_t-threads \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-threads
.set build_t-threads yes
.set guid_t-threadedmbox 4B0635D3-A35C-3B0A-9500-A3B151792477
.set file_t-threadedmbox sshutil\\tests\\t-threadedmbox.vcproj
.set dependencies_t-threadedmbox \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-threadedmbox
.set build_t-threadedmbox yes
.set guid_t-url 79AADF44-3F90-30A4-8400-D4C257A60C1B
.set file_t-url sshutil\\tests\\t-url.vcproj
.set dependencies_t-url \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-url
.set build_t-url yes
.set guid_t-audit 856A201A-C145-34CA-9500-034B22C28991
.set file_t-audit sshutil\\tests\\t-audit.vcproj
.set dependencies_t-audit \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-audit
.set build_t-audit yes
.set guid_t-regex CC41709F-2ED4-3A83-8900-06BF61D9B469
.set file_t-regex sshutil\\tests\\t-regex.vcproj
.set dependencies_t-regex \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-regex
.set build_t-regex yes
.set guid_t-fingerprint B01B86A9-FD98-3FF9-9000-0F68AD64EC79
.set file_t-fingerprint sshutil\\tests\\t-fingerprint.vcproj
.set dependencies_t-fingerprint \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-fingerprint
.set build_t-fingerprint yes
.set guid_t-crc32 C94CD148-2C39-3288-9400-FCD0B0303BDB
.set file_t-crc32 sshutil\\tests\\t-crc32.vcproj
.set dependencies_t-crc32 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-crc32
.set build_t-crc32 yes
.set guid_t-buffer 2FBB601A-EF57-3B70-8500-F2C251B42C64
.set file_t-buffer sshutil\\tests\\t-buffer.vcproj
.set dependencies_t-buffer \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-buffer
.set build_t-buffer yes
.set guid_t-miscstring CE02BE56-06B8-30C7-8E00-A4BC4E379829
.set file_t-miscstring sshutil\\tests\\t-miscstring.vcproj
.set dependencies_t-miscstring \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-miscstring
.set build_t-miscstring yes
.set guid_t-streampair 3CFD6124-CAD2-3492-8D00-4D6F9E90DFAD
.set file_t-streampair sshutil\\tests\\t-streampair.vcproj
.set dependencies_t-streampair \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-streampair
.set build_t-streampair yes
.set guid_t-socks 9D0656E8-55EA-3C7C-8000-32243E5631D1
.set file_t-socks sshutil\\tests\\t-socks.vcproj
.set dependencies_t-socks \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-socks
.set build_t-socks yes
.set guid_t-localstream F9AB8F74-A3C1-3469-9E00-44081B30E84C
.set file_t-localstream sshutil\\tests\\t-localstream.vcproj
.set dependencies_t-localstream \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-localstream \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-localstream yes
.set guid_t-icmp-util D35E2A81-EC98-3BBB-9000-04716FACBDD5
.set file_t-icmp-util sshutil\\tests\\t-icmp-util.vcproj
.set dependencies_t-icmp-util \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-icmp-util
.set build_t-icmp-util yes
.set guid_t-adt 70B05508-6374-3A41-8800-A5BDC6F9B4E0
.set file_t-adt sshutil\\tests\\t-adt.vcproj
.set dependencies_t-adt \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-adt
.set build_t-adt yes
.set guid_t-timeout 609D6B87-5E1B-3499-9700-8EE138974E6A
.set file_t-timeout sshutil\\tests\\t-timeout.vcproj
.set dependencies_t-timeout \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-timeout
.set build_t-timeout yes
.set guid_t-operation 12E2D2A3-F657-313D-8700-285578CB618D
.set file_t-operation sshutil\\tests\\t-operation.vcproj
.set dependencies_t-operation \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-operation
.set build_t-operation yes
.set guid_t-packet 4451C42B-B53E-3F1B-9300-E00BC582C6A1
.set file_t-packet sshutil\\tests\\t-packet.vcproj
.set dependencies_t-packet \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-packet
.set build_t-packet yes
.set guid_t-dns BADFD3E7-272F-3B19-8900-D272CDD1D976
.set file_t-dns sshutil\\tests\\t-dns.vcproj
.set dependencies_t-dns \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-dns
.set build_t-dns yes
.set guid_t-resolver 4C9DCB89-4440-3E19-9400-099F28F234BE
.set file_t-resolver sshutil\\tests\\t-resolver.vcproj
.set dependencies_t-resolver \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-resolver
.set build_t-resolver yes
.set guid_t-stream FFFCDF88-BA21-3D98-9700-685F94E41FDD
.set file_t-stream sshutil\\tests\\t-stream.vcproj
.set dependencies_t-stream \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-stream
.set build_t-stream yes
.set guid_t-timemeasure 5D8B9F65-F0C6-3FAE-9600-1B42113C05DF
.set file_t-timemeasure sshutil\\tests\\t-timemeasure.vcproj
.set dependencies_t-timemeasure \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-timemeasure
.set build_t-timemeasure yes
.set guid_t-obstack 14BB9C92-FE92-3A39-9C00-9E776887D65F
.set file_t-obstack sshutil\\tests\\t-obstack.vcproj
.set dependencies_t-obstack \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-obstack
.set build_t-obstack yes
.set guid_sshutil 819FA266-7DD1-32CC-8500-5038787E9CE3
.set file_sshutil sshutil\\sshutil.vcproj
.set dependencies_sshutil \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil
.set platforms_sshutil
.set build_sshutil yes
.set guid_z FBADE9E3-6A3F-36D3-9600-C1B808451DD7
.set file_z zlib\\z.vcproj
.set dependencies_z \
	include
.set platforms_z
.set build_z yes
.set guid_minigzip C8752B55-00FA-3F35-8D00-207A7ACA6527
.set file_minigzip zlib\\minigzip.vcproj
.set dependencies_minigzip \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheap \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshsim \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_minigzip \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_minigzip yes
.set guid_factor 742F32C6-5FFD-38B7-8600-307F8DE2D47D
.set file_factor sshmath\\tests\\factor.vcproj
.set dependencies_factor \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_factor
.set build_factor yes
.set guid_t-xuint 53039616-7027-3031-9E00-D7F7CC10C114
.set file_t-xuint sshmath\\tests\\t-xuint.vcproj
.set dependencies_t-xuint \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-xuint
.set build_t-xuint yes
.set guid_t-xuint2 EFCB9BCE-FE58-3D62-8500-6704146A0ADA
.set file_t-xuint2 sshmath\\tests\\t-xuint2.vcproj
.set dependencies_t-xuint2 \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-xuint2
.set build_t-xuint2 yes
.set guid_t-mathtest 5FA2DFB6-93B6-3478-9800-36ED97648F75
.set file_t-mathtest sshmath\\tests\\t-mathtest.vcproj
.set dependencies_t-mathtest \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-mathtest
.set build_t-mathtest yes
.set guid_t-sophie-germain 82990C44-B031-3B3C-9800-B4A1DBB54ABE
.set file_t-sophie-germain sshmath\\tests\\t-sophie-germain.vcproj
.set dependencies_t-sophie-germain \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-sophie-germain
.set build_t-sophie-germain yes
.set guid_t-montgomery D154DE53-0890-38DB-9B00-B8D6C17C1E70
.set file_t-montgomery sshmath\\tests\\t-montgomery.vcproj
.set dependencies_t-montgomery \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-montgomery
.set build_t-montgomery yes
.set guid_t-mathspeed 251C09C3-FCAC-3069-9300-428951D61A03
.set file_t-mathspeed sshmath\\tests\\t-mathspeed.vcproj
.set dependencies_t-mathspeed \
	include \
	sshadt \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-mathspeed
.set build_t-mathspeed yes
.set guid_sshmath 6341F67E-D3D1-36F4-8500-6A76E6762389
.set file_sshmath sshmath\\sshmath.vcproj
.set dependencies_sshmath \
	include
.set platforms_sshmath
.set build_sshmath yes
.set guid_t-asn1 BA56810E-B666-3505-8A00-716CB5FE4A79
.set file_t-asn1 sshasn1\\tests\\t-asn1.vcproj
.set dependencies_t-asn1 \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-asn1
.set build_t-asn1 yes
.set guid_t-decode F323BC7A-5D1C-37DF-9A00-0950DFAA758A
.set file_t-decode sshasn1\\tests\\t-decode.vcproj
.set dependencies_t-decode \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcore \
	ssheloop \
	sshfsm \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-decode
.set build_t-decode yes
.set guid_sshasn1 67000B82-36C1-3620-9800-D88557A73BB4
.set file_sshasn1 sshasn1\\sshasn1.vcproj
.set dependencies_sshasn1 \
	include
.set platforms_sshasn1
.set build_sshasn1 yes
.set guid_t-proxykey 9D669ABE-115B-3575-9900-58F20FF2F96A
.set file_t-proxykey sshcrypto\\tests\\t-proxykey.vcproj
.set dependencies_t-proxykey \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-proxykey
.set build_t-proxykey yes
.set guid_t-combined-modes 408DE862-5987-359B-8D00-3450235DEA1A
.set file_t-combined-modes sshcrypto\\tests\\t-combined-modes.vcproj
.set dependencies_t-combined-modes \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-combined-modes
.set build_t-combined-modes yes
.set guid_t-pkcs1implicit 304614D6-9C45-31FF-9700-AA4BD8B15F87
.set file_t-pkcs1implicit sshcrypto\\tests\\t-pkcs1implicit.vcproj
.set dependencies_t-pkcs1implicit \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-pkcs1implicit
.set build_t-pkcs1implicit yes
.set guid_t-namelist 42C374F8-989D-3883-9600-BF9BE38B5E50
.set file_t-namelist sshcrypto\\tests\\t-namelist.vcproj
.set dependencies_t-namelist \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-namelist
.set build_t-namelist yes
.set guid_t-modetest 0697BED0-9676-3C3A-8900-81F7DE154A38
.set file_t-modetest sshcrypto\\tests\\t-modetest.vcproj
.set dependencies_t-modetest \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-modetest
.set build_t-modetest yes
.set guid_t-gentest 7C69AD23-BDA3-31EE-9C00-A1CEA9F434E2
.set file_t-gentest sshcrypto\\tests\\t-gentest.vcproj
.set dependencies_t-gentest \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-gentest
.set build_t-gentest yes
.set guid_t-dh 8E5EC959-22D0-3C89-9E00-E5F2BB66A3B2
.set file_t-dh sshcrypto\\tests\\t-dh.vcproj
.set dependencies_t-dh \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-dh
.set build_t-dh yes
.set guid_t-hdt A89BCC5D-644B-3804-8200-4A788C52CFB4
.set file_t-hdt sshcrypto\\tests\\t-hdt.vcproj
.set dependencies_t-hdt \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-hdt \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-hdt yes
.set guid_t-combined-speed 75A44BE6-AFF2-3C7B-9200-AB2461B3E220
.set file_t-combined-speed sshcrypto\\tests\\t-combined-speed.vcproj
.set dependencies_t-combined-speed \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-combined-speed
.set build_t-combined-speed yes
.set guid_t-cipher-vs-mac-speed 83EEF642-181F-3084-9F00-88E58F15B675
.set file_t-cipher-vs-mac-speed sshcrypto\\tests\\t-cipher-vs-mac-speed.vcproj
.set dependencies_t-cipher-vs-mac-speed \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-cipher-vs-mac-speed
.set build_t-cipher-vs-mac-speed yes
.set guid_t-cryptest 7943EE43-07B7-3649-8A00-19B1DC14C29C
.set file_t-cryptest sshcrypto\\tests\\t-cryptest.vcproj
.set dependencies_t-cryptest \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-cryptest
.set build_t-cryptest yes
.set guid_t-random A51B975C-CA1B-369E-9F00-2B23B9E4AE5B
.set file_t-random sshcrypto\\tests\\t-random.vcproj
.set dependencies_t-random \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-random
.set build_t-random yes
.set guid_sshcipher 57F6AD89-D599-38E6-9700-08B93A10F0BC
.set file_sshcipher sshcrypto\\sshcipher\\sshcipher.vcproj
.set dependencies_sshcipher \
	include
.set platforms_sshcipher
.set build_sshcipher yes
.set guid_sshhash 638F2924-DF11-3358-8800-753E18476A64
.set file_sshhash sshcrypto\\sshhash\\sshhash.vcproj
.set dependencies_sshhash \
	include
.set platforms_sshhash
.set build_sshhash yes
.set guid_sshrandom 52B37BC0-2745-3264-9200-E24BAB42B06F
.set file_sshrandom sshcrypto\\sshrandom\\sshrandom.vcproj
.set dependencies_sshrandom \
	include
.set platforms_sshrandom
.set build_sshrandom yes
.set guid_sshcryptocore EA82B6D4-7FCC-3EDD-8000-8FF0D0B54A21
.set file_sshcryptocore sshcrypto\\sshcryptocore\\sshcryptocore.vcproj
.set dependencies_sshcryptocore \
	include
.set platforms_sshcryptocore
.set build_sshcryptocore yes
.set guid_sshmac 73D9175D-C510-3681-8100-9508EF1F5752
.set file_sshmac sshcrypto\\sshmac\\sshmac.vcproj
.set dependencies_sshmac \
	include
.set platforms_sshmac
.set build_sshmac yes
.set guid_sshpk A3B0C9DB-08E9-3493-8E00-1AB82B0261D9
.set file_sshpk sshcrypto\\sshpk\\sshpk.vcproj
.set dependencies_sshpk \
	include
.set platforms_sshpk
.set build_sshpk yes
.set guid_sshcrypto 62883C6E-B04E-3904-8000-1E92E980733D
.set file_sshcrypto sshcrypto\\sshcrypto.vcproj
.set dependencies_sshcrypto \
	include \
	sshcipher \
	sshcryptocore \
	sshhash \
	sshmac \
	sshpk \
	sshrandom
.set platforms_sshcrypto
.set build_sshcrypto yes
.set guid_t-aes-keywrap 08BD0ED6-D635-38BD-9300-A160C17ED41F
.set file_t-aes-keywrap sshcryptoaux\\tests\\t-aes-keywrap.vcproj
.set dependencies_t-aes-keywrap \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-aes-keywrap
.set build_t-aes-keywrap yes
.set guid_t-compress 2B89B77E-D3D6-317B-8200-0082DD237E39
.set file_t-compress sshcryptoaux\\tests\\t-compress.vcproj
.set dependencies_t-compress \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-compress
.set build_t-compress yes
.set guid_t-key-export A3949984-65F8-3E16-8000-D6DD02051168
.set file_t-key-export sshcryptoaux\\tests\\t-key-export.vcproj
.set dependencies_t-key-export \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-key-export
.set build_t-key-export yes
.set guid_sshcryptoaux 745975F2-C747-344D-9000-4C5C9776BF09
.set file_sshcryptoaux sshcryptoaux\\sshcryptoaux.vcproj
.set dependencies_sshcryptoaux \
	include
.set platforms_sshcryptoaux
.set build_sshcryptoaux yes
.set guid_sshradius B95CDBFD-ADB8-3783-8600-C9D9C88FCC72
.set file_sshradius sshradius\\sshradius.vcproj
.set dependencies_sshradius \
	include
.set platforms_sshradius
.set build_sshradius yes
.set guid_t-ldap 0850ACF5-E8DB-39EB-8C00-F27BB7709088
.set file_t-ldap sshldap\\tests\\t-ldap.vcproj
.set dependencies_t-ldap \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-ldap
.set build_t-ldap yes
.set guid_t-ldapconv C4F6AFB1-1D4B-36B0-8400-29BEAE4F995E
.set file_t-ldapconv sshldap\\tests\\t-ldapconv.vcproj
.set dependencies_t-ldapconv \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-ldapconv
.set build_t-ldapconv yes
.set guid_t-ldapfilter 7BD658D4-5F6A-3965-9F00-37C6B02816A5
.set file_t-ldapfilter sshldap\\tests\\t-ldapfilter.vcproj
.set dependencies_t-ldapfilter \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-ldapfilter
.set build_t-ldapfilter yes
.set guid_sshldap 7B7D73E9-5B07-3D40-8D00-63516C15F9EA
.set file_sshldap sshldap\\sshldap.vcproj
.set dependencies_sshldap \
	include
.set platforms_sshldap
.set build_sshldap yes
.set guid_t-http-kvhash E9D1F470-41DC-3E53-9200-282310248940
.set file_t-http-kvhash sshhttp\\tests\\t-http-kvhash.vcproj
.set dependencies_t-http-kvhash \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-http-kvhash
.set build_t-http-kvhash yes
.set guid_t-http 418F409E-99C1-3AC4-8400-489216418B47
.set file_t-http sshhttp\\tests\\t-http.vcproj
.set dependencies_t-http \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_t-http
.set build_t-http yes
.set guid_httpclient 0918AB5A-FD8B-35E3-9300-4AE53821F16F
.set file_httpclient sshhttp\\tests\\httpclient.vcproj
.set dependencies_httpclient \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_httpclient \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_httpclient yes
.set guid_httpserver 7DD4174D-FBCF-35FB-8000-8A5D1A311AE9
.set file_httpserver sshhttp\\tests\\httpserver.vcproj
.set dependencies_httpserver \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_httpserver \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_httpserver yes
.set guid_http-benchmark BBFF4EF5-0A76-3BB4-9300-2357188798C8
.set file_http-benchmark sshhttp\\tests\\http-benchmark.vcproj
.set dependencies_http-benchmark \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_http-benchmark
.set build_http-benchmark yes
.set guid_filterproxy 4EC6EB95-CF06-337A-9500-D88568687376
.set file_filterproxy sshhttp\\tests\\filterproxy.vcproj
.set dependencies_filterproxy \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	z
.set platforms_filterproxy
.set build_filterproxy yes
.set guid_sshhttp 8B592B00-A042-3CE0-9C00-C53EB335755F
.set file_sshhttp sshhttp\\sshhttp.vcproj
.set dependencies_sshhttp \
	include
.set platforms_sshhttp
.set build_sshhttp yes
.set guid_sshxml 094D0086-296A-3E9D-9A00-1D71E4D06B56
.set file_sshxml sshxml\\sshxml.vcproj
.set dependencies_sshxml \
	include
.set platforms_sshxml
.set build_sshxml yes
.set guid_xml-tool 64862624-3E78-335A-8700-C503523A7497
.set file_xml-tool sshxml\\xml-tool.vcproj
.set dependencies_xml-tool \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_xml-tool
.set build_xml-tool yes
.set guid_xmlconf 96CE1088-0AF3-357A-9100-5191501BE6E1
.set file_xmlconf sshxml\\xmlconf.vcproj
.set dependencies_xmlconf \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_xmlconf
.set build_xmlconf yes
.set guid_dtd-compress 5E5FF045-7F63-3586-8C00-9D097D379902
.set file_dtd-compress sshxml\\dtd-compress.vcproj
.set dependencies_dtd-compress \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_dtd-compress
.set build_dtd-compress yes
.set guid_t-makeandverify 937AC967-0E89-3479-8000-41383A4C07AC
.set file_t-makeandverify sshcert\\tests\\t-makeandverify.vcproj
.set dependencies_t-makeandverify \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-makeandverify
.set build_t-makeandverify yes
.set guid_t-certhierarchy 9BC3D641-22FB-3406-8200-192C99396FE5
.set file_t-certhierarchy sshcert\\tests\\t-certhierarchy.vcproj
.set dependencies_t-certhierarchy \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-certhierarchy
.set build_t-certhierarchy yes
.set guid_pem2bin 71B4937E-2C75-320E-9800-2B14AD8D6CE8
.set file_pem2bin sshcert\\tests\\pem2bin.vcproj
.set dependencies_pem2bin \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_pem2bin
.set build_pem2bin yes
.set guid_t-certtest A28ADFD9-9573-3DC4-8300-39020D85AA03
.set file_t-certtest sshcert\\tests\\t-certtest.vcproj
.set dependencies_t-certtest \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-certtest
.set build_t-certtest yes
.set guid_t-dn F0065F5C-0591-3126-9000-3FADD205F5BF
.set file_t-dn sshcert\\tests\\t-dn.vcproj
.set dependencies_t-dn \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-dn
.set build_t-dn yes
.set guid_t-ocsp 45611988-B606-3E87-9200-079828CF3692
.set file_t-ocsp sshcert\\tests\\t-ocsp.vcproj
.set dependencies_t-ocsp \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-ocsp
.set build_t-ocsp yes
.set guid_t-ocsp-packet 3A5B87D3-B234-3737-9100-2879C35D0F07
.set file_t-ocsp-packet sshcert\\tests\\t-ocsp-packet.vcproj
.set dependencies_t-ocsp-packet \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-ocsp-packet
.set build_t-ocsp-packet yes
.set guid_sshcert 6CC716A0-8161-3CE9-9000-85E0FBB0DC8A
.set file_sshcert sshcert\\sshcert.vcproj
.set dependencies_sshcert \
	include
.set platforms_sshcert
.set build_sshcert yes
.set guid_t-p12 DBDAF417-493D-3602-9700-AE628013B8C7
.set file_t-p12 sshpkcs\\tests\\t-p12.vcproj
.set dependencies_t-p12 \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-p12
.set build_t-p12 yes
.set guid_t-pkcs1 CEF3DAE2-BBE0-33DA-9000-3C9482E6838C
.set file_t-pkcs1 sshpkcs\\tests\\t-pkcs1.vcproj
.set dependencies_t-pkcs1 \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-pkcs1
.set build_t-pkcs1 yes
.set guid_t-pkcs8 9E266849-F5D3-3E9A-9300-8C9FFF8DA387
.set file_t-pkcs8 sshpkcs\\tests\\t-pkcs8.vcproj
.set dependencies_t-pkcs8 \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-pkcs8
.set build_t-pkcs8 yes
.set guid_t-p7dump 456931D6-0921-318E-9600-5294C5F61937
.set file_t-p7dump sshpkcs\\tests\\t-p7dump.vcproj
.set dependencies_t-p7dump \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-p7dump
.set build_t-p7dump yes
.set guid_t-p12make FD5EC2C3-57F1-3F0E-9000-0594B37CA04B
.set file_t-p12make sshpkcs\\tests\\t-p12make.vcproj
.set dependencies_t-p12make \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshxml \
	z
.set platforms_t-p12make
.set build_t-p12make yes
.set guid_sshpkcs E09EB275-BD4B-39EB-9F00-2D2892CEADFC
.set file_sshpkcs sshpkcs\\sshpkcs.vcproj
.set dependencies_sshpkcs \
	include
.set platforms_sshpkcs
.set build_sshpkcs yes
.set guid_sshenroll 8572775B-E017-385D-8800-4D73EE7A0692
.set file_sshenroll sshenroll\\sshenroll.vcproj
.set dependencies_sshenroll \
	include
.set platforms_sshenroll
.set build_sshenroll yes
.set guid_t-basic 927A3472-A4AD-3B59-8800-C5CC1E819FF9
.set file_t-basic sshvalidator\\tests\\t-basic.vcproj
.set dependencies_t-basic \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshvalidator \
	sshxml \
	z
.set platforms_t-basic \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-basic yes
.set guid_t-anchor F9FBE91C-2ABA-3642-8E00-B7D9782DC001
.set file_t-anchor sshvalidator\\tests\\t-anchor.vcproj
.set dependencies_t-anchor \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshvalidator \
	sshxml \
	z
.set platforms_t-anchor
.set build_t-anchor yes
.set guid_t-cmi C501E644-3C28-393B-8300-AA3A3210AB5B
.set file_t-cmi sshvalidator\\tests\\t-cmi.vcproj
.set dependencies_t-cmi \
	include \
	ssh-certmake \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshvalidator \
	sshxml \
	z
.set platforms_t-cmi \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-cmi yes
.set guid_t-cmistress 30A195F5-8F18-3213-8F00-AD8C526F5845
.set file_t-cmistress sshvalidator\\tests\\t-cmistress.vcproj
.set dependencies_t-cmistress \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshvalidator \
	sshxml \
	z
.set platforms_t-cmistress
.set build_t-cmistress yes
.set guid_t-certbundle 46764CCC-0E50-34B7-8700-A020B726294B
.set file_t-certbundle sshvalidator\\tests\\t-certbundle.vcproj
.set dependencies_t-certbundle \
	include \
	ssh-certmake \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshvalidator \
	sshxml \
	z
.set platforms_t-certbundle
.set build_t-certbundle yes
.set guid_sshvalidator F60D0C37-9A39-3CE5-8D00-DEFCE68C7FFB
.set file_sshvalidator sshvalidator\\sshvalidator.vcproj
.set dependencies_sshvalidator \
	include
.set platforms_sshvalidator
.set build_sshvalidator yes
.set guid_t-tls F11EC4EA-0C41-3DBA-9000-2B36FCEA9850
.set file_t-tls sshtls\\tests\\t-tls.vcproj
.set dependencies_t-tls \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-tls \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_t-tls yes
.set guid_tls-client 4ED03EE0-3561-3822-8100-324907ECC37D
.set file_tls-client sshtls\\tests\\tls-client.vcproj
.set dependencies_tls-client \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_tls-client \
	win32 \
	x64 \
	win32vista \
	x64vista \
	win32win7 \
	x64win7
.set build_tls-client yes
.set guid_t-speedtest 5B2CC2F0-524B-3507-8400-995D7216558E
.set file_t-speedtest sshtls\\tests\\t-speedtest.vcproj
.set dependencies_t-speedtest \
	include \
	sshadt \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-speedtest
.set build_t-speedtest yes
.set guid_sshtls EC0240CA-185F-391C-8300-E8AD7FAFD1E8
.set file_sshtls sshtls\\sshtls.vcproj
.set dependencies_sshtls \
	include
.set platforms_sshtls
.set build_sshtls yes
.set guid_sshapputil 8D899501-A7C5-375A-8800-9409DEA675A0
.set file_sshapputil sshapputil\\sshapputil.vcproj
.set dependencies_sshapputil \
	include
.set platforms_sshapputil
.set build_sshapputil yes
.set guid_t-softprovider 20508522-4DC2-3C38-8400-64514B23A5D8
.set file_t-softprovider sshexternalkey\\tests\\t-softprovider.vcproj
.set dependencies_t-softprovider \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-softprovider
.set build_t-softprovider yes
.set guid_t-genacc 8943AE1E-AF71-3340-9900-E4A3949E5A88
.set file_t-genacc sshexternalkey\\tests\\t-genacc.vcproj
.set dependencies_t-genacc \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-genacc
.set build_t-genacc yes
.set guid_t-genacc-speed 2E8822EB-93A6-3BBE-9300-58E3712B8CF5
.set file_t-genacc-speed sshexternalkey\\tests\\t-genacc-speed.vcproj
.set dependencies_t-genacc-speed \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-genacc-speed
.set build_t-genacc-speed yes
.set guid_t-genacc_rsacrt 031D8CAA-0D44-34B7-8A00-24E764B6DC70
.set file_t-genacc_rsacrt sshexternalkey\\tests\\t-genacc_rsacrt.vcproj
.set dependencies_t-genacc_rsacrt \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-genacc_rsacrt
.set build_t-genacc_rsacrt yes
.set guid_t-externalkey 8B384D2A-CC8E-3BEA-9000-6BBBCAF6FFDA
.set file_t-externalkey sshexternalkey\\tests\\t-externalkey.vcproj
.set dependencies_t-externalkey \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-externalkey
.set build_t-externalkey yes
.set guid_t-simple_externalkey 7F553FE1-4E6B-333C-9D00-6BAD435418E8
.set file_t-simple_externalkey sshexternalkey\\tests\\t-simple_externalkey.vcproj
.set dependencies_t-simple_externalkey \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-simple_externalkey
.set build_t-simple_externalkey yes
.set guid_t-accelerator CE3F39E6-75B5-3A9F-9500-9051B2A29C40
.set file_t-accelerator sshexternalkey\\tests\\t-accelerator.vcproj
.set dependencies_t-accelerator \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-accelerator
.set build_t-accelerator yes
.set guid_t-makereq 3702584C-417A-3C1E-8E00-62CEA6CF9C95
.set file_t-makereq sshexternalkey\\tests\\t-makereq.vcproj
.set dependencies_t-makereq \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-makereq
.set build_t-makereq yes
.set guid_t-externalcert 4613AF65-C7BB-3813-9200-536435FD6194
.set file_t-externalcert sshexternalkey\\tests\\t-externalcert.vcproj
.set dependencies_t-externalcert \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_t-externalcert
.set build_t-externalcert yes
.set guid_sshexternalkey 21B86D89-3195-351B-8E00-EA53596D85D2
.set file_sshexternalkey sshexternalkey\\sshexternalkey.vcproj
.set dependencies_sshexternalkey \
	include
.set platforms_sshexternalkey
.set build_sshexternalkey yes
.set guid_ssheap 5CC49761-5411-3CBE-9800-B12EF8288219
.set file_ssheap ssheap\\ssheap.vcproj
.set dependencies_ssheap \
	include
.set platforms_ssheap
.set build_ssheap yes
.set guid_sshsim E57F846B-FD75-3FF3-9800-EA1818BBDE36
.set file_sshsim sshsim\\sshsim.vcproj
.set dependencies_sshsim \
	include
.set platforms_sshsim
.set build_sshsim yes
.set guid_ssh 1787D764-6304-35D9-8700-4E64A3973DC7
.set file_ssh ssh.vcproj
.set dependencies_ssh \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheap \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshsim \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_ssh
.set build_ssh yes
.set guid_include D436EB0F-D9DE-30B5-8A00-8CE6435F7E81
.set file_include ..\\include\\include.vcproj
.set dependencies_include
.set platforms_include
.set build_include yes
.set guid_ssh-certmake 929F2936-F267-3169-8300-D74D3E1D3DEB
.set file_ssh-certmake ..\\apps\\certutils\\ssh-certmake.vcproj
.set dependencies_ssh-certmake \
	include \
	sshadt \
	sshapputil \
	sshasn1 \
	sshaudit \
	sshcert \
	sshcipher \
	sshcore \
	sshcryptoaux \
	sshcryptocore \
	ssheap \
	ssheloop \
	sshenroll \
	sshexternalkey \
	sshfsm \
	sshhash \
	sshhttp \
	sshldap \
	sshmac \
	sshmath \
	sshmisc \
	sshnet \
	sshpacketstream \
	sshpk \
	sshpkcs \
	sshradius \
	sshrandom \
	sshsim \
	sshstream \
	sshstrutil \
	sshsysutil \
	sshtestutil \
	sshtls \
	sshvalidator \
	sshxml \
	z
.set platforms_ssh-certmake
.set build_ssh-certmake yes
.set projects \
	sshcore \
	sshadt \
	ssheloop \
	sshstrutil \
	hello \
	hello2 \
	yield \
	producer-consumer \
	timeout \
	sshfsm \
	sshstream \
	sshsysutil \
	sshnet \
	sshmisc \
	sshaudit \
	sshpacketstream \
	sshtestutil \
	t-decay \
	t-base64 \
	t-debug \
	t-c64 \
	t-ipaddr-print \
	t-zlib \
	t-tcpc \
	t-udpc \
	t-localstreamclient \
	t-localstreamserver \
	t-randspeed \
	t-messenger \
	t-audit-format \
	t-sshstr \
	t-time \
	t-addr \
	t-addrencode \
	t-debugwrite \
	t-dsprintf \
	t-encode \
	t-eprintf \
	t-esnprintf \
	t-eventloop \
	t-fsm \
	t-getput \
	t-snprintf \
	t-snprintf2 \
	t-renderer \
	t-sshutf8 \
	t-threads \
	t-threadedmbox \
	t-url \
	t-audit \
	t-regex \
	t-fingerprint \
	t-crc32 \
	t-buffer \
	t-miscstring \
	t-streampair \
	t-socks \
	t-localstream \
	t-icmp-util \
	t-adt \
	t-timeout \
	t-operation \
	t-packet \
	t-dns \
	t-resolver \
	t-stream \
	t-timemeasure \
	t-obstack \
	sshutil \
	z \
	minigzip \
	factor \
	t-xuint \
	t-xuint2 \
	t-mathtest \
	t-sophie-germain \
	t-montgomery \
	t-mathspeed \
	sshmath \
	t-asn1 \
	t-decode \
	sshasn1 \
	t-proxykey \
	t-combined-modes \
	t-pkcs1implicit \
	t-namelist \
	t-modetest \
	t-gentest \
	t-dh \
	t-hdt \
	t-combined-speed \
	t-cipher-vs-mac-speed \
	t-cryptest \
	t-random \
	sshcipher \
	sshhash \
	sshrandom \
	sshcryptocore \
	sshmac \
	sshpk \
	sshcrypto \
	t-aes-keywrap \
	t-compress \
	t-key-export \
	sshcryptoaux \
	sshradius \
	t-ldap \
	t-ldapconv \
	t-ldapfilter \
	sshldap \
	t-http-kvhash \
	t-http \
	httpclient \
	httpserver \
	http-benchmark \
	filterproxy \
	sshhttp \
	sshxml \
	xml-tool \
	xmlconf \
	dtd-compress \
	t-makeandverify \
	t-certhierarchy \
	pem2bin \
	t-certtest \
	t-dn \
	t-ocsp \
	t-ocsp-packet \
	sshcert \
	t-p12 \
	t-pkcs1 \
	t-pkcs8 \
	t-p7dump \
	t-p12make \
	sshpkcs \
	sshenroll \
	t-basic \
	t-anchor \
	t-cmi \
	t-cmistress \
	t-certbundle \
	sshvalidator \
	t-tls \
	tls-client \
	t-speedtest \
	sshtls \
	sshapputil \
	t-softprovider \
	t-genacc \
	t-genacc-speed \
	t-genacc_rsacrt \
	t-externalkey \
	t-simple_externalkey \
	t-accelerator \
	t-makereq \
	t-externalcert \
	sshexternalkey \
	ssheap \
	sshsim \
	ssh \
	include \
	ssh-certmake
