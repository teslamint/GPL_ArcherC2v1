.set workspace_name sshasn1
.set guid_t-asn1 BA56810E-B666-3505-8A00-716CB5FE4A79
.set file_t-asn1 tests\\t-asn1.vcproj
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
.set file_t-decode tests\\t-decode.vcproj
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
.set file_sshasn1 sshasn1.vcproj
.set dependencies_sshasn1 \
	include
.set platforms_sshasn1
.set build_sshasn1 yes
.set guid_sshmath 6341F67E-D3D1-36F4-8500-6A76E6762389
.set file_sshmath ..\\..\\lib\\sshmath\\sshmath.vcproj
.set dependencies_sshmath \
	include
.set platforms_sshmath
.set build_sshmath yes
.set guid_z FBADE9E3-6A3F-36D3-9600-C1B808451DD7
.set file_z ..\\..\\lib\\zlib\\z.vcproj
.set dependencies_z \
	include
.set platforms_z
.set build_z yes
.set guid_sshutil 819FA266-7DD1-32CC-8500-5038787E9CE3
.set file_sshutil ..\\..\\lib\\sshutil\\sshutil.vcproj
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
.set guid_include D436EB0F-D9DE-30B5-8A00-8CE6435F7E81
.set file_include ..\\..\\include\\include.vcproj
.set dependencies_include
.set platforms_include
.set build_include yes
.set guid_sshcore 259EAF88-CA28-3380-9700-C18375175008
.set file_sshcore ..\\..\\lib\\sshutil\\sshcore\\sshcore.vcproj
.set dependencies_sshcore \
	include
.set platforms_sshcore
.set build_sshcore yes
.set guid_sshadt 4F11E88E-9933-3BA0-9600-A983E1E53D1B
.set file_sshadt ..\\..\\lib\\sshutil\\sshadt\\sshadt.vcproj
.set dependencies_sshadt \
	include
.set platforms_sshadt
.set build_sshadt yes
.set guid_sshstrutil 82FBF629-E182-3FB9-9F00-77FE7DA7D84A
.set file_sshstrutil ..\\..\\lib\\sshutil\\sshstrutil\\sshstrutil.vcproj
.set dependencies_sshstrutil \
	include
.set platforms_sshstrutil
.set build_sshstrutil yes
.set guid_ssheloop 6E65EAF3-0803-31A1-9400-C85DB357FF80
.set file_ssheloop ..\\..\\lib\\sshutil\\ssheloop\\ssheloop.vcproj
.set dependencies_ssheloop \
	include
.set platforms_ssheloop
.set build_ssheloop yes
.set guid_sshfsm 8900C0FD-960F-359A-8C00-9B420E706302
.set file_sshfsm ..\\..\\lib\\sshutil\\sshfsm\\sshfsm.vcproj
.set dependencies_sshfsm \
	include
.set platforms_sshfsm
.set build_sshfsm yes
.set guid_sshstream BE7CDA3E-818D-3765-8C00-3A05D4B12F65
.set file_sshstream ..\\..\\lib\\sshutil\\sshstream\\sshstream.vcproj
.set dependencies_sshstream \
	include
.set platforms_sshstream
.set build_sshstream yes
.set guid_sshsysutil 91AE84FB-3C30-3B57-8900-C794F1BE5CAD
.set file_sshsysutil ..\\..\\lib\\sshutil\\sshsysutil\\sshsysutil.vcproj
.set dependencies_sshsysutil \
	include
.set platforms_sshsysutil
.set build_sshsysutil yes
.set guid_sshnet E6E2CD1C-CBDD-39F7-8900-1B19140A1334
.set file_sshnet ..\\..\\lib\\sshutil\\sshnet\\sshnet.vcproj
.set dependencies_sshnet \
	include
.set platforms_sshnet
.set build_sshnet yes
.set guid_sshaudit 76DEEAB9-A2D3-35A6-8400-EE313F932877
.set file_sshaudit ..\\..\\lib\\sshutil\\sshaudit\\sshaudit.vcproj
.set dependencies_sshaudit \
	include
.set platforms_sshaudit
.set build_sshaudit yes
.set guid_sshmisc E4CC88BD-FC51-30C8-9300-AA06B6E25C47
.set file_sshmisc ..\\..\\lib\\sshutil\\sshmisc\\sshmisc.vcproj
.set dependencies_sshmisc \
	include
.set platforms_sshmisc
.set build_sshmisc yes
.set guid_sshpacketstream D3F312E3-B689-32DA-8500-B2A045D86CF3
.set file_sshpacketstream ..\\..\\lib\\sshutil\\sshpacketstream\\sshpacketstream.vcproj
.set dependencies_sshpacketstream \
	include
.set platforms_sshpacketstream
.set build_sshpacketstream yes
.set guid_sshtestutil 199C3F03-A1E0-3EC2-8100-45998DD80F2A
.set file_sshtestutil ..\\..\\lib\\sshutil\\sshtestutil\\sshtestutil.vcproj
.set dependencies_sshtestutil \
	include
.set platforms_sshtestutil
.set build_sshtestutil yes
.set projects \
	t-asn1 \
	t-decode \
	sshasn1 \
	sshmath \
	z \
	sshutil \
	include \
	sshcore \
	sshadt \
	sshstrutil \
	ssheloop \
	sshfsm \
	sshstream \
	sshsysutil \
	sshnet \
	sshaudit \
	sshmisc \
	sshpacketstream \
	sshtestutil
