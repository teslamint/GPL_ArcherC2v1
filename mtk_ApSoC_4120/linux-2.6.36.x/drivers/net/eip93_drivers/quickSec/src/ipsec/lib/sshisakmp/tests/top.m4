dnl SSH test certificates
dnl
dnl This file is supposed to be run through m4 (it may require gnu-m4)
dnl This defines generic macros. 
dnl
dnl Input variables:
dnl
dnl `IP_NUMBER'           IP number to put in certificates. Defaults to real ip
dnl `REVOKE_CERTS'        If set to 1 then revoke both rsa and dsa certs
dnl `NO_CAS'              If set to 1 then do not create ca keys
dnl `NO_KEYS'             If set to 1 then do not create keys
dnl `NO_CRLS'             If set to 1 then do not create crls
dnl `KEY_BITS_CA'         Number of bits used in CA key
dnl `KEY_BITS_KEY'        Number of bits used in RSA key
dnl `SERIAL_START'        Start of serial number
dnl `CRL_TTL'             CRL time to live (hh:mm)
dnl `FILE_NAME_PREFIX'    Prefix for all file names
dnl `SIGNATURE_FORMAT'    md5WithRSAEncryption or sha1WithRSAEncryption
dnl `TOP_DN'              Specifies the top level DN for keys.
dnl `USE_OLD_PRIVATE_KEY_FILES'
dnl                       Specifies that we use all old private key files

ifelse(IP_NUMBER,`IP_NUMBER',`define(IP_NUMBER,)')
ifelse(NO_KEYS,`NO_KEYS',`define(NO_KEYS,0)')
ifelse(NO_CAS,`NO_CAS',`define(NO_CAS,0)')
ifelse(NO_CRLS,`NO_CRLS',`define(NO_CRLS,0)')
ifelse(REVOKE_CERTS,`REVOKE_CERTS',`define(REVOKE_CERTS,0)')
ifelse(CRL_TTL,`CRL_TTL',`define(CRL_TTL,01:00)')
ifelse(PATH_LENGTH,`PATH_LENGTH',`define(PATH_LENGTH, 50)')
ifelse(SERIAL_START,`SERIAL_START',`define(SERIAL_START,10000)')
ifelse(FILE_NAME_PREFIX,`FILE_NAME_PREFIX',`define(FILE_NAME_PREFIX,ssh-test-)')
ifelse(SIGNATURE_FORMAT,`SIGNATURE_FORMAT',`define(SIGNATURE_FORMAT,md5WithRSAEncryption)')
ifelse(TOP_DN,`TOP_DN',`define(TOP_DN,`C=FI,O=Example, CN=Test ')')

changequote([,])
syscmd([rm -f /tmp/test-x509-m4])
syscmd([echo 'ifelse(IP_NUMBER,,[define([IP_NUMBER],'`netstat -in | grep -v Link | grep -v "lo" | grep -v Mtu | fgrep . | head -1 | cut -c 25-40`')])' > /tmp/test-x509-m4])
ifelse(REVOKE_CERTS,1,[syscmd([echo "define(REVOKE_COMMENT,)" >> /tmp/test-x509-m4])],[syscmd([echo "define(REVOKE_COMMENT,%)" >> /tmp/test-x509-m4])])
syscmd([date -u "+Y(%Y)b(%b)d(%d)H(%H)M(%M)S(%S)" |
sed 's/Y(/define(YEAR,/g; s/b(/define(MONTH,/g; s/d(/define(MDAY,/g;
s/H(/define(HOUR,/g; s/M(/define(MIN,/g; s/S(/define(SEC,/g;' >> /tmp/test-x509-m4])
syscmd([TZ=GMT-]CRL_TTL [ date "+Y(%Y)b(%b)d(%d)H(%H)M(%M)S(%S)" |
sed 's/Y(/define(NYEAR,/g; s/b(/define(NMONTH,/g; s/d(/define(NMDAY,/g;
s/H(/define(NHOUR,/g; s/M(/define(NMIN,/g; s/S(/define(NSEC,/g;' >> /tmp/test-x509-m4])
syscmd([echo "define(HOSTNAME,`uname -n`)" >> /tmp/test-x509-m4])

include([/tmp/test-x509-m4])
syscmd([rm -f /tmp/test-x509-m4])

changequote(`,')

define(CA_START,`ifelse(NO_CAS,1,`divert(-1)',`divert(0)')')
define(CERT_START,`ifelse(NO_KEYS,1,`divert(-1)',`divert(0)')')
define(CRL_START,`ifelse(NO_CRLS,1,`divert(-1)',`divert(0)')')

define(DAY_ENDING,`ifelse($1,01,st,ifelse($1,21,st,ifelse($1,31,st,ifelse($1,02,nd,ifelse($1,22,nd,ifelse($1,03,rd,ifelse($1,13,th,ifelse($1,23,rd,th))))))))')

define(MDAY_END,`DAY_ENDING(MDAY)')
define(NMDAY_END,`DAY_ENDING(NMDAY)')

ifelse(START_TIME,`START_TIME',`define(`START_TIME',`YEAR MONTH MDAY()MDAY_END, HOUR:MIN:SEC')')
ifelse(END_TIME,`END_TIME',`define(`END_TIME',`YEAR Dec 31st, 23:59:59')')
ifelse(THIS_TIME,`THIS_TIME',`define(THIS_TIME,`YEAR MONTH MDAY()MDAY_END, HOUR:MIN:SEC')')
ifelse(NEXT_TIME,`NEXT_TIME',`define(NEXT_TIME,`NYEAR NMONTH NMDAY()NMDAY_END, NHOUR:NMIN:NSEC')')
ifdef(KEY_BITS_CA,,`define(KEY_BITS_CA,1024)')
ifdef(KEY_BITS_KEY,,`define(KEY_BITS_KEY,1024)')

define(INT_SERIAL_NUMBER,SERIAL_START)
define(SERIAL_NUMBER,`define(`INT_SERIAL_NUMBER',incr(INT_SERIAL_NUMBER)) INT_SERIAL_NUMBER')
define(A_INT_SERIAL_NUMBER,SERIAL_START)
define(A_SERIAL_NUMBER,`define(`A_INT_SERIAL_NUMBER',incr(A_INT_SERIAL_NUMBER)) A_INT_SERIAL_NUMBER')

define(B_INT_SERIAL_NUMBER,SERIAL_START)
define(B_SERIAL_NUMBER,`define(`B_INT_SERIAL_NUMBER',incr(B_INT_SERIAL_NUMBER)) B_INT_SERIAL_NUMBER')

dnl
dnl Create CA key
dnl
dnl CA_CERT_DEF(name, serial number[, sig format [, key type [, name]]])

define(CA_CERT_DEF,`CA_START()dnl
Certificate ::= {
  OutputFile ::= "FILE_NAME_PREFIX`'$1.bin"

  SerialNumber ::= ifelse($2,,`SERIAL_NUMBER',$2)
  SubjectName  ::= <TOP_DN`'ifelse($5,,$1,$5)>
  IssuerName   ::= <TOP_DN`'ifelse($5,,$1,$5)>
  Validity     ::= {
    NotBefore  ::= "START_TIME"
    NotAfter   ::= "END_TIME"
  }
  PublicKeyInfo ::= {
   ifelse(USE_OLD_PRIVATE_KEY_FILES,`USE_OLD_PRIVATE_KEY_FILES',
    Size ::= KEY_BITS_CA
    Type ::= ifelse($4,`',`rsaEncryption',$4)
    PrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv"
   , InputPrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv")
  }
  Signature ::= {
    SelfSigned
    SignatureAlgorithm ::= ifelse($3,,SIGNATURE_FORMAT,$3)
  }
  Extensions ::= {
    BasicConstraints ::= {
      CA
      PathLength ::= PATH_LENGTH
    }
    KeyUsage ::= {
      DigitalSignature
      KeyCertSign
      CRLSign
    }
  }
}
')

dnl
dnl Create Intermediate key
dnl
dnl INT_CERT_DEF(name, issuer, serial number [, sig format [, key type
dnl    [, cert name [, issuer name ]]]])

define(INT_CERT_DEF,`CA_START()dnl
Certificate ::= {
  OutputFile ::= "FILE_NAME_PREFIX`'$1.bin"

  SerialNumber ::= ifelse($3,,`SERIAL_NUMBER',$3)
  IssuerName   ::= <TOP_DN`'ifelse($7,,$2,$7)>
  SubjectName  ::= <TOP_DN`'ifelse($6,,$1,$6)>
  Validity     ::= {
    NotBefore  ::= "START_TIME"
    NotAfter   ::= "END_TIME"
  }
  PublicKeyInfo ::= {
   ifelse(USE_OLD_PRIVATE_KEY_FILES,`USE_OLD_PRIVATE_KEY_FILES',
    Size ::= KEY_BITS_CA
    Type ::= ifelse($5,`',`rsaEncryption',$5)
    PrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv"
   ,InputPrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv")
  }
  Signature ::= {
    SignatureAlgorithm ::= ifelse($4,,SIGNATURE_FORMAT,$4)
    IssuerKeyFile ::= "FILE_NAME_PREFIX`'$2.prv"
  }
  Extensions ::= {
    BasicConstraints ::= {
      CA
      PathLength ::= PATH_LENGTH
    }
    KeyUsage ::= {
      DigitalSignature
      KeyCertSign
      CRLSign
    }
  }
}
')

dnl
dnl Create Intermediate key with old private key
dnl
dnl INT_CERT_DEF_WITHKEY(name, new name, issuer, serial number [, sig format [, key type
dnl    [, cert name [, issuer name ]]]])

define(INT_CERT_DEF_WITHKEY,`CA_START()dnl
Certificate ::= {
  OutputFile ::= "FILE_NAME_PREFIX`'$2.bin"

  SerialNumber ::= ifelse($4,,`SERIAL_NUMBER',$4)
  IssuerName   ::= <TOP_DN`'ifelse($8,,$3,$8)>
  SubjectName  ::= <TOP_DN`'ifelse($7,,$2,$7)>
  Validity     ::= {
    NotBefore  ::= "START_TIME"
    NotAfter   ::= "END_TIME"
  }
  PublicKeyInfo ::= {
    InputPrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv"
  }
  Signature ::= {
    SignatureAlgorithm ::= ifelse($5,,SIGNATURE_FORMAT,$5)
    IssuerKeyFile ::= "FILE_NAME_PREFIX`'$3.prv"
  }
  Extensions ::= {
    BasicConstraints ::= {
      CA
      PathLength ::= PATH_LENGTH
    }
    KeyUsage ::= {
      DigitalSignature
      KeyCertSign
      CRLSign
    }
  }
}
')

dnl
dnl Create end user key
dnl
dnl CERT_DEF(name, issuer, subject alt names, serial number[, sig format [, key type
dnl  [, cert name [, issuer name]]]])

define(CERT_DEF,`CERT_START()dnl
Certificate ::= {
  OutputFile   ::= "FILE_NAME_PREFIX`'$1.bin"

  SerialNumber ::= ifelse($4,,`SERIAL_NUMBER',$4)
  IssuerName   ::= <TOP_DN`'ifelse($8,,$2,$8)>
  SubjectName  ::= <TOP_DN`'ifelse($7,,$1,$7)>
  Extensions ::= {
    SubjectAltNames ::= {
	$3
    }
    KeyUsage ::= {
      DigitalSignature
      ifelse($6,`dsaEncryption',,`KeyEncipherment')
    }
  }
  Validity     ::= {
    NotBefore  ::= "START_TIME"
    NotAfter   ::= "END_TIME"
  }
  PublicKeyInfo ::= {
   ifelse(USE_OLD_PRIVATE_KEY_FILES,`USE_OLD_PRIVATE_KEY_FILES',
    Size ::= KEY_BITS_KEY
    Type ::= ifelse($6,`',`rsaEncryption',$6)
    PrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv"
   ,InputPrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv")
  }
  Signature ::= {
    SignatureAlgorithm ::= ifelse($5,,SIGNATURE_FORMAT,$5)
    IssuerKeyFile ::= "FILE_NAME_PREFIX`'$2.prv"
  }
}
')


dnl
dnl Create end user key with old private key
dnl
dnl CERT_DEF_WITHKEY(name, new name, issuer, subject alt names, serial number
dnl [, sig format [, key type [, cert name [, issuer name]]]])

define(CERT_DEF_WITHKEY,`CERT_START()dnl
Certificate ::= {
  OutputFile   ::= "FILE_NAME_PREFIX`'$2.bin"

  SerialNumber ::= ifelse($5,,`SERIAL_NUMBER',$5)
  IssuerName   ::= <TOP_DN`'ifelse($9,,$3,$9)>
  SubjectName  ::= <TOP_DN`'ifelse($8,,$2,$8)>
  Extensions ::= {
    SubjectAltNames ::= {
	$4
    }
    KeyUsage ::= {
      DigitalSignature
      ifelse($7,`dsaEncryption',,`KeyEncipherment')
    }
  }
  Validity     ::= {
    NotBefore  ::= "START_TIME"
    NotAfter   ::= "END_TIME"
  }
  PublicKeyInfo ::= {
    InputPrivateKeyFile ::= "FILE_NAME_PREFIX`'$1.prv"
  }
  Signature ::= {
    SignatureAlgorithm ::= ifelse($6,,SIGNATURE_FORMAT,$6)
    IssuerKeyFile ::= "FILE_NAME_PREFIX`'$3.prv"
  }
}
')

define(REVOKE_LIST,`ifelse($1,`',`',`REVOKE_COMMENT   { SerialNumber ::= $1
REVOKE_COMMENT     RevocationDate ::= "THIS_TIME" }
REVOKE_LIST(shift($@))')')

dnl
dnl Create certificate revocation list
dnl
dnl CRL_DEF(name, serial numbers ...)

define(CRL_DEF,`CRL_START()dnl
CRL ::= {
  OutputFile ::= "FILE_NAME_PREFIX`'$1.crl"

  Signature ::= {
    SignatureAlgorithm ::= SIGNATURE_FORMAT
    IssuerKeyFile     ::= "FILE_NAME_PREFIX`'$1.prv"
  }

  IssuerName ::= <TOP_DN`'$1>
  ThisUpdate ::= "THIS_TIME"
  NextUpdate ::= "NEXT_TIME"
  RevokedCertificates ::= [
REVOKE_LIST(shift($@))dnl
  ] % end revoked certificates list
}
')

dnl
dnl Create certificate revocation list with issuer name
dnl
dnl CRL_DEF_WITHNAME(name, issuer name, serial numbers ...)

define(CRL_DEF_WITHNAME,`CRL_START()dnl
CRL ::= {
  OutputFile ::= "FILE_NAME_PREFIX`'$1.crl"

  Signature ::= {
    SignatureAlgorithm ::= SIGNATURE_FORMAT
    IssuerKeyFile     ::= "FILE_NAME_PREFIX`'$1.prv"
  }

  IssuerName ::= <TOP_DN`'$2>
  ThisUpdate ::= "THIS_TIME"
  NextUpdate ::= "NEXT_TIME"
  RevokedCertificates ::= [
REVOKE_LIST(shift(shift($@)))dnl
  ] % end revoked certificates list
}
')
