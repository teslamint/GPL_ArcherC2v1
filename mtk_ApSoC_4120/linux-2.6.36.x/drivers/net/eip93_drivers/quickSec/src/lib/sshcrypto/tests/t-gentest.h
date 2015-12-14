#ifndef PKCS_CNT
#define PKCS_CNT 100
#endif

extern char *srcpath;
/*, filename[128];*/
extern Boolean verbose;

/* Minimum test time in seconds */
#define TEST_TIME_MIN (getenv("SSH_TIMING") ? atof(getenv("SSH_TIMING")) : 0.3)
/* Optimum test time in milliseconds */
#define TEST_TIME_OPTIMUM       (TEST_TIME_MIN * 1500)
/* Reporting format */
#define TEST_FMT                "%.0f"
#define SPEED_FMT                "%6.3f"

Boolean test_random(const char *name, int flags);

void tstart(SshTimeMeasure tmit, char *fmt, ...);
void tstop(SshTimeMeasure tmit, char *fmt, ...);

void tstartn(SshTimeMeasure tmit, int total, char *fmt, ...);
int  tstopn(SshTimeMeasure tmit, int total, char *fmt, ...);

#define MODE_ECB (1 << 6)
#define MODE_CBC (1 << 7)
#define MODE_CFB (1 << 8)
#define MODE_OFB (1 << 9)

typedef struct HexRenderRec {
  size_t length;
  const unsigned char *data;
} *HexRender, HexRenderStruct;

int hex_render(unsigned char *buf, int buf_size, int prec, void *datum);

/* Compare two public keys */
Boolean
cmp_public_keys(SshPublicKey a, SshPublicKey b);

/* PKCS tests */
Boolean predefined_groups_tests(void);
Boolean pkcs_tests(Boolean speed_test);
Boolean pkcs_random_tests(Boolean speed_test);
/* from pkcs-static-test.c */
Boolean pkcs_static_tests(const char *filename);
Boolean pkcs_static_tests_do(const char *filename);
Boolean oaep_static_tests(Boolean verbose);
Boolean pss_static_tests(Boolean verbose);
Boolean fips_dss_static_tests(Boolean verbose);
Boolean pkcs_import_export_tests(const char *filename);
Boolean pkcs_import_export_tests_do(const char *filename);
Boolean pkcs_rsa_e_equal_3_signature_forgery_test(Boolean verbose);
#ifdef SSHDIST_CRYPT_ECP
Boolean ecp_ietf_groups_diffie_hellman_test(Boolean verbose);
Boolean ecp_ietf_groups_dsa_test(Boolean verbose);
#endif /* SSHDIST_CRYPT_ECP */

/* Hash tests */
Boolean hash_static_tests(const char *filename);
Boolean hash_random_tests(Boolean speed_test, size_t len);
Boolean hash_asn1_encode_test(void);

/* MAC tests */
Boolean mac_random_tests(Boolean speed_test, size_t len);
Boolean mac_static_tests(const char *filename);
Boolean mac_static_tests_do(const char *filename);

/* Cipher tests */
Boolean cipher_random_tests(Boolean speed_test, int flag, size_t len);
Boolean cipher_static_tests(const char *filename);
Boolean cipher_static_tests_do(const char *filename);

/* Combined cipher and MAC speed tests */
Boolean encrypt_auth_speed_tests(size_t len);

/* Misc tests */

Boolean misc_nonfips_tests(void);


#ifdef SSHDIST_IPSEC_HWACCEL_OCTEON
#ifdef ASM_PLATFORM_OCTEON
Boolean octeon_combined_consistency_tests(size_t len);
void octeon_combined_speed_tests(size_t len);
#endif /* ASM_PLATFORM_OCTEON */
#endif /* SSHDIST_IPSEC_HWACCEL_OCTEON */
