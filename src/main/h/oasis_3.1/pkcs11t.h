/*
 * PKCS #11 Specification Version 3.1
 * Committee Specification 01
 * 11 August 2022
 * Copyright (c) OASIS Open 2022. All Rights Reserved.
 * Source: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/cs01/include/pkcs11-v3.1/
 * Latest stage of narrative specification: https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/pkcs11-spec-v3.1.html
 * TC IPR Statement: https://www.oasis-open.org/committees/pkcs11/ipr.php 
 */

/* See top of pkcs11.h for information about the macros that
 * must be defined and the structure-packing conventions that
 * must be set before including this file.
 */

#ifndef _PKCS11T_H_
#define _PKCS11T_H_ 1

#define CRYPTOKI_VERSION_MAJOR          3
#define CRYPTOKI_VERSION_MINOR          1
#define CRYPTOKI_VERSION_AMENDMENT      0

#define CK_TRUE         1
#define CK_FALSE        0

#ifndef CK_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE CK_FALSE
#endif
#ifndef TRUE
#define TRUE CK_TRUE
#endif
#endif

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;


/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION      (~0UL)
#define CK_EFFECTIVELY_INFINITE         0UL


typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
typedef void        CK_PTR   CK_VOID_PTR;

/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;


/* The following value is always invalid if used as a session
 * handle or object handle
 */
#define CK_INVALID_HANDLE       0UL


typedef struct CK_VERSION {
  CK_BYTE       major;  /* integer portion of version number */
  CK_BYTE       minor;  /* 1/100ths portion of version number */
} CK_VERSION;

typedef CK_VERSION CK_PTR CK_VERSION_PTR;


typedef struct CK_INFO {
  CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_FLAGS      flags;               /* must be zero */
  CK_UTF8CHAR   libraryDescription[32];  /* blank padded */
  CK_VERSION    libraryVersion;          /* version of library */
} CK_INFO;

typedef CK_INFO CK_PTR    CK_INFO_PTR;


/* CK_NOTIFICATION enumerates the types of notifications that
 * Cryptoki provides to an application
 */
typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER           0UL
#define CKN_OTP_CHANGED         1UL

typedef CK_ULONG          CK_SLOT_ID;

typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;


/* CK_SLOT_INFO provides information about a slot */
typedef struct CK_SLOT_INFO {
  CK_UTF8CHAR   slotDescription[64];  /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];   /* blank padded */
  CK_FLAGS      flags;

  CK_VERSION    hardwareVersion;  /* version of hardware */
  CK_VERSION    firmwareVersion;  /* version of firmware */
} CK_SLOT_INFO;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag              Mask        Meaning
 */
#define CKF_TOKEN_PRESENT     0x00000001UL  /* a token is there */
#define CKF_REMOVABLE_DEVICE  0x00000002UL  /* removable devices*/
#define CKF_HW_SLOT           0x00000004UL  /* hardware slot */

typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;


/* CK_TOKEN_INFO provides information about a token */
typedef struct CK_TOKEN_INFO {
  CK_UTF8CHAR   label[32];           /* blank padded */
  CK_UTF8CHAR   manufacturerID[32];  /* blank padded */
  CK_UTF8CHAR   model[16];           /* blank padded */
  CK_CHAR       serialNumber[16];    /* blank padded */
  CK_FLAGS      flags;               /* see below */

  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
  CK_ULONG      ulSessionCount;        /* sess. now open */
  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
  CK_ULONG      ulMaxPinLen;           /* in bytes */
  CK_ULONG      ulMinPinLen;           /* in bytes */
  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
  CK_ULONG      ulFreePublicMemory;    /* in bytes */
  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
  CK_ULONG      ulFreePrivateMemory;   /* in bytes */
  CK_VERSION    hardwareVersion;       /* version of hardware */
  CK_VERSION    firmwareVersion;       /* version of firmware */
  CK_CHAR       utcTime[16];           /* time */
} CK_TOKEN_INFO;

/* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
#define CKF_RNG                     0x00000001UL  /* has random # generator */
#define CKF_WRITE_PROTECTED         0x00000002UL  /* token is write-protected */
#define CKF_LOGIN_REQUIRED          0x00000004UL  /* user must login */
#define CKF_USER_PIN_INITIALIZED    0x00000008UL  /* normal user's PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED.  If it is set,
 * that means that *every* time the state of cryptographic
 * operations of a session is successfully saved, all keys
 * needed to continue those operations are stored in the state
 */
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020UL

/* CKF_CLOCK_ON_TOKEN.  If it is set, that means
 * that the token has some sort of clock.  The time on that
 * clock is returned in the token info structure
 */
#define CKF_CLOCK_ON_TOKEN          0x00000040UL

/* CKF_PROTECTED_AUTHENTICATION_PATH.  If it is
 * set, that means that there is some way for the user to login
 * without sending a PIN through the Cryptoki library itself
 */
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100UL

/* CKF_DUAL_CRYPTO_OPERATIONS.  If it is true,
 * that means that a single session with the token can perform
 * dual simultaneous cryptographic operations (digest and
 * encrypt; decrypt and digest; sign and encrypt; and decrypt
 * and sign)
 */
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200UL

/* CKF_TOKEN_INITIALIZED. If it is true, the
 * token has been initialized using C_InitializeToken or an
 * equivalent mechanism outside the scope of PKCS #11.
 * Calling C_InitializeToken when this flag is set will cause
 * the token to be reinitialized.
 */
#define CKF_TOKEN_INITIALIZED       0x00000400UL

/* CKF_SECONDARY_AUTHENTICATION. If it is
 * true, the token supports secondary authentication for
 * private key objects.
 */
#define CKF_SECONDARY_AUTHENTICATION  0x00000800UL

/* CKF_USER_PIN_COUNT_LOW. If it is true, an
 * incorrect user login PIN has been entered at least once
 * since the last successful authentication.
 */
#define CKF_USER_PIN_COUNT_LOW       0x00010000UL

/* CKF_USER_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect user PIN will it to become locked.
 */
#define CKF_USER_PIN_FINAL_TRY       0x00020000UL

/* CKF_USER_PIN_LOCKED. If it is true, the
 * user PIN has been locked. User login to the token is not
 * possible.
 */
#define CKF_USER_PIN_LOCKED          0x00040000UL

/* CKF_USER_PIN_TO_BE_CHANGED. If it is true,
 * the user PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
#define CKF_USER_PIN_TO_BE_CHANGED   0x00080000UL

/* CKF_SO_PIN_COUNT_LOW. If it is true, an
 * incorrect SO login PIN has been entered at least once since
 * the last successful authentication.
 */
#define CKF_SO_PIN_COUNT_LOW         0x00100000UL

/* CKF_SO_PIN_FINAL_TRY. If it is true,
 * supplying an incorrect SO PIN will it to become locked.
 */
#define CKF_SO_PIN_FINAL_TRY         0x00200000UL

/* CKF_SO_PIN_LOCKED. If it is true, the SO
 * PIN has been locked. SO login to the token is not possible.
 */
#define CKF_SO_PIN_LOCKED            0x00400000UL

/* CKF_SO_PIN_TO_BE_CHANGED. If it is true,
 * the SO PIN value is the default value set by token
 * initialization or manufacturing, or the PIN has been
 * expired by the card.
 */
#define CKF_SO_PIN_TO_BE_CHANGED     0x00800000UL

#define CKF_ERROR_STATE              0x01000000UL

typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;


/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
 * identifies a session
 */
typedef CK_ULONG          CK_SESSION_HANDLE;

typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;


/* CK_USER_TYPE enumerates the types of Cryptoki users */
typedef CK_ULONG          CK_USER_TYPE;
/* Security Officer */
#define CKU_SO                  0UL
/* Normal user */
#define CKU_USER                1UL
/* Context specific */
#define CKU_CONTEXT_SPECIFIC    2UL

/* CK_STATE enumerates the session states */
typedef CK_ULONG          CK_STATE;
#define CKS_RO_PUBLIC_SESSION   0UL
#define CKS_RO_USER_FUNCTIONS   1UL
#define CKS_RW_PUBLIC_SESSION   2UL
#define CKS_RW_USER_FUNCTIONS   3UL
#define CKS_RW_SO_FUNCTIONS     4UL

/* CK_SESSION_INFO provides information about a session */
typedef struct CK_SESSION_INFO {
  CK_SLOT_ID    slotID;
  CK_STATE      state;
  CK_FLAGS      flags;          /* see below */
  CK_ULONG      ulDeviceError;  /* device-dependent error code */
} CK_SESSION_INFO;

/* The flags are defined in the following table:
 *      Bit Flag                Mask        Meaning
 */
#define CKF_RW_SESSION          0x00000002UL /* session is r/w */
#define CKF_SERIAL_SESSION      0x00000004UL /* no parallel    */

typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;


/* CK_OBJECT_HANDLE is a token-specific identifier for an
 * object
 */
typedef CK_ULONG          CK_OBJECT_HANDLE;

typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;


/* CK_OBJECT_CLASS is a value that identifies the classes (or
 * types) of objects that Cryptoki recognizes.  It is defined
 * as follows:
 */
typedef CK_ULONG          CK_OBJECT_CLASS;

/* The following classes of objects are defined: */
#define CKO_DATA              0x00000000UL
#define CKO_CERTIFICATE       0x00000001UL
#define CKO_PUBLIC_KEY        0x00000002UL
#define CKO_PRIVATE_KEY       0x00000003UL
#define CKO_SECRET_KEY        0x00000004UL
#define CKO_HW_FEATURE        0x00000005UL
#define CKO_DOMAIN_PARAMETERS 0x00000006UL
#define CKO_MECHANISM         0x00000007UL
#define CKO_OTP_KEY           0x00000008UL
#define CKO_PROFILE           0x00000009UL 

#define CKO_VENDOR_DEFINED    0x80000000UL

typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

/* Profile ID's */
#define CKP_INVALID_ID                0x00000000UL
#define CKP_BASELINE_PROVIDER         0x00000001UL
#define CKP_EXTENDED_PROVIDER         0x00000002UL
#define CKP_AUTHENTICATION_TOKEN      0x00000003UL
#define CKP_PUBLIC_CERTIFICATES_TOKEN 0x00000004UL
#define CKP_COMPLETE_PROVIDER         0x00000005UL
#define CKP_HKDF_TLS_TOKEN            0x00000006UL
#define CKP_VENDOR_DEFINED            0x80000000UL


/* CK_HW_FEATURE_TYPE is a value that identifies the hardware feature type
 * of an object with CK_OBJECT_CLASS equal to CKO_HW_FEATURE.
 */
typedef CK_ULONG          CK_HW_FEATURE_TYPE;

/* The following hardware feature types are defined */
#define CKH_MONOTONIC_COUNTER  0x00000001UL
#define CKH_CLOCK              0x00000002UL
#define CKH_USER_INTERFACE     0x00000003UL
#define CKH_VENDOR_DEFINED     0x80000000UL

/* CK_KEY_TYPE is a value that identifies a key type */
typedef CK_ULONG          CK_KEY_TYPE;

/* the following key types are defined: */
#define CKK_RSA                 0x00000000UL
#define CKK_DSA                 0x00000001UL
#define CKK_DH                  0x00000002UL
#define CKK_ECDSA               0x00000003UL /* Deprecated */
#define CKK_EC                  0x00000003UL
#define CKK_X9_42_DH            0x00000004UL
#define CKK_KEA                 0x00000005UL
#define CKK_GENERIC_SECRET      0x00000010UL
#define CKK_RC2                 0x00000011UL
#define CKK_RC4                 0x00000012UL
#define CKK_DES                 0x00000013UL
#define CKK_DES2                0x00000014UL
#define CKK_DES3                0x00000015UL
#define CKK_CAST                0x00000016UL
#define CKK_CAST3               0x00000017UL
#define CKK_CAST5               0x00000018UL /* Deprecated */
#define CKK_CAST128             0x00000018UL
#define CKK_RC5                 0x00000019UL
#define CKK_IDEA                0x0000001AUL
#define CKK_SKIPJACK            0x0000001BUL
#define CKK_BATON               0x0000001CUL
#define CKK_JUNIPER             0x0000001DUL
#define CKK_CDMF                0x0000001EUL
#define CKK_AES                 0x0000001FUL
#define CKK_BLOWFISH            0x00000020UL
#define CKK_TWOFISH             0x00000021UL
#define CKK_SECURID             0x00000022UL
#define CKK_HOTP                0x00000023UL
#define CKK_ACTI                0x00000024UL
#define CKK_CAMELLIA            0x00000025UL
#define CKK_ARIA                0x00000026UL

/* the following definitions were added in the 2.30 header file,
 * but never defined in the spec. */
#define CKK_MD5_HMAC            0x00000027UL
#define CKK_SHA_1_HMAC          0x00000028UL
#define CKK_RIPEMD128_HMAC      0x00000029UL
#define CKK_RIPEMD160_HMAC      0x0000002AUL
#define CKK_SHA256_HMAC         0x0000002BUL
#define CKK_SHA384_HMAC         0x0000002CUL
#define CKK_SHA512_HMAC         0x0000002DUL
#define CKK_SHA224_HMAC         0x0000002EUL

#define CKK_SEED                0x0000002FUL
#define CKK_GOSTR3410           0x00000030UL
#define CKK_GOSTR3411           0x00000031UL
#define CKK_GOST28147           0x00000032UL
#define CKK_CHACHA20            0x00000033UL
#define CKK_POLY1305            0x00000034UL
#define CKK_AES_XTS             0x00000035UL
#define CKK_SHA3_224_HMAC       0x00000036UL
#define CKK_SHA3_256_HMAC       0x00000037UL
#define CKK_SHA3_384_HMAC       0x00000038UL
#define CKK_SHA3_512_HMAC       0x00000039UL
#define CKK_BLAKE2B_160_HMAC    0x0000003aUL
#define CKK_BLAKE2B_256_HMAC    0x0000003bUL
#define CKK_BLAKE2B_384_HMAC    0x0000003cUL
#define CKK_BLAKE2B_512_HMAC    0x0000003dUL
#define CKK_SALSA20             0x0000003eUL
#define CKK_X2RATCHET           0x0000003fUL
#define CKK_EC_EDWARDS          0x00000040UL
#define CKK_EC_MONTGOMERY       0x00000041UL
#define CKK_HKDF                0x00000042UL

#define CKK_SHA512_224_HMAC     0x00000043UL
#define CKK_SHA512_256_HMAC     0x00000044UL
#define CKK_SHA512_T_HMAC       0x00000045UL
#define CKK_HSS                 0x00000046UL

#define CKK_VENDOR_DEFINED      0x80000000UL


/* CK_CERTIFICATE_TYPE is a value that identifies a certificate
 * type
 */
typedef CK_ULONG          CK_CERTIFICATE_TYPE;

#define CK_CERTIFICATE_CATEGORY_UNSPECIFIED     0UL
#define CK_CERTIFICATE_CATEGORY_TOKEN_USER      1UL
#define CK_CERTIFICATE_CATEGORY_AUTHORITY       2UL
#define CK_CERTIFICATE_CATEGORY_OTHER_ENTITY    3UL

#define CK_SECURITY_DOMAIN_UNSPECIFIED     0UL
#define CK_SECURITY_DOMAIN_MANUFACTURER    1UL
#define CK_SECURITY_DOMAIN_OPERATOR        2UL
#define CK_SECURITY_DOMAIN_THIRD_PARTY     3UL


/* The following certificate types are defined: */
#define CKC_X_509               0x00000000UL
#define CKC_X_509_ATTR_CERT     0x00000001UL
#define CKC_WTLS                0x00000002UL
#define CKC_VENDOR_DEFINED      0x80000000UL


/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
 * type
 */
typedef CK_ULONG          CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
 * consists of an array of values.
 */
#define CKF_ARRAY_ATTRIBUTE     0x40000000UL

/* The following OTP-related defines relate to the CKA_OTP_FORMAT attribute */
#define CK_OTP_FORMAT_DECIMAL           0UL
#define CK_OTP_FORMAT_HEXADECIMAL       1UL
#define CK_OTP_FORMAT_ALPHANUMERIC      2UL
#define CK_OTP_FORMAT_BINARY            3UL

/* The following OTP-related defines relate to the CKA_OTP_..._REQUIREMENT
 * attributes
 */
#define CK_OTP_PARAM_IGNORED            0UL
#define CK_OTP_PARAM_OPTIONAL           1UL
#define CK_OTP_PARAM_MANDATORY          2UL

/* The following attribute types are defined: */
#define CKA_CLASS              0x00000000UL
#define CKA_TOKEN              0x00000001UL
#define CKA_PRIVATE            0x00000002UL
#define CKA_LABEL              0x00000003UL
#define CKA_UNIQUE_ID          0x00000004UL
#define CKA_APPLICATION        0x00000010UL
#define CKA_VALUE              0x00000011UL
#define CKA_OBJECT_ID          0x00000012UL
#define CKA_CERTIFICATE_TYPE   0x00000080UL
#define CKA_ISSUER             0x00000081UL
#define CKA_SERIAL_NUMBER      0x00000082UL
#define CKA_AC_ISSUER          0x00000083UL
#define CKA_OWNER              0x00000084UL
#define CKA_ATTR_TYPES         0x00000085UL
#define CKA_TRUSTED            0x00000086UL
#define CKA_CERTIFICATE_CATEGORY        0x00000087UL
#define CKA_JAVA_MIDP_SECURITY_DOMAIN   0x00000088UL
#define CKA_URL                         0x00000089UL
#define CKA_HASH_OF_SUBJECT_PUBLIC_KEY  0x0000008aUL
#define CKA_HASH_OF_ISSUER_PUBLIC_KEY   0x0000008bUL
#define CKA_NAME_HASH_ALGORITHM         0x0000008cUL
#define CKA_CHECK_VALUE                 0x00000090UL

#define CKA_KEY_TYPE           0x00000100UL
#define CKA_SUBJECT            0x00000101UL
#define CKA_ID                 0x00000102UL
#define CKA_SENSITIVE          0x00000103UL
#define CKA_ENCRYPT            0x00000104UL
#define CKA_DECRYPT            0x00000105UL
#define CKA_WRAP               0x00000106UL
#define CKA_UNWRAP             0x00000107UL
#define CKA_SIGN               0x00000108UL
#define CKA_SIGN_RECOVER       0x00000109UL
#define CKA_VERIFY             0x0000010aUL
#define CKA_VERIFY_RECOVER     0x0000010bUL
#define CKA_DERIVE             0x0000010cUL
#define CKA_START_DATE         0x00000110UL
#define CKA_END_DATE           0x00000111UL
#define CKA_MODULUS            0x00000120UL
#define CKA_MODULUS_BITS       0x00000121UL
#define CKA_PUBLIC_EXPONENT    0x00000122UL
#define CKA_PRIVATE_EXPONENT   0x00000123UL
#define CKA_PRIME_1            0x00000124UL
#define CKA_PRIME_2            0x00000125UL
#define CKA_EXPONENT_1         0x00000126UL
#define CKA_EXPONENT_2         0x00000127UL
#define CKA_COEFFICIENT        0x00000128UL
#define CKA_PUBLIC_KEY_INFO    0x00000129UL
#define CKA_PRIME              0x00000130UL
#define CKA_SUBPRIME           0x00000131UL
#define CKA_BASE               0x00000132UL

#define CKA_PRIME_BITS         0x00000133UL
#define CKA_SUBPRIME_BITS      0x00000134UL
#define CKA_SUB_PRIME_BITS     CKA_SUBPRIME_BITS

#define CKA_VALUE_BITS         0x00000160UL
#define CKA_VALUE_LEN          0x00000161UL
#define CKA_EXTRACTABLE        0x00000162UL
#define CKA_LOCAL              0x00000163UL
#define CKA_NEVER_EXTRACTABLE  0x00000164UL
#define CKA_ALWAYS_SENSITIVE   0x00000165UL
#define CKA_KEY_GEN_MECHANISM  0x00000166UL

#define CKA_MODIFIABLE         0x00000170UL
#define CKA_COPYABLE           0x00000171UL

#define CKA_DESTROYABLE        0x00000172UL

#define CKA_ECDSA_PARAMS       0x00000180UL /* Deprecated */
#define CKA_EC_PARAMS          0x00000180UL

#define CKA_EC_POINT           0x00000181UL

#define CKA_SECONDARY_AUTH     0x00000200UL /* Deprecated */
#define CKA_AUTH_PIN_FLAGS     0x00000201UL /* Deprecated */

#define CKA_ALWAYS_AUTHENTICATE  0x00000202UL

#define CKA_WRAP_WITH_TRUSTED    0x00000210UL
#define CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211UL)
#define CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212UL)
#define CKA_DERIVE_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000213UL)

#define CKA_OTP_FORMAT                0x00000220UL
#define CKA_OTP_LENGTH                0x00000221UL
#define CKA_OTP_TIME_INTERVAL         0x00000222UL
#define CKA_OTP_USER_FRIENDLY_MODE    0x00000223UL
#define CKA_OTP_CHALLENGE_REQUIREMENT 0x00000224UL
#define CKA_OTP_TIME_REQUIREMENT      0x00000225UL
#define CKA_OTP_COUNTER_REQUIREMENT   0x00000226UL
#define CKA_OTP_PIN_REQUIREMENT       0x00000227UL
#define CKA_OTP_COUNTER               0x0000022eUL
#define CKA_OTP_TIME                  0x0000022fUL
#define CKA_OTP_USER_IDENTIFIER       0x0000022aUL
#define CKA_OTP_SERVICE_IDENTIFIER    0x0000022bUL
#define CKA_OTP_SERVICE_LOGO          0x0000022cUL
#define CKA_OTP_SERVICE_LOGO_TYPE     0x0000022dUL

#define CKA_GOSTR3410_PARAMS            0x00000250UL
#define CKA_GOSTR3411_PARAMS            0x00000251UL
#define CKA_GOST28147_PARAMS            0x00000252UL

#define CKA_HW_FEATURE_TYPE             0x00000300UL
#define CKA_RESET_ON_INIT               0x00000301UL
#define CKA_HAS_RESET                   0x00000302UL

#define CKA_PIXEL_X                     0x00000400UL
#define CKA_PIXEL_Y                     0x00000401UL
#define CKA_RESOLUTION                  0x00000402UL
#define CKA_CHAR_ROWS                   0x00000403UL
#define CKA_CHAR_COLUMNS                0x00000404UL
#define CKA_COLOR                       0x00000405UL
#define CKA_BITS_PER_PIXEL              0x00000406UL
#define CKA_CHAR_SETS                   0x00000480UL
#define CKA_ENCODING_METHODS            0x00000481UL
#define CKA_MIME_TYPES                  0x00000482UL
#define CKA_MECHANISM_TYPE              0x00000500UL
#define CKA_REQUIRED_CMS_ATTRIBUTES     0x00000501UL
#define CKA_DEFAULT_CMS_ATTRIBUTES      0x00000502UL
#define CKA_SUPPORTED_CMS_ATTRIBUTES    0x00000503UL
#define CKA_ALLOWED_MECHANISMS          (CKF_ARRAY_ATTRIBUTE|0x00000600UL)
#define CKA_PROFILE_ID                  0x00000601UL

#define CKA_X2RATCHET_BAG               0x00000602UL
#define CKA_X2RATCHET_BAGSIZE           0x00000603UL
#define CKA_X2RATCHET_BOBS1STMSG        0x00000604UL
#define CKA_X2RATCHET_CKR               0x00000605UL
#define CKA_X2RATCHET_CKS               0x00000606UL
#define CKA_X2RATCHET_DHP               0x00000607UL
#define CKA_X2RATCHET_DHR               0x00000608UL
#define CKA_X2RATCHET_DHS               0x00000609UL
#define CKA_X2RATCHET_HKR               0x0000060aUL
#define CKA_X2RATCHET_HKS               0x0000060bUL
#define CKA_X2RATCHET_ISALICE           0x0000060cUL
#define CKA_X2RATCHET_NHKR              0x0000060dUL
#define CKA_X2RATCHET_NHKS              0x0000060eUL
#define CKA_X2RATCHET_NR                0x0000060fUL
#define CKA_X2RATCHET_NS                0x00000610UL
#define CKA_X2RATCHET_PNS               0x00000611UL
#define CKA_X2RATCHET_RK                0x00000612UL
/* HSS */
#define CKA_HSS_LEVELS                  0x00000617UL
#define CKA_HSS_LMS_TYPE                0x00000618UL
#define CKA_HSS_LMOTS_TYPE              0x00000619UL
#define CKA_HSS_LMS_TYPES               0x0000061aUL
#define CKA_HSS_LMOTS_TYPES             0x0000061bUL
#define CKA_HSS_KEYS_REMAINING          0x0000061cUL

#define CKA_VENDOR_DEFINED              0x80000000UL

/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute
 */
typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR       pValue;
  CK_ULONG          ulValueLen;  /* in bytes */
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;

/* CK_DATE is a structure that defines a date */
typedef struct CK_DATE{
  CK_CHAR       year[4];   /* the year ("1900" - "9999") */
  CK_CHAR       month[2];  /* the month ("01" - "12") */
  CK_CHAR       day[2];    /* the day   ("01" - "31") */
} CK_DATE;


/* CK_MECHANISM_TYPE is a value that identifies a mechanism
 * type
 */
typedef CK_ULONG          CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000UL
#define CKM_RSA_PKCS                   0x00000001UL
#define CKM_RSA_9796                   0x00000002UL
#define CKM_RSA_X_509                  0x00000003UL

#define CKM_MD2_RSA_PKCS               0x00000004UL
#define CKM_MD5_RSA_PKCS               0x00000005UL
#define CKM_SHA1_RSA_PKCS              0x00000006UL

#define CKM_RIPEMD128_RSA_PKCS         0x00000007UL
#define CKM_RIPEMD160_RSA_PKCS         0x00000008UL
#define CKM_RSA_PKCS_OAEP              0x00000009UL

#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000aUL
#define CKM_RSA_X9_31                  0x0000000bUL
#define CKM_SHA1_RSA_X9_31             0x0000000cUL
#define CKM_RSA_PKCS_PSS               0x0000000dUL
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000eUL

#define CKM_DSA_KEY_PAIR_GEN           0x00000010UL
#define CKM_DSA                        0x00000011UL
#define CKM_DSA_SHA1                   0x00000012UL
#define CKM_DSA_SHA224                 0x00000013UL
#define CKM_DSA_SHA256                 0x00000014UL
#define CKM_DSA_SHA384                 0x00000015UL
#define CKM_DSA_SHA512                 0x00000016UL
#define CKM_DSA_SHA3_224               0x00000018UL
#define CKM_DSA_SHA3_256               0x00000019UL
#define CKM_DSA_SHA3_384               0x0000001aUL
#define CKM_DSA_SHA3_512               0x0000001bUL

#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020UL
#define CKM_DH_PKCS_DERIVE             0x00000021UL

#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030UL
#define CKM_X9_42_DH_DERIVE            0x00000031UL
#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032UL
#define CKM_X9_42_MQV_DERIVE           0x00000033UL

#define CKM_SHA256_RSA_PKCS            0x00000040UL
#define CKM_SHA384_RSA_PKCS            0x00000041UL
#define CKM_SHA512_RSA_PKCS            0x00000042UL
#define CKM_SHA256_RSA_PKCS_PSS        0x00000043UL
#define CKM_SHA384_RSA_PKCS_PSS        0x00000044UL
#define CKM_SHA512_RSA_PKCS_PSS        0x00000045UL

#define CKM_SHA224_RSA_PKCS            0x00000046UL
#define CKM_SHA224_RSA_PKCS_PSS        0x00000047UL

#define CKM_SHA512_224                 0x00000048UL
#define CKM_SHA512_224_HMAC            0x00000049UL
#define CKM_SHA512_224_HMAC_GENERAL    0x0000004aUL
#define CKM_SHA512_224_KEY_DERIVATION  0x0000004bUL
#define CKM_SHA512_256                 0x0000004cUL
#define CKM_SHA512_256_HMAC            0x0000004dUL
#define CKM_SHA512_256_HMAC_GENERAL    0x0000004eUL
#define CKM_SHA512_256_KEY_DERIVATION  0x0000004fUL

#define CKM_SHA512_T                   0x00000050UL
#define CKM_SHA512_T_HMAC              0x00000051UL
#define CKM_SHA512_T_HMAC_GENERAL      0x00000052UL
#define CKM_SHA512_T_KEY_DERIVATION    0x00000053UL

#define CKM_SHA3_256_RSA_PKCS          0x00000060UL
#define CKM_SHA3_384_RSA_PKCS          0x00000061UL
#define CKM_SHA3_512_RSA_PKCS          0x00000062UL
#define CKM_SHA3_256_RSA_PKCS_PSS      0x00000063UL
#define CKM_SHA3_384_RSA_PKCS_PSS      0x00000064UL
#define CKM_SHA3_512_RSA_PKCS_PSS      0x00000065UL
#define CKM_SHA3_224_RSA_PKCS          0x00000066UL
#define CKM_SHA3_224_RSA_PKCS_PSS      0x00000067UL

#define CKM_RC2_KEY_GEN                0x00000100UL
#define CKM_RC2_ECB                    0x00000101UL
#define CKM_RC2_CBC                    0x00000102UL
#define CKM_RC2_MAC                    0x00000103UL

#define CKM_RC2_MAC_GENERAL            0x00000104UL
#define CKM_RC2_CBC_PAD                0x00000105UL

#define CKM_RC4_KEY_GEN                0x00000110UL
#define CKM_RC4                        0x00000111UL
#define CKM_DES_KEY_GEN                0x00000120UL
#define CKM_DES_ECB                    0x00000121UL
#define CKM_DES_CBC                    0x00000122UL
#define CKM_DES_MAC                    0x00000123UL

#define CKM_DES_MAC_GENERAL            0x00000124UL
#define CKM_DES_CBC_PAD                0x00000125UL

#define CKM_DES2_KEY_GEN               0x00000130UL
#define CKM_DES3_KEY_GEN               0x00000131UL
#define CKM_DES3_ECB                   0x00000132UL
#define CKM_DES3_CBC                   0x00000133UL
#define CKM_DES3_MAC                   0x00000134UL

#define CKM_DES3_MAC_GENERAL           0x00000135UL
#define CKM_DES3_CBC_PAD               0x00000136UL
#define CKM_DES3_CMAC_GENERAL          0x00000137UL
#define CKM_DES3_CMAC                  0x00000138UL
#define CKM_CDMF_KEY_GEN               0x00000140UL
#define CKM_CDMF_ECB                   0x00000141UL
#define CKM_CDMF_CBC                   0x00000142UL
#define CKM_CDMF_MAC                   0x00000143UL
#define CKM_CDMF_MAC_GENERAL           0x00000144UL
#define CKM_CDMF_CBC_PAD               0x00000145UL

#define CKM_DES_OFB64                  0x00000150UL
#define CKM_DES_OFB8                   0x00000151UL
#define CKM_DES_CFB64                  0x00000152UL
#define CKM_DES_CFB8                   0x00000153UL

#define CKM_MD2                        0x00000200UL

#define CKM_MD2_HMAC                   0x00000201UL
#define CKM_MD2_HMAC_GENERAL           0x00000202UL

#define CKM_MD5                        0x00000210UL

#define CKM_MD5_HMAC                   0x00000211UL
#define CKM_MD5_HMAC_GENERAL           0x00000212UL

#define CKM_SHA_1                      0x00000220UL

#define CKM_SHA_1_HMAC                 0x00000221UL
#define CKM_SHA_1_HMAC_GENERAL         0x00000222UL

#define CKM_RIPEMD128                  0x00000230UL
#define CKM_RIPEMD128_HMAC             0x00000231UL
#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232UL
#define CKM_RIPEMD160                  0x00000240UL
#define CKM_RIPEMD160_HMAC             0x00000241UL
#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242UL

#define CKM_SHA256                     0x00000250UL
#define CKM_SHA256_HMAC                0x00000251UL
#define CKM_SHA256_HMAC_GENERAL        0x00000252UL
#define CKM_SHA224                     0x00000255UL
#define CKM_SHA224_HMAC                0x00000256UL
#define CKM_SHA224_HMAC_GENERAL        0x00000257UL
#define CKM_SHA384                     0x00000260UL
#define CKM_SHA384_HMAC                0x00000261UL
#define CKM_SHA384_HMAC_GENERAL        0x00000262UL
#define CKM_SHA512                     0x00000270UL
#define CKM_SHA512_HMAC                0x00000271UL
#define CKM_SHA512_HMAC_GENERAL        0x00000272UL
#define CKM_SECURID_KEY_GEN            0x00000280UL
#define CKM_SECURID                    0x00000282UL
#define CKM_HOTP_KEY_GEN               0x00000290UL
#define CKM_HOTP                       0x00000291UL
#define CKM_ACTI                       0x000002a0UL
#define CKM_ACTI_KEY_GEN               0x000002a1UL

#define CKM_SHA3_256                   0x000002b0UL
#define CKM_SHA3_256_HMAC              0x000002b1UL
#define CKM_SHA3_256_HMAC_GENERAL      0x000002b2UL
#define CKM_SHA3_256_KEY_GEN           0x000002b3UL
#define CKM_SHA3_224                   0x000002b5UL
#define CKM_SHA3_224_HMAC              0x000002b6UL
#define CKM_SHA3_224_HMAC_GENERAL      0x000002b7UL
#define CKM_SHA3_224_KEY_GEN           0x000002b8UL
#define CKM_SHA3_384                   0x000002c0UL
#define CKM_SHA3_384_HMAC              0x000002c1UL
#define CKM_SHA3_384_HMAC_GENERAL      0x000002c2UL
#define CKM_SHA3_384_KEY_GEN           0x000002c3UL
#define CKM_SHA3_512                   0x000002d0UL
#define CKM_SHA3_512_HMAC              0x000002d1UL
#define CKM_SHA3_512_HMAC_GENERAL      0x000002d2UL
#define CKM_SHA3_512_KEY_GEN           0x000002d3UL


#define CKM_CAST_KEY_GEN               0x00000300UL
#define CKM_CAST_ECB                   0x00000301UL
#define CKM_CAST_CBC                   0x00000302UL
#define CKM_CAST_MAC                   0x00000303UL
#define CKM_CAST_MAC_GENERAL           0x00000304UL
#define CKM_CAST_CBC_PAD               0x00000305UL
#define CKM_CAST3_KEY_GEN              0x00000310UL
#define CKM_CAST3_ECB                  0x00000311UL
#define CKM_CAST3_CBC                  0x00000312UL
#define CKM_CAST3_MAC                  0x00000313UL
#define CKM_CAST3_MAC_GENERAL          0x00000314UL
#define CKM_CAST3_CBC_PAD              0x00000315UL
/* Note that CAST128 and CAST5 are the same algorithm */
#define CKM_CAST5_KEY_GEN              0x00000320UL
#define CKM_CAST128_KEY_GEN            0x00000320UL
#define CKM_CAST5_ECB                  0x00000321UL
#define CKM_CAST128_ECB                0x00000321UL
#define CKM_CAST5_CBC                  0x00000322UL /* Deprecated */
#define CKM_CAST128_CBC                0x00000322UL
#define CKM_CAST5_MAC                  0x00000323UL /* Deprecated */
#define CKM_CAST128_MAC                0x00000323UL
#define CKM_CAST5_MAC_GENERAL          0x00000324UL /* Deprecated */
#define CKM_CAST128_MAC_GENERAL        0x00000324UL
#define CKM_CAST5_CBC_PAD              0x00000325UL /* Deprecated */
#define CKM_CAST128_CBC_PAD            0x00000325UL
#define CKM_RC5_KEY_GEN                0x00000330UL
#define CKM_RC5_ECB                    0x00000331UL
#define CKM_RC5_CBC                    0x00000332UL
#define CKM_RC5_MAC                    0x00000333UL
#define CKM_RC5_MAC_GENERAL            0x00000334UL
#define CKM_RC5_CBC_PAD                0x00000335UL
#define CKM_IDEA_KEY_GEN               0x00000340UL
#define CKM_IDEA_ECB                   0x00000341UL
#define CKM_IDEA_CBC                   0x00000342UL
#define CKM_IDEA_MAC                   0x00000343UL
#define CKM_IDEA_MAC_GENERAL           0x00000344UL
#define CKM_IDEA_CBC_PAD               0x00000345UL
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350UL
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360UL
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362UL
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363UL
#define CKM_XOR_BASE_AND_DATA          0x00000364UL
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365UL
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370UL
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371UL
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372UL

#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373UL
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374UL
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375UL
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376UL
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377UL

#define CKM_TLS_PRF                    0x00000378UL

#define CKM_SSL3_MD5_MAC               0x00000380UL
#define CKM_SSL3_SHA1_MAC              0x00000381UL
#define CKM_MD5_KEY_DERIVATION         0x00000390UL
#define CKM_MD2_KEY_DERIVATION         0x00000391UL
#define CKM_SHA1_KEY_DERIVATION        0x00000392UL

#define CKM_SHA256_KEY_DERIVATION      0x00000393UL
#define CKM_SHA384_KEY_DERIVATION      0x00000394UL
#define CKM_SHA512_KEY_DERIVATION      0x00000395UL
#define CKM_SHA224_KEY_DERIVATION      0x00000396UL
#define CKM_SHA3_256_KEY_DERIVATION    0x00000397UL
#define CKM_SHA3_224_KEY_DERIVATION    0x00000398UL
#define CKM_SHA3_384_KEY_DERIVATION    0x00000399UL
#define CKM_SHA3_512_KEY_DERIVATION    0x0000039aUL
#define CKM_SHAKE_128_KEY_DERIVATION   0x0000039bUL
#define CKM_SHAKE_256_KEY_DERIVATION   0x0000039cUL
#define CKM_SHA3_256_KEY_DERIVE  CKM_SHA3_256_KEY_DERIVATION
#define CKM_SHA3_224_KEY_DERIVE  CKM_SHA3_224_KEY_DERIVATION
#define CKM_SHA3_384_KEY_DERIVE  CKM_SHA3_384_KEY_DERIVATION
#define CKM_SHA3_512_KEY_DERIVE  CKM_SHA3_512_KEY_DERIVATION
#define CKM_SHAKE_128_KEY_DERIVE CKM_SHAKE_128_KEY_DERIVATION
#define CKM_SHAKE_256_KEY_DERIVE CKM_SHAKE_256_KEY_DERIVATION

#define CKM_PBE_MD2_DES_CBC            0x000003a0UL
#define CKM_PBE_MD5_DES_CBC            0x000003a1UL
#define CKM_PBE_MD5_CAST_CBC           0x000003a2UL
#define CKM_PBE_MD5_CAST3_CBC          0x000003a3UL
#define CKM_PBE_MD5_CAST5_CBC          0x000003a4UL /* Deprecated */
#define CKM_PBE_MD5_CAST128_CBC        0x000003a4UL
#define CKM_PBE_SHA1_CAST5_CBC         0x000003a5UL /* Deprecated */
#define CKM_PBE_SHA1_CAST128_CBC       0x000003a5UL
#define CKM_PBE_SHA1_RC4_128           0x000003a6UL
#define CKM_PBE_SHA1_RC4_40            0x000003a7UL
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003a8UL
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003a9UL
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003aaUL
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003abUL

#define CKM_PKCS5_PBKD2                0x000003b0UL

#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003c0UL

#define CKM_WTLS_PRE_MASTER_KEY_GEN         0x000003d0UL
#define CKM_WTLS_MASTER_KEY_DERIVE          0x000003d1UL
#define CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC   0x000003d2UL
#define CKM_WTLS_PRF                        0x000003d3UL
#define CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE  0x000003d4UL
#define CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE  0x000003d5UL

#define CKM_TLS10_MAC_SERVER                0x000003d6UL
#define CKM_TLS10_MAC_CLIENT                0x000003d7UL
#define CKM_TLS12_MAC                       0x000003d8UL
#define CKM_TLS12_KDF                       0x000003d9UL
#define CKM_TLS12_MASTER_KEY_DERIVE         0x000003e0UL
#define CKM_TLS12_KEY_AND_MAC_DERIVE        0x000003e1UL
#define CKM_TLS12_MASTER_KEY_DERIVE_DH      0x000003e2UL
#define CKM_TLS12_KEY_SAFE_DERIVE           0x000003e3UL
#define CKM_TLS_MAC                         0x000003e4UL
#define CKM_TLS_KDF                         0x000003e5UL

#define CKM_KEY_WRAP_LYNKS             0x00000400UL
#define CKM_KEY_WRAP_SET_OAEP          0x00000401UL

#define CKM_CMS_SIG                    0x00000500UL
#define CKM_KIP_DERIVE                 0x00000510UL
#define CKM_KIP_WRAP                   0x00000511UL
#define CKM_KIP_MAC                    0x00000512UL

#define CKM_CAMELLIA_KEY_GEN           0x00000550UL
#define CKM_CAMELLIA_ECB               0x00000551UL
#define CKM_CAMELLIA_CBC               0x00000552UL
#define CKM_CAMELLIA_MAC               0x00000553UL
#define CKM_CAMELLIA_MAC_GENERAL       0x00000554UL
#define CKM_CAMELLIA_CBC_PAD           0x00000555UL
#define CKM_CAMELLIA_ECB_ENCRYPT_DATA  0x00000556UL
#define CKM_CAMELLIA_CBC_ENCRYPT_DATA  0x00000557UL
#define CKM_CAMELLIA_CTR               0x00000558UL

#define CKM_ARIA_KEY_GEN               0x00000560UL
#define CKM_ARIA_ECB                   0x00000561UL
#define CKM_ARIA_CBC                   0x00000562UL
#define CKM_ARIA_MAC                   0x00000563UL
#define CKM_ARIA_MAC_GENERAL           0x00000564UL
#define CKM_ARIA_CBC_PAD               0x00000565UL
#define CKM_ARIA_ECB_ENCRYPT_DATA      0x00000566UL
#define CKM_ARIA_CBC_ENCRYPT_DATA      0x00000567UL

#define CKM_SEED_KEY_GEN               0x00000650UL
#define CKM_SEED_ECB                   0x00000651UL
#define CKM_SEED_CBC                   0x00000652UL
#define CKM_SEED_MAC                   0x00000653UL
#define CKM_SEED_MAC_GENERAL           0x00000654UL
#define CKM_SEED_CBC_PAD               0x00000655UL
#define CKM_SEED_ECB_ENCRYPT_DATA      0x00000656UL
#define CKM_SEED_CBC_ENCRYPT_DATA      0x00000657UL

#define CKM_SKIPJACK_KEY_GEN           0x00001000UL
#define CKM_SKIPJACK_ECB64             0x00001001UL
#define CKM_SKIPJACK_CBC64             0x00001002UL
#define CKM_SKIPJACK_OFB64             0x00001003UL
#define CKM_SKIPJACK_CFB64             0x00001004UL
#define CKM_SKIPJACK_CFB32             0x00001005UL
#define CKM_SKIPJACK_CFB16             0x00001006UL
#define CKM_SKIPJACK_CFB8              0x00001007UL
#define CKM_SKIPJACK_WRAP              0x00001008UL
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009UL
#define CKM_SKIPJACK_RELAYX            0x0000100aUL
#define CKM_KEA_KEY_PAIR_GEN           0x00001010UL
#define CKM_KEA_KEY_DERIVE             0x00001011UL
#define CKM_KEA_DERIVE                 0x00001012UL
#define CKM_FORTEZZA_TIMESTAMP         0x00001020UL
#define CKM_BATON_KEY_GEN              0x00001030UL
#define CKM_BATON_ECB128               0x00001031UL
#define CKM_BATON_ECB96                0x00001032UL
#define CKM_BATON_CBC128               0x00001033UL
#define CKM_BATON_COUNTER              0x00001034UL
#define CKM_BATON_SHUFFLE              0x00001035UL
#define CKM_BATON_WRAP                 0x00001036UL

#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040UL /* Deprecated */
#define CKM_EC_KEY_PAIR_GEN            0x00001040UL

#define CKM_ECDSA                      0x00001041UL
#define CKM_ECDSA_SHA1                 0x00001042UL
#define CKM_ECDSA_SHA224               0x00001043UL
#define CKM_ECDSA_SHA256               0x00001044UL
#define CKM_ECDSA_SHA384               0x00001045UL
#define CKM_ECDSA_SHA512               0x00001046UL
#define CKM_EC_KEY_PAIR_GEN_W_EXTRA_BITS 0x0000140bUL

#define CKM_ECDH1_DERIVE               0x00001050UL
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051UL
#define CKM_ECMQV_DERIVE               0x00001052UL

#define CKM_ECDH_AES_KEY_WRAP          0x00001053UL
#define CKM_RSA_AES_KEY_WRAP           0x00001054UL

#define CKM_JUNIPER_KEY_GEN            0x00001060UL
#define CKM_JUNIPER_ECB128             0x00001061UL
#define CKM_JUNIPER_CBC128             0x00001062UL
#define CKM_JUNIPER_COUNTER            0x00001063UL
#define CKM_JUNIPER_SHUFFLE            0x00001064UL
#define CKM_JUNIPER_WRAP               0x00001065UL
#define CKM_FASTHASH                   0x00001070UL

#define CKM_AES_XTS                    0x00001071UL
#define CKM_AES_XTS_KEY_GEN            0x00001072UL
#define CKM_AES_KEY_GEN                0x00001080UL
#define CKM_AES_ECB                    0x00001081UL
#define CKM_AES_CBC                    0x00001082UL
#define CKM_AES_MAC                    0x00001083UL
#define CKM_AES_MAC_GENERAL            0x00001084UL
#define CKM_AES_CBC_PAD                0x00001085UL
#define CKM_AES_CTR                    0x00001086UL
#define CKM_AES_GCM                    0x00001087UL
#define CKM_AES_CCM                    0x00001088UL
#define CKM_AES_CTS                    0x00001089UL
#define CKM_AES_CMAC                   0x0000108aUL
#define CKM_AES_CMAC_GENERAL           0x0000108bUL

#define CKM_AES_XCBC_MAC               0x0000108cUL
#define CKM_AES_XCBC_MAC_96            0x0000108dUL
#define CKM_AES_GMAC                   0x0000108eUL

#define CKM_BLOWFISH_KEY_GEN           0x00001090UL
#define CKM_BLOWFISH_CBC               0x00001091UL
#define CKM_TWOFISH_KEY_GEN            0x00001092UL
#define CKM_TWOFISH_CBC                0x00001093UL
#define CKM_BLOWFISH_CBC_PAD           0x00001094UL
#define CKM_TWOFISH_CBC_PAD            0x00001095UL

#define CKM_DES_ECB_ENCRYPT_DATA       0x00001100UL
#define CKM_DES_CBC_ENCRYPT_DATA       0x00001101UL
#define CKM_DES3_ECB_ENCRYPT_DATA      0x00001102UL
#define CKM_DES3_CBC_ENCRYPT_DATA      0x00001103UL
#define CKM_AES_ECB_ENCRYPT_DATA       0x00001104UL
#define CKM_AES_CBC_ENCRYPT_DATA       0x00001105UL

#define CKM_GOSTR3410_KEY_PAIR_GEN     0x00001200UL
#define CKM_GOSTR3410                  0x00001201UL
#define CKM_GOSTR3410_WITH_GOSTR3411   0x00001202UL
#define CKM_GOSTR3410_KEY_WRAP         0x00001203UL
#define CKM_GOSTR3410_DERIVE           0x00001204UL
#define CKM_GOSTR3411                  0x00001210UL
#define CKM_GOSTR3411_HMAC             0x00001211UL
#define CKM_GOST28147_KEY_GEN          0x00001220UL
#define CKM_GOST28147_ECB              0x00001221UL
#define CKM_GOST28147                  0x00001222UL
#define CKM_GOST28147_MAC              0x00001223UL
#define CKM_GOST28147_KEY_WRAP         0x00001224UL
#define CKM_CHACHA20_KEY_GEN           0x00001225UL
#define CKM_CHACHA20                   0x00001226UL
#define CKM_POLY1305_KEY_GEN           0x00001227UL
#define CKM_POLY1305                   0x00001228UL
#define CKM_DSA_PARAMETER_GEN          0x00002000UL
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001UL
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002UL
#define CKM_DSA_PROBABILISTIC_PARAMETER_GEN 0x00002003UL
#define CKM_DSA_PROBABLISTIC_PARAMETER_GEN CKM_DSA_PROBABILISTIC_PARAMETER_GEN
#define CKM_DSA_SHAWE_TAYLOR_PARAMETER_GEN    0x00002004UL
#define CKM_DSA_FIPS_G_GEN               0x00002005UL

#define CKM_AES_OFB                    0x00002104UL
#define CKM_AES_CFB64                  0x00002105UL
#define CKM_AES_CFB8                   0x00002106UL
#define CKM_AES_CFB128                 0x00002107UL

#define CKM_AES_CFB1                   0x00002108UL
#define CKM_AES_KEY_WRAP               0x00002109UL     /* WAS: 0x00001090 */
#define CKM_AES_KEY_WRAP_PAD           0x0000210AUL     /* WAS: 0x00001091 */
#define CKM_AES_KEY_WRAP_KWP           0x0000210BUL
#define CKM_AES_KEY_WRAP_PKCS7         0x0000210CUL

#define CKM_RSA_PKCS_TPM_1_1           0x00004001UL
#define CKM_RSA_PKCS_OAEP_TPM_1_1      0x00004002UL

#define CKM_SHA_1_KEY_GEN              0x00004003UL
#define CKM_SHA224_KEY_GEN             0x00004004UL
#define CKM_SHA256_KEY_GEN             0x00004005UL
#define CKM_SHA384_KEY_GEN             0x00004006UL
#define CKM_SHA512_KEY_GEN             0x00004007UL
#define CKM_SHA512_224_KEY_GEN         0x00004008UL
#define CKM_SHA512_256_KEY_GEN         0x00004009UL
#define CKM_SHA512_T_KEY_GEN           0x0000400aUL
#define CKM_NULL                       0x0000400bUL
#define CKM_BLAKE2B_160                0x0000400cUL
#define CKM_BLAKE2B_160_HMAC           0x0000400dUL
#define CKM_BLAKE2B_160_HMAC_GENERAL   0x0000400eUL
#define CKM_BLAKE2B_160_KEY_DERIVE     0x0000400fUL
#define CKM_BLAKE2B_160_KEY_GEN        0x00004010UL
#define CKM_BLAKE2B_256                0x00004011UL
#define CKM_BLAKE2B_256_HMAC           0x00004012UL
#define CKM_BLAKE2B_256_HMAC_GENERAL   0x00004013UL
#define CKM_BLAKE2B_256_KEY_DERIVE     0x00004014UL
#define CKM_BLAKE2B_256_KEY_GEN        0x00004015UL
#define CKM_BLAKE2B_384                0x00004016UL
#define CKM_BLAKE2B_384_HMAC           0x00004017UL
#define CKM_BLAKE2B_384_HMAC_GENERAL   0x00004018UL
#define CKM_BLAKE2B_384_KEY_DERIVE     0x00004019UL
#define CKM_BLAKE2B_384_KEY_GEN        0x0000401aUL
#define CKM_BLAKE2B_512                0x0000401bUL
#define CKM_BLAKE2B_512_HMAC           0x0000401cUL
#define CKM_BLAKE2B_512_HMAC_GENERAL   0x0000401dUL
#define CKM_BLAKE2B_512_KEY_DERIVE     0x0000401eUL
#define CKM_BLAKE2B_512_KEY_GEN        0x0000401fUL
#define CKM_SALSA20                    0x00004020UL
#define CKM_CHACHA20_POLY1305          0x00004021UL
#define CKM_SALSA20_POLY1305           0x00004022UL
#define CKM_X3DH_INITIALIZE            0x00004023UL
#define CKM_X3DH_RESPOND               0x00004024UL
#define CKM_X2RATCHET_INITIALIZE       0x00004025UL
#define CKM_X2RATCHET_RESPOND          0x00004026UL
#define CKM_X2RATCHET_ENCRYPT          0x00004027UL
#define CKM_X2RATCHET_DECRYPT          0x00004028UL
#define CKM_XEDDSA                     0x00004029UL
#define CKM_HKDF_DERIVE                0x0000402aUL
#define CKM_HKDF_DATA                  0x0000402bUL
#define CKM_HKDF_KEY_GEN               0x0000402cUL
#define CKM_SALSA20_KEY_GEN            0x0000402dUL

#define CKM_ECDSA_SHA3_224             0x00001047UL
#define CKM_ECDSA_SHA3_256             0x00001048UL
#define CKM_ECDSA_SHA3_384             0x00001049UL
#define CKM_ECDSA_SHA3_512             0x0000104aUL
#define CKM_EC_EDWARDS_KEY_PAIR_GEN    0x00001055UL
#define CKM_EC_MONTGOMERY_KEY_PAIR_GEN 0x00001056UL
#define CKM_EDDSA                      0x00001057UL
#define CKM_SP800_108_COUNTER_KDF      0x000003acUL
#define CKM_SP800_108_FEEDBACK_KDF     0x000003adUL
#define CKM_SP800_108_DOUBLE_PIPELINE_KDF 0x000003aeUL

#define CKM_IKE2_PRF_PLUS_DERIVE       0x0000402eUL
#define CKM_IKE_PRF_DERIVE             0x0000402fUL
#define CKM_IKE1_PRF_DERIVE            0x00004030UL
#define CKM_IKE1_EXTENDED_DERIVE       0x00004031UL
#define CKM_HSS_KEY_PAIR_GEN           0x00004032UL
#define CKM_HSS                        0x00004033UL


#define CKM_VENDOR_DEFINED             0x80000000UL

typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;


/* CK_MECHANISM is a structure that specifies a particular
 * mechanism
 */
typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR       pParameter;
  CK_ULONG          ulParameterLen;  /* in bytes */
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;


/* CK_MECHANISM_INFO provides information about a particular
 * mechanism
 */
typedef struct CK_MECHANISM_INFO {
    CK_ULONG    ulMinKeySize;
    CK_ULONG    ulMaxKeySize;
    CK_FLAGS    flags;
} CK_MECHANISM_INFO;

/* The flags are defined as follows:
 *      Bit Flag               Mask          Meaning */
#define CKF_HW                 0x00000001UL  /* performed by HW */

/* Specify whether or not a mechanism can be used for a particular task */
#define CKF_MESSAGE_ENCRYPT    0x00000002UL
#define CKF_MESSAGE_DECRYPT    0x00000004UL
#define CKF_MESSAGE_SIGN       0x00000008UL
#define CKF_MESSAGE_VERIFY     0x00000010UL
#define CKF_MULTI_MESSAGE      0x00000020UL
#define CKF_MULTI_MESSGE       CKF_MULTI_MESSAGE
#define CKF_FIND_OBJECTS       0x00000040UL

#define CKF_ENCRYPT            0x00000100UL
#define CKF_DECRYPT            0x00000200UL
#define CKF_DIGEST             0x00000400UL
#define CKF_SIGN               0x00000800UL
#define CKF_SIGN_RECOVER       0x00001000UL
#define CKF_VERIFY             0x00002000UL
#define CKF_VERIFY_RECOVER     0x00004000UL
#define CKF_GENERATE           0x00008000UL
#define CKF_GENERATE_KEY_PAIR  0x00010000UL
#define CKF_WRAP               0x00020000UL
#define CKF_UNWRAP             0x00040000UL
#define CKF_DERIVE             0x00080000UL

/* Describe a token's EC capabilities not available in mechanism
 * information.
 */
#define CKF_EC_F_P             0x00100000UL
#define CKF_EC_F_2M            0x00200000UL
#define CKF_EC_ECPARAMETERS    0x00400000UL
#define CKF_EC_OID             0x00800000UL
#define CKF_EC_NAMEDCURVE      CKF_EC_OID   /* deprecated since PKCS#11 3.00 */
#define CKF_EC_UNCOMPRESS      0x01000000UL
#define CKF_EC_COMPRESS        0x02000000UL
#define CKF_EC_CURVENAME       0x04000000UL

#define CKF_EXTENSION          0x80000000UL

typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;

/* CK_RV is a value that identifies the return value of a
 * Cryptoki function
 */
typedef CK_ULONG          CK_RV;

#define CKR_OK                                0x00000000UL
#define CKR_CANCEL                            0x00000001UL
#define CKR_HOST_MEMORY                       0x00000002UL
#define CKR_SLOT_ID_INVALID                   0x00000003UL

#define CKR_GENERAL_ERROR                     0x00000005UL
#define CKR_FUNCTION_FAILED                   0x00000006UL

#define CKR_ARGUMENTS_BAD                     0x00000007UL
#define CKR_NO_EVENT                          0x00000008UL
#define CKR_NEED_TO_CREATE_THREADS            0x00000009UL
#define CKR_CANT_LOCK                         0x0000000AUL

#define CKR_ATTRIBUTE_READ_ONLY               0x00000010UL
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011UL
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012UL
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013UL

#define CKR_ACTION_PROHIBITED                 0x0000001BUL

#define CKR_DATA_INVALID                      0x00000020UL
#define CKR_DATA_LEN_RANGE                    0x00000021UL
#define CKR_DEVICE_ERROR                      0x00000030UL
#define CKR_DEVICE_MEMORY                     0x00000031UL
#define CKR_DEVICE_REMOVED                    0x00000032UL
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040UL
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041UL
#define CKR_AEAD_DECRYPT_FAILED               0x00000042UL
#define CKR_FUNCTION_CANCELED                 0x00000050UL
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051UL

#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054UL

#define CKR_KEY_HANDLE_INVALID                0x00000060UL

#define CKR_KEY_SIZE_RANGE                    0x00000062UL
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063UL

#define CKR_KEY_NOT_NEEDED                    0x00000064UL
#define CKR_KEY_CHANGED                       0x00000065UL
#define CKR_KEY_NEEDED                        0x00000066UL
#define CKR_KEY_INDIGESTIBLE                  0x00000067UL
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068UL
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069UL
#define CKR_KEY_UNEXTRACTABLE                 0x0000006AUL

#define CKR_MECHANISM_INVALID                 0x00000070UL
#define CKR_MECHANISM_PARAM_INVALID           0x00000071UL

#define CKR_OBJECT_HANDLE_INVALID             0x00000082UL
#define CKR_OPERATION_ACTIVE                  0x00000090UL
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091UL
#define CKR_PIN_INCORRECT                     0x000000A0UL
#define CKR_PIN_INVALID                       0x000000A1UL
#define CKR_PIN_LEN_RANGE                     0x000000A2UL

#define CKR_PIN_EXPIRED                       0x000000A3UL
#define CKR_PIN_LOCKED                        0x000000A4UL

#define CKR_SESSION_CLOSED                    0x000000B0UL
#define CKR_SESSION_COUNT                     0x000000B1UL
#define CKR_SESSION_HANDLE_INVALID            0x000000B3UL
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4UL
#define CKR_SESSION_READ_ONLY                 0x000000B5UL
#define CKR_SESSION_EXISTS                    0x000000B6UL

#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7UL
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8UL

#define CKR_SIGNATURE_INVALID                 0x000000C0UL
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1UL
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0UL
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1UL
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0UL
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1UL
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2UL
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0UL
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1UL
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2UL
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100UL
#define CKR_USER_NOT_LOGGED_IN                0x00000101UL
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102UL
#define CKR_USER_TYPE_INVALID                 0x00000103UL

#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104UL
#define CKR_USER_TOO_MANY_TYPES               0x00000105UL

#define CKR_WRAPPED_KEY_INVALID               0x00000110UL
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112UL
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113UL
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114UL
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115UL
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120UL

#define CKR_RANDOM_NO_RNG                     0x00000121UL

#define CKR_DOMAIN_PARAMS_INVALID             0x00000130UL

#define CKR_CURVE_NOT_SUPPORTED               0x00000140UL

#define CKR_BUFFER_TOO_SMALL                  0x00000150UL
#define CKR_SAVED_STATE_INVALID               0x00000160UL
#define CKR_INFORMATION_SENSITIVE             0x00000170UL
#define CKR_STATE_UNSAVEABLE                  0x00000180UL

#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190UL
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191UL
#define CKR_MUTEX_BAD                         0x000001A0UL
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1UL

#define CKR_NEW_PIN_MODE                      0x000001B0UL
#define CKR_NEXT_OTP                          0x000001B1UL

#define CKR_EXCEEDED_MAX_ITERATIONS           0x000001B5UL
#define CKR_FIPS_SELF_TEST_FAILED             0x000001B6UL
#define CKR_LIBRARY_LOAD_FAILED               0x000001B7UL
#define CKR_PIN_TOO_WEAK                      0x000001B8UL
#define CKR_PUBLIC_KEY_INVALID                0x000001B9UL

#define CKR_FUNCTION_REJECTED                 0x00000200UL
#define CKR_TOKEN_RESOURCE_EXCEEDED           0x00000201UL
#define CKR_OPERATION_CANCEL_FAILED           0x00000202UL
#define CKR_KEY_EXHAUSTED                     0x00000203UL

#define CKR_VENDOR_DEFINED                    0x80000000UL


/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);


/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions
 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef struct CK_FUNCTION_LIST_3_0 CK_FUNCTION_LIST_3_0;

typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_3_0 CK_PTR CK_FUNCTION_LIST_3_0_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;
typedef CK_FUNCTION_LIST_3_0_PTR CK_PTR CK_FUNCTION_LIST_3_0_PTR_PTR;

typedef struct CK_INTERFACE {
      CK_CHAR     *pInterfaceName;
      CK_VOID_PTR pFunctionList;
      CK_FLAGS    flags;
} CK_INTERFACE;

typedef CK_INTERFACE CK_PTR CK_INTERFACE_PTR;
typedef CK_INTERFACE_PTR CK_PTR CK_INTERFACE_PTR_PTR;

#define CKF_END_OF_MESSAGE   0x00000001UL


/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);


/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex
 */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);

/* Get functionlist flags */
#define CKF_INTERFACE_FORK_SAFE  0x00000001UL

/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize
 */
typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX LockMutex;
  CK_UNLOCKMUTEX UnlockMutex;
  CK_FLAGS flags;
  CK_VOID_PTR pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001UL
#define CKF_OS_LOCKING_OK                  0x00000002UL

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;



/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
#define CKF_DONT_BLOCK     1

/* CK_RSA_PKCS_MGF_TYPE  is used to indicate the Message
 * Generation Function (MGF) applied to a message block when
 * formatting a message block for the PKCS #1 OAEP encryption
 * scheme.
 */
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;

typedef CK_RSA_PKCS_MGF_TYPE CK_PTR CK_RSA_PKCS_MGF_TYPE_PTR;

/* The following MGFs are defined */
#define CKG_MGF1_SHA1         0x00000001UL
#define CKG_MGF1_SHA256       0x00000002UL
#define CKG_MGF1_SHA384       0x00000003UL
#define CKG_MGF1_SHA512       0x00000004UL
#define CKG_MGF1_SHA224       0x00000005UL
#define CKG_MGF1_SHA3_224     0x00000006UL
#define CKG_MGF1_SHA3_256     0x00000007UL
#define CKG_MGF1_SHA3_384     0x00000008UL
#define CKG_MGF1_SHA3_512     0x00000009UL


/* CK_RSA_PKCS_OAEP_SOURCE_TYPE  is used to indicate the source
 * of the encoding parameter when formatting a message block
 * for the PKCS #1 OAEP encryption scheme.
 */
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;

typedef CK_RSA_PKCS_OAEP_SOURCE_TYPE CK_PTR CK_RSA_PKCS_OAEP_SOURCE_TYPE_PTR;

/* The following encoding parameter sources are defined */
#define CKZ_DATA_SPECIFIED    0x00000001UL

/* CK_RSA_PKCS_OAEP_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_OAEP mechanism.
 */
typedef struct CK_RSA_PKCS_OAEP_PARAMS {
        CK_MECHANISM_TYPE hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
        CK_VOID_PTR pSourceData;
        CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

/* CK_RSA_PKCS_PSS_PARAMS provides the parameters to the
 * CKM_RSA_PKCS_PSS mechanism(s).
 */
typedef struct CK_RSA_PKCS_PSS_PARAMS {
        CK_MECHANISM_TYPE    hashAlg;
        CK_RSA_PKCS_MGF_TYPE mgf;
        CK_ULONG             sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

typedef CK_ULONG CK_EC_KDF_TYPE;
typedef CK_EC_KDF_TYPE CK_PTR CK_EC_KDF_TYPE_PTR;

/* The following EC Key Derivation Functions are defined */
#define CKD_NULL                 0x00000001UL
#define CKD_SHA1_KDF             0x00000002UL

/* The following X9.42 DH key derivation functions are defined */
#define CKD_SHA1_KDF_ASN1        0x00000003UL
#define CKD_SHA1_KDF_CONCATENATE 0x00000004UL
#define CKD_SHA224_KDF           0x00000005UL
#define CKD_SHA256_KDF           0x00000006UL
#define CKD_SHA384_KDF           0x00000007UL
#define CKD_SHA512_KDF           0x00000008UL
#define CKD_CPDIVERSIFY_KDF      0x00000009UL
#define CKD_SHA3_224_KDF         0x0000000AUL
#define CKD_SHA3_256_KDF         0x0000000BUL
#define CKD_SHA3_384_KDF         0x0000000CUL
#define CKD_SHA3_512_KDF         0x0000000DUL
#define CKD_SHA1_KDF_SP800       0x0000000EUL
#define CKD_SHA224_KDF_SP800     0x0000000FUL
#define CKD_SHA256_KDF_SP800     0x00000010UL
#define CKD_SHA384_KDF_SP800     0x00000011UL
#define CKD_SHA512_KDF_SP800     0x00000012UL
#define CKD_SHA3_224_KDF_SP800   0x00000013UL
#define CKD_SHA3_256_KDF_SP800   0x00000014UL
#define CKD_SHA3_384_KDF_SP800   0x00000015UL
#define CKD_SHA3_512_KDF_SP800   0x00000016UL
#define CKD_BLAKE2B_160_KDF      0x00000017UL
#define CKD_BLAKE2B_256_KDF      0x00000018UL
#define CKD_BLAKE2B_384_KDF      0x00000019UL
#define CKD_BLAKE2B_512_KDF      0x0000001aUL

/* CK_ECDH1_DERIVE_PARAMS provides the parameters to the
 * CKM_ECDH1_DERIVE and CKM_ECDH1_COFACTOR_DERIVE mechanisms,
 * where each party contributes one key pair.
 */
typedef struct CK_ECDH1_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_ECDH1_DERIVE_PARAMS;

typedef CK_ECDH1_DERIVE_PARAMS CK_PTR CK_ECDH1_DERIVE_PARAMS_PTR;

/*
 * CK_ECDH2_DERIVE_PARAMS provides the parameters to the
 * CKM_ECMQV_DERIVE mechanism, where each party contributes two key pairs.
 */
typedef struct CK_ECDH2_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_ECDH2_DERIVE_PARAMS;

typedef CK_ECDH2_DERIVE_PARAMS CK_PTR CK_ECDH2_DERIVE_PARAMS_PTR;

typedef struct CK_ECMQV_DERIVE_PARAMS {
  CK_EC_KDF_TYPE kdf;
  CK_ULONG ulSharedDataLen;
  CK_BYTE_PTR pSharedData;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_ECMQV_DERIVE_PARAMS;

typedef CK_ECMQV_DERIVE_PARAMS CK_PTR CK_ECMQV_DERIVE_PARAMS_PTR;

/* Typedefs and defines for the CKM_X9_42_DH_KEY_PAIR_GEN and the
 * CKM_X9_42_DH_PARAMETER_GEN mechanisms
 */
typedef CK_ULONG CK_X9_42_DH_KDF_TYPE;
typedef CK_X9_42_DH_KDF_TYPE CK_PTR CK_X9_42_DH_KDF_TYPE_PTR;

/* CK_X9_42_DH1_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_DERIVE key derivation mechanism, where each party
 * contributes one key pair
 */
typedef struct CK_X9_42_DH1_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
} CK_X9_42_DH1_DERIVE_PARAMS;

typedef struct CK_X9_42_DH1_DERIVE_PARAMS CK_PTR CK_X9_42_DH1_DERIVE_PARAMS_PTR;

/* CK_X9_42_DH2_DERIVE_PARAMS provides the parameters to the
 * CKM_X9_42_DH_HYBRID_DERIVE and CKM_X9_42_MQV_DERIVE key derivation
 * mechanisms, where each party contributes two key pairs
 */
typedef struct CK_X9_42_DH2_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
} CK_X9_42_DH2_DERIVE_PARAMS;

typedef CK_X9_42_DH2_DERIVE_PARAMS CK_PTR CK_X9_42_DH2_DERIVE_PARAMS_PTR;

typedef struct CK_X9_42_MQV_DERIVE_PARAMS {
  CK_X9_42_DH_KDF_TYPE kdf;
  CK_ULONG ulOtherInfoLen;
  CK_BYTE_PTR pOtherInfo;
  CK_ULONG ulPublicDataLen;
  CK_BYTE_PTR pPublicData;
  CK_ULONG ulPrivateDataLen;
  CK_OBJECT_HANDLE hPrivateData;
  CK_ULONG ulPublicDataLen2;
  CK_BYTE_PTR pPublicData2;
  CK_OBJECT_HANDLE publicKey;
} CK_X9_42_MQV_DERIVE_PARAMS;

typedef CK_X9_42_MQV_DERIVE_PARAMS CK_PTR CK_X9_42_MQV_DERIVE_PARAMS_PTR;

/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism
 */
typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS CK_PTR CK_KEA_DERIVE_PARAMS_PTR;


/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize
 */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS CK_PTR CK_RC2_PARAMS_PTR;


/* CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC
 * mechanism
 */
typedef struct CK_RC2_CBC_PARAMS {
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
  CK_BYTE       iv[8];            /* IV for CBC mode */
} CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS CK_PTR CK_RC2_CBC_PARAMS_PTR;


/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC2_MAC_GENERAL mechanism
 */
typedef struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
  CK_ULONG      ulMacLength;      /* Length of MAC in bytes */
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC2_MAC_GENERAL_PARAMS_PTR;


/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
 * CKM_RC5_MAC mechanisms
 */
typedef struct CK_RC5_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS CK_PTR CK_RC5_PARAMS_PTR;


/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
 * mechanism
 */
typedef struct CK_RC5_CBC_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
  CK_BYTE_PTR   pIv;         /* pointer to IV */
  CK_ULONG      ulIvLen;     /* length of IV in bytes */
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS CK_PTR CK_RC5_CBC_PARAMS_PTR;


/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC5_MAC_GENERAL mechanism
 */
typedef struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG      ulWordsize;   /* wordsize in bits */
  CK_ULONG      ulRounds;     /* number of rounds */
  CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC5_MAC_GENERAL_PARAMS_PTR;

/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
 * ciphers' MAC_GENERAL mechanisms.  Its value is the length of
 * the MAC
 */
typedef CK_ULONG          CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS CK_PTR CK_MAC_GENERAL_PARAMS_PTR;

typedef struct CK_DES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[8];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_DES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_DES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_DES_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
  CK_BYTE      iv[16];
  CK_BYTE_PTR  pData;
  CK_ULONG     length;
} CK_AES_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS CK_PTR CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;

/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism
 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS CK_PTR \
  CK_SKIPJACK_PRIVATE_WRAP_PARAMS_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism
 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS CK_PTR \
  CK_SKIPJACK_RELAYX_PARAMS_PTR;


typedef struct CK_PBE_PARAMS {
  CK_BYTE_PTR      pInitVector;
  CK_UTF8CHAR_PTR  pPassword;
  CK_ULONG         ulPasswordLen;
  CK_BYTE_PTR      pSalt;
  CK_ULONG         ulSaltLen;
  CK_ULONG         ulIteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS CK_PTR CK_PBE_PARAMS_PTR;


/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
 * CKM_KEY_WRAP_SET_OAEP mechanism
 */
typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE       bBC;     /* block contents byte */
  CK_BYTE_PTR   pX;      /* extra data */
  CK_ULONG      ulXLen;  /* length of extra data in bytes */
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS CK_PTR CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;

typedef struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR  pClientRandom;
  CK_ULONG     ulClientRandomLen;
  CK_BYTE_PTR  pServerRandom;
  CK_ULONG     ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;


typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS CK_PTR \
  CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR      pIVClient;
  CK_BYTE_PTR      pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT CK_PTR CK_SSL3_KEY_MAT_OUT_PTR;


typedef struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_BBOOL                bIsExport;
  CK_SSL3_RANDOM_DATA     RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS CK_PTR CK_SSL3_KEY_MAT_PARAMS_PTR;

typedef struct CK_TLS_PRF_PARAMS {
  CK_BYTE_PTR  pSeed;
  CK_ULONG     ulSeedLen;
  CK_BYTE_PTR  pLabel;
  CK_ULONG     ulLabelLen;
  CK_BYTE_PTR  pOutput;
  CK_ULONG_PTR pulOutputLen;
} CK_TLS_PRF_PARAMS;

typedef CK_TLS_PRF_PARAMS CK_PTR CK_TLS_PRF_PARAMS_PTR;

typedef struct CK_WTLS_RANDOM_DATA {
  CK_BYTE_PTR pClientRandom;
  CK_ULONG    ulClientRandomLen;
  CK_BYTE_PTR pServerRandom;
  CK_ULONG    ulServerRandomLen;
} CK_WTLS_RANDOM_DATA;

typedef CK_WTLS_RANDOM_DATA CK_PTR CK_WTLS_RANDOM_DATA_PTR;

typedef struct CK_WTLS_MASTER_KEY_DERIVE_PARAMS {
  CK_MECHANISM_TYPE   DigestMechanism;
  CK_WTLS_RANDOM_DATA RandomInfo;
  CK_BYTE_PTR         pVersion;
} CK_WTLS_MASTER_KEY_DERIVE_PARAMS;

typedef CK_WTLS_MASTER_KEY_DERIVE_PARAMS CK_PTR \
  CK_WTLS_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_WTLS_PRF_PARAMS {
  CK_MECHANISM_TYPE DigestMechanism;
  CK_BYTE_PTR       pSeed;
  CK_ULONG          ulSeedLen;
  CK_BYTE_PTR       pLabel;
  CK_ULONG          ulLabelLen;
  CK_BYTE_PTR       pOutput;
  CK_ULONG_PTR      pulOutputLen;
} CK_WTLS_PRF_PARAMS;

typedef CK_WTLS_PRF_PARAMS CK_PTR CK_WTLS_PRF_PARAMS_PTR;

typedef struct CK_WTLS_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hMacSecret;
  CK_OBJECT_HANDLE hKey;
  CK_BYTE_PTR      pIV;
} CK_WTLS_KEY_MAT_OUT;

typedef CK_WTLS_KEY_MAT_OUT CK_PTR CK_WTLS_KEY_MAT_OUT_PTR;

typedef struct CK_WTLS_KEY_MAT_PARAMS {
  CK_MECHANISM_TYPE       DigestMechanism;
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_ULONG                ulSequenceNumber;
  CK_BBOOL                bIsExport;
  CK_WTLS_RANDOM_DATA     RandomInfo;
  CK_WTLS_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_WTLS_KEY_MAT_PARAMS;

typedef CK_WTLS_KEY_MAT_PARAMS CK_PTR CK_WTLS_KEY_MAT_PARAMS_PTR;

typedef struct CK_CMS_SIG_PARAMS {
  CK_OBJECT_HANDLE      certificateHandle;
  CK_MECHANISM_PTR      pSigningMechanism;
  CK_MECHANISM_PTR      pDigestMechanism;
  CK_UTF8CHAR_PTR       pContentType;
  CK_BYTE_PTR           pRequestedAttributes;
  CK_ULONG              ulRequestedAttributesLen;
  CK_BYTE_PTR           pRequiredAttributes;
  CK_ULONG              ulRequiredAttributesLen;
} CK_CMS_SIG_PARAMS;

typedef CK_CMS_SIG_PARAMS CK_PTR CK_CMS_SIG_PARAMS_PTR;

typedef struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG    ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA CK_PTR \
  CK_KEY_DERIVATION_STRING_DATA_PTR;


/* The CK_EXTRACT_PARAMS is used for the
 * CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
 * of the base key should be used as the first bit of the
 * derived key
 */
typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS CK_PTR CK_EXTRACT_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE is used to
 * indicate the Pseudo-Random Function (PRF) used to generate
 * key bits using PKCS #5 PBKDF2.
 */
typedef CK_ULONG CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE;

typedef CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE CK_PTR \
                        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE_PTR;

#define CKP_PKCS5_PBKD2_HMAC_SHA1          0x00000001UL
#define CKP_PKCS5_PBKD2_HMAC_GOSTR3411     0x00000002UL
#define CKP_PKCS5_PBKD2_HMAC_SHA224        0x00000003UL
#define CKP_PKCS5_PBKD2_HMAC_SHA256        0x00000004UL
#define CKP_PKCS5_PBKD2_HMAC_SHA384        0x00000005UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512        0x00000006UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512_224    0x00000007UL
#define CKP_PKCS5_PBKD2_HMAC_SHA512_256    0x00000008UL

/* CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE is used to indicate the
 * source of the salt value when deriving a key using PKCS #5
 * PBKDF2.
 */
typedef CK_ULONG CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE;

typedef CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE CK_PTR \
                        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE_PTR;

/* The following salt value sources are defined in PKCS #5 v2.0. */
#define CKZ_SALT_SPECIFIED        0x00000001UL

/* CK_PKCS5_PBKD2_PARAMS is a structure that provides the
 * parameters to the CKM_PKCS5_PBKD2 mechanism.
 */
typedef struct CK_PKCS5_PBKD2_PARAMS {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE           saltSource;
        CK_VOID_PTR                                pSaltSourceData;
        CK_ULONG                                   ulSaltSourceDataLen;
        CK_ULONG                                   iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR                                pPrfData;
        CK_ULONG                                   ulPrfDataLen;
        CK_UTF8CHAR_PTR                            pPassword;
        CK_ULONG_PTR                               ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS;

typedef CK_PKCS5_PBKD2_PARAMS CK_PTR CK_PKCS5_PBKD2_PARAMS_PTR;

/* CK_PKCS5_PBKD2_PARAMS2 is a corrected version of the CK_PKCS5_PBKD2_PARAMS
 * structure that provides the parameters to the CKM_PKCS5_PBKD2 mechanism
 * noting that the ulPasswordLen field is a CK_ULONG and not a CK_ULONG_PTR.
 */
typedef struct CK_PKCS5_PBKD2_PARAMS2 {
        CK_PKCS5_PBKDF2_SALT_SOURCE_TYPE saltSource;
        CK_VOID_PTR pSaltSourceData;
        CK_ULONG ulSaltSourceDataLen;
        CK_ULONG iterations;
        CK_PKCS5_PBKD2_PSEUDO_RANDOM_FUNCTION_TYPE prf;
        CK_VOID_PTR pPrfData;
        CK_ULONG ulPrfDataLen;
        CK_UTF8CHAR_PTR pPassword;
        CK_ULONG ulPasswordLen;
} CK_PKCS5_PBKD2_PARAMS2;

typedef CK_PKCS5_PBKD2_PARAMS2 CK_PTR CK_PKCS5_PBKD2_PARAMS2_PTR;

typedef CK_ULONG CK_OTP_PARAM_TYPE;
typedef CK_OTP_PARAM_TYPE CK_PARAM_TYPE; /* backward compatibility */

typedef struct CK_OTP_PARAM {
    CK_OTP_PARAM_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_OTP_PARAM;

typedef CK_OTP_PARAM CK_PTR CK_OTP_PARAM_PTR;

typedef struct CK_OTP_PARAMS {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_PARAMS;

typedef CK_OTP_PARAMS CK_PTR CK_OTP_PARAMS_PTR;

typedef struct CK_OTP_SIGNATURE_INFO {
    CK_OTP_PARAM_PTR pParams;
    CK_ULONG ulCount;
} CK_OTP_SIGNATURE_INFO;

typedef CK_OTP_SIGNATURE_INFO CK_PTR CK_OTP_SIGNATURE_INFO_PTR;

#define CK_OTP_VALUE          0UL
#define CK_OTP_PIN            1UL
#define CK_OTP_CHALLENGE      2UL
#define CK_OTP_TIME           3UL
#define CK_OTP_COUNTER        4UL
#define CK_OTP_FLAGS          5UL
#define CK_OTP_OUTPUT_LENGTH  6UL
#define CK_OTP_OUTPUT_FORMAT  7UL

#define CKF_NEXT_OTP          0x00000001UL
#define CKF_EXCLUDE_TIME      0x00000002UL
#define CKF_EXCLUDE_COUNTER   0x00000004UL
#define CKF_EXCLUDE_CHALLENGE 0x00000008UL
#define CKF_EXCLUDE_PIN       0x00000010UL
#define CKF_USER_FRIENDLY_OTP 0x00000020UL

typedef struct CK_KIP_PARAMS {
    CK_MECHANISM_PTR  pMechanism;
    CK_OBJECT_HANDLE  hKey;
    CK_BYTE_PTR       pSeed;
    CK_ULONG          ulSeedLen;
} CK_KIP_PARAMS;

typedef CK_KIP_PARAMS CK_PTR CK_KIP_PARAMS_PTR;

typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

typedef struct CK_GCM_PARAMS {
    CK_BYTE_PTR       pIv;
    CK_ULONG          ulIvLen;
    CK_ULONG          ulIvBits;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulTagBits;
} CK_GCM_PARAMS;

typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;

typedef CK_ULONG CK_GENERATOR_FUNCTION;
#define CKG_NO_GENERATE      0x00000000UL
#define CKG_GENERATE         0x00000001UL
#define CKG_GENERATE_COUNTER 0x00000002UL
#define CKG_GENERATE_RANDOM  0x00000003UL
#define CKG_GENERATE_COUNTER_XOR 0x00000004UL

typedef struct CK_GCM_MESSAGE_PARAMS {
    CK_BYTE_PTR       pIv;
    CK_ULONG          ulIvLen;
    CK_ULONG          ulIvFixedBits;
    CK_GENERATOR_FUNCTION ivGenerator;
    CK_BYTE_PTR       pTag;
    CK_ULONG          ulTagBits;
} CK_GCM_MESSAGE_PARAMS;

typedef CK_GCM_MESSAGE_PARAMS CK_PTR CK_GCM_MESSAGE_PARAMS_PTR;

typedef struct CK_CCM_PARAMS {
    CK_ULONG          ulDataLen;
    CK_BYTE_PTR       pNonce;
    CK_ULONG          ulNonceLen;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulMACLen;
} CK_CCM_PARAMS;

typedef CK_CCM_PARAMS CK_PTR CK_CCM_PARAMS_PTR;

typedef struct CK_CCM_MESSAGE_PARAMS {
    CK_ULONG          ulDataLen; /*plaintext or ciphertext*/
    CK_BYTE_PTR       pNonce;
    CK_ULONG          ulNonceLen;
    CK_ULONG          ulNonceFixedBits;
    CK_GENERATOR_FUNCTION nonceGenerator;
    CK_BYTE_PTR       pMAC;
    CK_ULONG          ulMACLen;
} CK_CCM_MESSAGE_PARAMS;

typedef CK_CCM_MESSAGE_PARAMS CK_PTR CK_CCM_MESSAGE_PARAMS_PTR;

/* Deprecated. Use CK_GCM_PARAMS */
typedef struct CK_AES_GCM_PARAMS {
  CK_BYTE_PTR pIv;
  CK_ULONG ulIvLen;
  CK_ULONG ulIvBits;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
  CK_ULONG ulTagBits;
} CK_AES_GCM_PARAMS;

typedef CK_AES_GCM_PARAMS CK_PTR CK_AES_GCM_PARAMS_PTR;

/* Deprecated. Use CK_CCM_PARAMS */
typedef struct CK_AES_CCM_PARAMS {
    CK_ULONG          ulDataLen;
    CK_BYTE_PTR       pNonce;
    CK_ULONG          ulNonceLen;
    CK_BYTE_PTR       pAAD;
    CK_ULONG          ulAADLen;
    CK_ULONG          ulMACLen;
} CK_AES_CCM_PARAMS;

typedef CK_AES_CCM_PARAMS CK_PTR CK_AES_CCM_PARAMS_PTR;

typedef struct CK_CAMELLIA_CTR_PARAMS {
    CK_ULONG          ulCounterBits;
    CK_BYTE           cb[16];
} CK_CAMELLIA_CTR_PARAMS;

typedef CK_CAMELLIA_CTR_PARAMS CK_PTR CK_CAMELLIA_CTR_PARAMS_PTR;

typedef struct CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE           iv[16];
    CK_BYTE_PTR       pData;
    CK_ULONG          length;
} CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR \
                                CK_CAMELLIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_ARIA_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE           iv[16];
    CK_BYTE_PTR       pData;
    CK_ULONG          length;
} CK_ARIA_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_ARIA_CBC_ENCRYPT_DATA_PARAMS CK_PTR \
                                CK_ARIA_CBC_ENCRYPT_DATA_PARAMS_PTR;

typedef struct CK_DSA_PARAMETER_GEN_PARAM {
    CK_MECHANISM_TYPE  hash;
    CK_BYTE_PTR        pSeed;
    CK_ULONG           ulSeedLen;
    CK_ULONG           ulIndex;
} CK_DSA_PARAMETER_GEN_PARAM;

typedef CK_DSA_PARAMETER_GEN_PARAM CK_PTR CK_DSA_PARAMETER_GEN_PARAM_PTR;

typedef struct CK_ECDH_AES_KEY_WRAP_PARAMS {
    CK_ULONG           ulAESKeyBits;
    CK_EC_KDF_TYPE     kdf;
    CK_ULONG           ulSharedDataLen;
    CK_BYTE_PTR        pSharedData;
} CK_ECDH_AES_KEY_WRAP_PARAMS;

typedef CK_ECDH_AES_KEY_WRAP_PARAMS CK_PTR CK_ECDH_AES_KEY_WRAP_PARAMS_PTR;

typedef CK_ULONG CK_JAVA_MIDP_SECURITY_DOMAIN;

typedef CK_ULONG CK_CERTIFICATE_CATEGORY;

typedef struct CK_RSA_AES_KEY_WRAP_PARAMS {
    CK_ULONG                      ulAESKeyBits;
    CK_RSA_PKCS_OAEP_PARAMS_PTR   pOAEPParams;
} CK_RSA_AES_KEY_WRAP_PARAMS;

typedef CK_RSA_AES_KEY_WRAP_PARAMS CK_PTR CK_RSA_AES_KEY_WRAP_PARAMS_PTR;

typedef struct CK_TLS12_MASTER_KEY_DERIVE_PARAMS {
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_VERSION_PTR            pVersion;
    CK_MECHANISM_TYPE         prfHashMechanism;
} CK_TLS12_MASTER_KEY_DERIVE_PARAMS;

typedef CK_TLS12_MASTER_KEY_DERIVE_PARAMS CK_PTR \
                                CK_TLS12_MASTER_KEY_DERIVE_PARAMS_PTR;

typedef struct CK_TLS12_KEY_MAT_PARAMS {
    CK_ULONG                  ulMacSizeInBits;
    CK_ULONG                  ulKeySizeInBits;
    CK_ULONG                  ulIVSizeInBits;
    CK_BBOOL                  bIsExport;
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_SSL3_KEY_MAT_OUT_PTR   pReturnedKeyMaterial;
    CK_MECHANISM_TYPE         prfHashMechanism;
} CK_TLS12_KEY_MAT_PARAMS;

typedef CK_TLS12_KEY_MAT_PARAMS CK_PTR CK_TLS12_KEY_MAT_PARAMS_PTR;

typedef struct CK_TLS_KDF_PARAMS {
    CK_MECHANISM_TYPE         prfMechanism;
    CK_BYTE_PTR               pLabel;
    CK_ULONG                  ulLabelLength;
    CK_SSL3_RANDOM_DATA       RandomInfo;
    CK_BYTE_PTR               pContextData;
    CK_ULONG                  ulContextDataLength;
} CK_TLS_KDF_PARAMS;

typedef CK_TLS_KDF_PARAMS CK_PTR CK_TLS_KDF_PARAMS_PTR;

typedef struct CK_TLS_MAC_PARAMS {
    CK_MECHANISM_TYPE         prfHashMechanism;
    CK_ULONG                  ulMacLength;
    CK_ULONG                  ulServerOrClient;
} CK_TLS_MAC_PARAMS;

typedef CK_TLS_MAC_PARAMS CK_PTR CK_TLS_MAC_PARAMS_PTR;

typedef struct CK_GOSTR3410_DERIVE_PARAMS {
    CK_EC_KDF_TYPE            kdf;
    CK_BYTE_PTR               pPublicData;
    CK_ULONG                  ulPublicDataLen;
    CK_BYTE_PTR               pUKM;
    CK_ULONG                  ulUKMLen;
} CK_GOSTR3410_DERIVE_PARAMS;

typedef CK_GOSTR3410_DERIVE_PARAMS CK_PTR CK_GOSTR3410_DERIVE_PARAMS_PTR;

typedef struct CK_GOSTR3410_KEY_WRAP_PARAMS {
    CK_BYTE_PTR               pWrapOID;
    CK_ULONG                  ulWrapOIDLen;
    CK_BYTE_PTR               pUKM;
    CK_ULONG                  ulUKMLen;
    CK_OBJECT_HANDLE          hKey;
} CK_GOSTR3410_KEY_WRAP_PARAMS;

typedef CK_GOSTR3410_KEY_WRAP_PARAMS CK_PTR CK_GOSTR3410_KEY_WRAP_PARAMS_PTR;

typedef struct CK_SEED_CBC_ENCRYPT_DATA_PARAMS {
    CK_BYTE                   iv[16];
    CK_BYTE_PTR               pData;
    CK_ULONG                  length;
} CK_SEED_CBC_ENCRYPT_DATA_PARAMS;

typedef CK_SEED_CBC_ENCRYPT_DATA_PARAMS CK_PTR \
                                        CK_SEED_CBC_ENCRYPT_DATA_PARAMS_PTR;

/*
 * New PKCS 11 v3.0 data structures.
 */

typedef CK_ULONG CK_PROFILE_ID;
typedef CK_PROFILE_ID CK_PTR CK_PROFILE_ID_PTR;

/* Typedefs for Flexible KDF */
typedef CK_ULONG CK_PRF_DATA_TYPE;
typedef CK_MECHANISM_TYPE CK_SP800_108_PRF_TYPE;
#define CK_SP800_108_ITERATION_VARIABLE 0x00000001UL
#define CK_SP800_108_OPTIONAL_COUNTER   0x00000002UL
#define CK_SP800_108_DKM_LENGTH         0x00000003UL
#define CK_SP800_108_BYTE_ARRAY         0x00000004UL
#define CK_SP800_108_COUNTER            CK_SP800_108_OPTIONAL_COUNTER

typedef struct CK_PRF_DATA_PARAM
{
   CK_PRF_DATA_TYPE    type;
   CK_VOID_PTR         pValue;
   CK_ULONG            ulValueLen;
} CK_PRF_DATA_PARAM;

typedef CK_PRF_DATA_PARAM CK_PTR CK_PRF_DATA_PARAM_PTR;


typedef struct CK_SP800_108_COUNTER_FORMAT
{ 
   CK_BBOOL           bLittleEndian;
   CK_ULONG		ulWidthInBits;
} CK_SP800_108_COUNTER_FORMAT;

typedef CK_SP800_108_COUNTER_FORMAT CK_PTR CK_SP800_108_COUNTER_FORMAT_PTR;

typedef CK_ULONG CK_SP800_108_DKM_LENGTH_METHOD;
#define CK_SP800_108_DKM_LENGTH_SUM_OF_KEYS     0x00000001UL
#define CK_SP800_108_DKM_LENGTH_SUM_OF_SEGMENTS 0x00000002UL

typedef struct CK_SP800_108_DKM_LENGTH_FORMAT
{ 
   CK_SP800_108_DKM_LENGTH_METHOD  dkmLengthMethod;
   CK_BBOOL                        bLittleEndian;
   CK_ULONG		             ulWidthInBits;
} CK_SP800_108_DKM_LENGTH_FORMAT;

typedef CK_SP800_108_DKM_LENGTH_FORMAT \
                                CK_PTR CK_SP800_108_DKM_LENGTH_FORMAT_PTR;

typedef struct CK_DERIVED_KEY
{
   CK_ATTRIBUTE_PTR     pTemplate;
   CK_ULONG             ulAttributeCount;
   CK_OBJECT_HANDLE_PTR phKey;
} CK_DERIVED_KEY;

typedef CK_DERIVED_KEY CK_PTR CK_DERIVED_KEY_PTR;

typedef struct CK_SP800_108_KDF_PARAMS
{
   CK_SP800_108_PRF_TYPE prfType;
   CK_ULONG               ulNumberOfDataParams;
   CK_PRF_DATA_PARAM_PTR  pDataParams;
   CK_ULONG             ulAdditionalDerivedKeys;
   CK_DERIVED_KEY_PTR   pAdditionalDerivedKeys;
} CK_SP800_108_KDF_PARAMS;

typedef CK_SP800_108_KDF_PARAMS CK_PTR CK_SP800_108_KDF_PARAMS_PTR;

typedef struct CK_SP800_108_FEEDBACK_KDF_PARAMS
{
   CK_SP800_108_PRF_TYPE prfType;
   CK_ULONG               ulNumberOfDataParams;
   CK_PRF_DATA_PARAM_PTR  pDataParams;
   CK_ULONG               ulIVLen;
   CK_BYTE_PTR            pIV;
   CK_ULONG             ulAdditionalDerivedKeys;
   CK_DERIVED_KEY_PTR   pAdditionalDerivedKeys;
} CK_SP800_108_FEEDBACK_KDF_PARAMS;

typedef CK_SP800_108_FEEDBACK_KDF_PARAMS \
                               CK_PTR CK_SP800_108_FEEDBACK_KDF_PARAMS_PTR;

/* EDDSA */
typedef struct CK_EDDSA_PARAMS {
	CK_BBOOL phFlag;
	CK_ULONG ulContextDataLen;
	CK_BYTE_PTR pContextData;
} CK_EDDSA_PARAMS;

typedef CK_EDDSA_PARAMS CK_PTR CK_EDDSA_PARAMS_PTR;

/* Extended ChaCha20/Salsa20 support*/
typedef struct CK_CHACHA20_PARAMS {
	CK_BYTE_PTR	pBlockCounter;
	CK_ULONG	blockCounterBits;
	CK_BYTE_PTR	pNonce;
	CK_ULONG	ulNonceBits;
} CK_CHACHA20_PARAMS;

typedef CK_CHACHA20_PARAMS CK_PTR CK_CHACHA20_PARAMS_PTR;

typedef struct CK_SALSA20_PARAMS {
	CK_BYTE_PTR	pBlockCounter;
	CK_BYTE_PTR	pNonce;
	CK_ULONG	ulNonceBits;
} CK_SALSA20_PARAMS;
typedef CK_SALSA20_PARAMS CK_PTR CK_SALSA20_PARAMS_PTR;

typedef struct CK_SALSA20_CHACHA20_POLY1305_PARAMS {
  CK_BYTE_PTR	pNonce;
  CK_ULONG	ulNonceLen;
  CK_BYTE_PTR pAAD;
  CK_ULONG ulAADLen;
} CK_SALSA20_CHACHA20_POLY1305_PARAMS;

typedef CK_SALSA20_CHACHA20_POLY1305_PARAMS \
                                CK_PTR CK_SALSA20_CHACHA20_POLY1305_PARAMS_PTR;

typedef struct CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS {
  CK_BYTE_PTR	pNonce;
  CK_ULONG	ulNonceLen;
  CK_BYTE_PTR pTag;
} CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS;

typedef CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS \
			CK_PTR CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS_PTR;

typedef CK_ULONG CK_X3DH_KDF_TYPE;
typedef CK_X3DH_KDF_TYPE CK_PTR CK_X3DH_KDF_TYPE_PTR;

/* X3dh, ratchet */
typedef struct CK_X3DH_INITIATE_PARAMS {
	CK_X3DH_KDF_TYPE kdf;
	CK_OBJECT_HANDLE pPeer_identity;
	CK_OBJECT_HANDLE pPeer_prekey;
	CK_BYTE_PTR pPrekey_signature;
	CK_BYTE_PTR pOnetime_key;
	CK_OBJECT_HANDLE pOwn_identity;
	CK_OBJECT_HANDLE pOwn_ephemeral;
} CK_X3DH_INITIATE_PARAMS;

typedef struct CK_X3DH_RESPOND_PARAMS {
	CK_X3DH_KDF_TYPE kdf;
	CK_BYTE_PTR pIdentity_id;
	CK_BYTE_PTR pPrekey_id;
	CK_BYTE_PTR pOnetime_id;
	CK_OBJECT_HANDLE pInitiator_identity;
	CK_BYTE_PTR pInitiator_ephemeral;
} CK_X3DH_RESPOND_PARAMS;

typedef CK_ULONG CK_X2RATCHET_KDF_TYPE;
typedef CK_X2RATCHET_KDF_TYPE CK_PTR CK_X2RATCHET_KDF_TYPE_PTR;

typedef struct CK_X2RATCHET_INITIALIZE_PARAMS {
	CK_BYTE_PTR 		sk;
	CK_OBJECT_HANDLE	peer_public_prekey;
	CK_OBJECT_HANDLE	peer_public_identity;
	CK_OBJECT_HANDLE	own_public_identity;
	CK_BBOOL 		bEncryptedHeader;
	CK_ULONG 		eCurve;
	CK_MECHANISM_TYPE 	aeadMechanism;
	CK_X2RATCHET_KDF_TYPE 	kdfMechanism;
} CK_X2RATCHET_INITIALIZE_PARAMS;

typedef CK_X2RATCHET_INITIALIZE_PARAMS \
                              CK_PTR CK_X2RATCHET_INITIALIZE_PARAMS_PTR;

typedef struct CK_X2RATCHET_RESPOND_PARAMS {
	CK_BYTE_PTR 			sk;
	CK_OBJECT_HANDLE		own_prekey;
	CK_OBJECT_HANDLE		initiator_identity;
	CK_OBJECT_HANDLE		own_public_identity;
	CK_BBOOL 			bEncryptedHeader;
	CK_ULONG 			eCurve;
	CK_MECHANISM_TYPE 		aeadMechanism;
	CK_X2RATCHET_KDF_TYPE 	kdfMechanism;
} CK_X2RATCHET_RESPOND_PARAMS;
typedef CK_X2RATCHET_RESPOND_PARAMS \
				CK_PTR CK_X2RATCHET_RESPOND_PARAMS_PTR;

typedef CK_ULONG CK_XEDDSA_HASH_TYPE;
typedef CK_XEDDSA_HASH_TYPE CK_PTR CK_XEDDSA_HASH_TYPE_PTR;

/* XEDDSA */
typedef struct CK_XEDDSA_PARAMS {
	CK_XEDDSA_HASH_TYPE hash;
} CK_XEDDSA_PARAMS;
typedef CK_XEDDSA_PARAMS CK_PTR CK_XEDDSA_PARAMS_PTR;

/* HKDF params */
typedef struct CK_HKDF_PARAMS {
   CK_BBOOL bExtract;
   CK_BBOOL bExpand;
   CK_MECHANISM_TYPE prfHashMechanism;
   CK_ULONG ulSaltType;
   CK_BYTE_PTR pSalt;
   CK_ULONG ulSaltLen;
   CK_OBJECT_HANDLE hSaltKey;
   CK_BYTE_PTR pInfo;
   CK_ULONG ulInfoLen;
} CK_HKDF_PARAMS;
typedef CK_HKDF_PARAMS CK_PTR CK_HKDF_PARAMS_PTR;

#define CKF_HKDF_SALT_NULL   0x00000001UL
#define CKF_HKDF_SALT_DATA   0x00000002UL
#define CKF_HKDF_SALT_KEY    0x00000004UL

/* HSS */
typedef CK_ULONG                   CK_HSS_LEVELS;
typedef CK_ULONG                   CK_LMS_TYPE;
typedef CK_ULONG                   CK_LMOTS_TYPE;

typedef struct specifiedParams {
  CK_HSS_LEVELS levels;
  CK_LMS_TYPE lm_type[8];
  CK_LMOTS_TYPE lm_ots_type[8];
} specifiedParams;

/* IKE Params */
typedef struct CK_IKE2_PRF_PLUS_DERIVE_PARAMS {
  CK_MECHANISM_TYPE prfMechanism;
  CK_BBOOL      bHasSeedKey;
  CK_OBJECT_HANDLE hSeedKey;
  CK_BYTE_PTR pSeedData;
  CK_ULONG    ulSeedDataLen;
} CK_IKE2_PRF_PLUS_DERIVE_PARAMS;
typedef CK_IKE2_PRF_PLUS_DERIVE_PARAMS CK_PTR CK_IKE2_PRF_PLUS_DERIVE_PARAMS_PTR;

typedef struct CK_IKE_PRF_DERIVE_PARAMS {
  CK_MECHANISM_TYPE prfMechanism;
  CK_BBOOL bDataAsKey;
  CK_BBOOL bRekey;
  CK_BYTE_PTR pNi;
  CK_ULONG    ulNiLen;
  CK_BYTE_PTR pNr;
  CK_ULONG    ulNrLen;
  CK_OBJECT_HANDLE hNewKey;
} CK_IKE_PRF_DERIVE_PARAMS;
typedef CK_IKE_PRF_DERIVE_PARAMS CK_PTR CK_IKE_PRF_DERIVE_PARAMS_PTR;

typedef struct CK_IKE1_PRF_DERIVE_PARAMS {
  CK_MECHANISM_TYPE prfMechanism;
  CK_BBOOL bHasPrevKey;
  CK_OBJECT_HANDLE hKeygxy;
  CK_OBJECT_HANDLE hPrevKey;
  CK_BYTE_PTR pCKYi;
  CK_ULONG    ulCKYiLen;
  CK_BYTE_PTR pCKYr;
  CK_ULONG    ulCKYrLen;
  CK_BYTE     keyNumber;
} CK_IKE1_PRF_DERIVE_PARAMS;
typedef CK_IKE1_PRF_DERIVE_PARAMS CK_PTR CK_IKE1_PRF_DERIVE_PARAMS_PTR;

typedef struct CK_IKE1_EXTENDED_DERIVE_PARAMS {
    CK_MECHANISM_TYPE prfMechanism;
    CK_BBOOL bHasKeygxy;
    CK_OBJECT_HANDLE hKeygxy;
    CK_BYTE_PTR pExtraData;
    CK_ULONG ulExtraDataLen;
} CK_IKE1_EXTENDED_DERIVE_PARAMS;
typedef CK_IKE1_EXTENDED_DERIVE_PARAMS CK_PTR CK_IKE1_EXTENDED_DERIVE_PARAMS_PTR;

#endif /* _PKCS11T_H_ */
