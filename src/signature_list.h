/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef __SIGNATURE_LIST_H
#define __SIGNATURE_LIST_H

#include <efi/efi.h>

#pragma pack(push, 1)
typedef struct _EFI_SIGNATURE_DATA {
    EFI_GUID SignatureOwner;
    UINT8 SignatureData[];
} EFI_SIGNATURE_DATA;

typedef struct _EFI_SIGNATURE_LIST {
    EFI_GUID SignatureType;
    UINT32 SignatureListSize;
    UINT32 SignatureHeaderSize;
    UINT32 SignatureSize;
    /* UINT8 SignatureHeader [SignatureHeaderSize]; */
    /* EFI_SIGNATURE_DATA Signatures[...][SignatureSize]; */
} EFI_SIGNATURE_LIST;
#pragma pack(pop)

enum SIG_TYPE {
    UNSUPPORTED = 0,
    SHA256,
    RSA2048,
    RSA2048_SHA256,
    SHA1,
    RSA2048_SHA1,
    X509,
    SHA224,
    SHA384,
    SHA512,
    X509_SHA256,
    X509_SHA384,
    X509_SHA512,
    EXTERNAL_MANAGEMENT
};

extern EFI_GUID IMAGE_SECURITY_DATABASE_GUID;
extern EFI_GUID CERT_SHA256_GUID;
extern EFI_GUID CERT_RSA2048_GUID;
extern EFI_GUID CERT_RSA2048_SHA256_GUID;
extern EFI_GUID CERT_SHA1_GUID;
extern EFI_GUID CERT_RSA2048_SHA1_GUID;
extern EFI_GUID CERT_X509_GUID;
extern EFI_GUID CERT_SHA224_GUID;
extern EFI_GUID CERT_SHA384_GUID;
extern EFI_GUID CERT_SHA512_GUID;
extern EFI_GUID CERT_X509_SHA256_GUID;
extern EFI_GUID CERT_X509_SHA384_GUID;
extern EFI_GUID CERT_X509_SHA512_GUID;
extern EFI_GUID CERT_EXTERNAL_MANAGEMENT_GUID;

VOID
ListSignatures (IN EFI_SIGNATURE_LIST *SigList, IN UINTN ListSize);

#endif /* __SIGNATURE_LIST_H */
