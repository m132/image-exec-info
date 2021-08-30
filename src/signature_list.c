/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include <efi.h>
#include <efilib.h>

#include "common.h"
#include "signature_list.h"

EFI_GUID IMAGE_SECURITY_DATABASE_GUID =
    {0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f}};

EFI_GUID CERT_SHA256_GUID =
    {0xc1c41626, 0x504c, 0x4092, {0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28}};

EFI_GUID CERT_RSA2048_GUID =
    {0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6}};

EFI_GUID CERT_RSA2048_SHA256_GUID =
    {0xe2b36190, 0x879b, 0x4a3d, {0xad, 0x8d, 0xf2, 0xe7, 0xbb, 0xa3, 0x27, 0x84}};

EFI_GUID CERT_SHA1_GUID =
    {0x826ca512, 0xcf10, 0x4ac9, {0xb1, 0x87, 0xbe, 0x01, 0x49, 0x66, 0x31, 0xbd}};

EFI_GUID CERT_RSA2048_SHA1_GUID =
    {0x67f8444f, 0x8743, 0x48f1, {0xa3, 0x28, 0x1e, 0xaa, 0xb8, 0x73, 0x60, 0x80}};

EFI_GUID CERT_X509_GUID =
    {0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72}};

EFI_GUID CERT_SHA224_GUID =
    { 0xb6e5233, 0xa65c, 0x44c9, {0x94, 0x07, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd}};

EFI_GUID CERT_SHA384_GUID =
    {0xff3e5307, 0x9fd0, 0x48c9, {0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x01}};

EFI_GUID CERT_SHA512_GUID =
    { 0x93e0fae, 0xa6c4, 0x4f50, {0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a}};

EFI_GUID CERT_X509_SHA256_GUID =
    {0x3bd2a492, 0x96c0, 0x4079, {0xb4, 0x20, 0xfc, 0xf9, 0x8e, 0xf1, 0x03, 0xed}};

EFI_GUID CERT_X509_SHA384_GUID =
    {0x7076876e, 0x80c2, 0x4ee6, {0xaa, 0xd2, 0x28, 0xb3, 0x49, 0xa6, 0x86, 0x5b}};

EFI_GUID CERT_X509_SHA512_GUID =
    {0x446dbf63, 0x2502, 0x4cda, {0xbc, 0xfa, 0x24, 0x65, 0xd2, 0xb0, 0xfe, 0x9d}};

EFI_GUID CERT_EXTERNAL_MANAGEMENT_GUID =
    {0x452e8ced, 0xdfff, 0x4b8c, {0xae, 0x01, 0x51, 0x18, 0x86, 0x2e, 0x68, 0x2c}};

static const CHAR16 *SIG_TYPE_STR[] = {
    L"Unsupported",
    L"SHA-256 Hash",
    L"RSA-2048 Public Key",
    L"RSA-2048 Signature of a SHA-256 Hash",
    L"SHA-1 Hash",
    L"RSA-2048 Signature of a SHA-1 Hash",
    L"X.509 Certificate",
    L"SHA-224 Hash",
    L"SHA-384 Hash",
    L"SHA-512 Hash",
    L"SHA-256 Hash of X.509 To-Be-Signed Contents",
    L"SHA-384 Hash of X.509 To-Be-Signed Contents",
    L"SHA-512 Hash of X.509 To-Be-Signed Contents",
    L"Externally Managed",
};

static enum SIG_TYPE
GuidToSigType (EFI_GUID *Guid)
{
    if (!CompareGuid(&CERT_SHA256_GUID, Guid))
        return SHA256;
    else if (!CompareGuid(&CERT_RSA2048_GUID, Guid))
        return RSA2048;
    else if (!CompareGuid(&CERT_RSA2048_SHA256_GUID, Guid))
        return RSA2048_SHA256;
    else if (!CompareGuid(&CERT_SHA1_GUID, Guid))
        return SHA1;
    else if (!CompareGuid(&CERT_RSA2048_SHA1_GUID, Guid))
        return RSA2048_SHA1;
    else if (!CompareGuid(&CERT_X509_GUID, Guid))
        return X509;
    else if (!CompareGuid(&CERT_SHA224_GUID, Guid))
        return SHA224;
    else if (!CompareGuid(&CERT_SHA384_GUID, Guid))
        return SHA384;
    else if (!CompareGuid(&CERT_SHA512_GUID, Guid))
        return SHA512;
    else if (!CompareGuid(&CERT_X509_SHA256_GUID, Guid))
        return X509_SHA256;
    else if (!CompareGuid(&CERT_X509_SHA384_GUID, Guid))
        return X509_SHA384;
    else if (!CompareGuid(&CERT_X509_SHA512_GUID, Guid))
        return X509_SHA512;
    else if (!CompareGuid(&CERT_EXTERNAL_MANAGEMENT_GUID, Guid))
        return EXTERNAL_MANAGEMENT;
    else
        return UNSUPPORTED;
}

VOID
ListSignatures (IN EFI_SIGNATURE_LIST *SigList, IN UINTN ListSize)
{
    UINTN ListIndex, SigIndex, Index;
    EFI_SIGNATURE_DATA *Sig, *LastSig;

    enum SIG_TYPE SigType;

    if (!SigList)
        return;

    for (ListIndex = 0; ListSize && ListSize >= SigList->SignatureListSize;
         ListSize -= SigList->SignatureListSize, ADVANCE_BY (SigList, SigList->SignatureListSize), ListIndex++)
    {
        SigType = GuidToSigType(&SigList->SignatureType);

        for (Sig = (EFI_SIGNATURE_DATA *) ((UINT8 *) SigList + sizeof (*SigList) + SigList->SignatureHeaderSize),
             LastSig = (EFI_SIGNATURE_DATA *) ((UINT8 *) SigList + SigList->SignatureListSize), SigIndex = 0;
             Sig != LastSig; ADVANCE_BY (Sig, SigList->SignatureSize), SigIndex++)
        {
            if (ListIndex || SigIndex)
                Print(L"\r\n");
            Print(L"%HSignature %d.%d:%N\r\n", ListIndex, SigIndex);

            if (SigType == UNSUPPORTED)
                Print(L"    Type: %g\r\n", &SigList->SignatureType);
            else
                Print(L"    Type: %s\r\n", SIG_TYPE_STR[SigType]);
            
            Print(L"   Owner: %g\r\n", &Sig->SignatureOwner);

            switch (SigType)
            {
                case SHA256:
                case SHA1:
                case SHA224:
                case SHA384:
                case SHA512:
                    Print(L"    Hash: ");
                    for (Index = 0; Index < SigList->SignatureSize - sizeof(EFI_GUID); Index++)
                        Print(L"%02x", Sig->SignatureData[Index]);
                    Print(L"\r\n");
                    break;
                case RSA2048:
                    Print(L" Modulus: \r\n");
                    DumpHex(0, 0, SigList->SignatureSize - sizeof (EFI_GUID), Sig->SignatureData);
                    break;
                case X509_SHA256:
                case X509_SHA384:
                case X509_SHA512:
                    Print(L"    Hash: ");
                    for (Index = 0; Index < SigList->SignatureSize - sizeof (EFI_GUID) - sizeof (EFI_TIME); Index++)
                        Print(L"%02x", Sig->SignatureData[Index]);
                    Print(L"\r\n"
                           " Expires: %t\r\n", (EFI_TIME *) &Sig->SignatureData[Index]);
                    break;
                case EXTERNAL_MANAGEMENT:
                    break;
                default:
                    Print(L"    Data: \r\n");
                    DumpHex(0, 0, SigList->SignatureSize - sizeof (EFI_GUID), Sig->SignatureData);
                    break;
            }
        }
    }
}
