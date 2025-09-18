/*/*************************************************************************
 *  Copyright 2021 IS Blocks, Ltd. and/or its affiliates 		 *
 *  and other contributors as indicated by the @author tags.	         *
 *									 *
 *  All rights reserved							 *
 * 									 *
 *  The use of this Proprietary Software are subject to specific         *
 *  commercial license terms						 *
 * 									 *
 *  To purchase a licence agreement for any use of this code please 	 *
 *  contact info@isblocks.com 			                         *
 *								         *
 *  Unless required by applicable law or agreed to in writing, software  *
 *  distributed under the License is distributed on an "AS IS" BASIS,    *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      *
 *  implied.								 *
 *  See the License for the specific language governing permissions and  *
 *  limitations under the License.                                       *
 *                                                                       *
 *************************************************************************/
package com.isblocks.pkcs11.jna;

import com.isblocks.pkcs11.CK_MECHANISM;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * JNA Native class with direct mapped methods.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public interface JNANativeI extends com.sun.jna.Library {

    public int C_Initialize(JNA_CK_C_INITIALIZE_ARGS pInitArgs);
    public int C_Finalize(Pointer pReserved);
    public int C_GetInfo(JNA_CK_INFO pInfo);
    public int C_GetSlotList(byte tokenPresent, LongArray pSlotList, NativeLongByReference pulCount);
    public int C_GetSlotInfo(NativeLong slotID, JNA_CK_SLOT_INFO pInfo);
    public int C_GetTokenInfo(NativeLong slotID, JNA_CK_TOKEN_INFO pInfo);
    public int C_WaitForSlotEvent(NativeLong flags, NativeLongByReference pSlot, Pointer pReserved);
    public int C_GetMechanismList(NativeLong slotID, LongArray pMechanismList, NativeLongByReference pulCount);
    public int C_GetMechanismInfo(NativeLong slotID, NativeLong type, JNA_CK_MECHANISM_INFO pInfo);
    public int C_InitToken(NativeLong slotID, byte[] pPin, NativeLong ulPinLen, byte[] pLabel32);
    public int C_InitPIN(NativeLong hSession, byte[] pPin, NativeLong ulPinLen);
    public int C_SetPIN(NativeLong hSession, byte[] pOldPin, NativeLong ulOldLen, byte[] pNewPin, NativeLong ulNewLen);
    public int C_OpenSession(NativeLong slotID, NativeLong flags, Pointer application, JNA_CK_NOTIFY notify, NativeLongByReference phSession);
    public int C_CloseSession(NativeLong hSession);
    public int C_CloseAllSessions(NativeLong slotID);
    public int C_GetSessionInfo(NativeLong hSession, JNA_CK_SESSION_INFO pInfo);
    public int C_GetOperationState(NativeLong hSession, byte[] pOperationState, NativeLongByReference pulOperationStateLen);
    public int C_SetOperationState(NativeLong hSession, byte[] pOperationState, NativeLong ulOperationStateLen, NativeLong hEncryptionKey, NativeLong hAuthenticationKey);
    public int C_Login(NativeLong hSession, NativeLong userType, byte[] pPin, NativeLong ulPinLen);
    public int C_Logout(NativeLong hSession);
    public int C_CreateObject(NativeLong hSession, Template pTemplate, NativeLong ulCount, NativeLongByReference phObject);
    public int C_CopyObject(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount, NativeLongByReference phNewObject);
    public int C_DestroyObject(NativeLong hSession, NativeLong hObject);
    public int C_GetObjectSize(NativeLong hSession, NativeLong hObject, NativeLongByReference pulSize);
    public int C_GetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public int C_SetAttributeValue(NativeLong hSession, NativeLong hObject, Template pTemplate, NativeLong ulCount);
    public int C_FindObjectsInit(NativeLong hSession, Template pTemplate, NativeLong ulCount);
    public int C_FindObjects(NativeLong hSession, LongArray phObject, NativeLong ulMaxObjectCount, NativeLongByReference pulObjectCount);
    public int C_FindObjectsFinal(NativeLong hSession);

    long C_EncryptInit(com.sun.jna.NativeLong hSession, Pointer pMechanism, com.sun.jna.NativeLong hKey);
    long C_EncryptInit(NativeLong hSession, JNA_CKM.ByReference pMechanism, NativeLong hKey);

       /**
     * C_EncryptInit initializes an encryption operation.
     *
     * @param hSession   the session's handle
     * @param pMechanism the encryption mechanism
     * @param hKey       handle of encryption key
     */
    long C_EncryptInit(NativeLong hSession, CK_MECHANISM pMechanism, NativeLong hKey);
   

     /**
     * C_EncryptInit initializes an encryption operation.
     *
     * @param hSession   the session's handle
     * @param pMechanism the encryption mechanism
     * @param hKey       handle of encryption key
     */
    long C_DecryptInit(NativeLong hSession, CK_MECHANISM pMechanism, NativeLong hKey);
    
    long C_DecryptInit(com.sun.jna.NativeLong hSession, Pointer pMechanism, com.sun.jna.NativeLong hKey);

    long C_DigestInit(com.sun.jna.NativeLong hSession, Pointer pMechanism);

    long C_SignInit(com.sun.jna.NativeLong hSession, Pointer pMechanism, com.sun.jna.NativeLong hKey);

    long C_VerifyInit(com.sun.jna.NativeLong hSession, Pointer pMechanism, com.sun.jna.NativeLong hKey);

    long C_GenerateKey(com.sun.jna.NativeLong hSession, Pointer pMechanism, Object pTemplate, com.sun.jna.NativeLong ulCount, com.sun.jna.ptr.NativeLongByReference phKey);
    //long C_EncryptInit(NativeLong hSession, JNA_CKM.ByReference pMechanism, NativeLong hKey);
    public int C_EncryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Encrypt(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pEncryptedData, NativeLongByReference pulEncryptedDataLen);
    public int C_EncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_EncryptFinal(NativeLong hSession, byte[] pLastEncryptedPart, NativeLongByReference pulLastEncryptedPartLen);
    public int C_DecryptInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Decrypt(NativeLong hSession, byte[] pEncryptedData, NativeLong ulEncryptedDataLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DecryptUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DecryptFinal(NativeLong hSession, byte[] pLastPart, NativeLongByReference pulLastPartLen);
    public int C_DigestInit(NativeLong hSession, JNA_CKM pMechanism);
    public int C_Digest(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pDigest, NativeLongByReference pulDigestLen);
    public int C_DigestUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_DigestKey(NativeLong hSession, NativeLong hKey);
    public int C_DigestFinal(NativeLong hSession, byte[] pDigest, NativeLongByReference pulDigestLen);
    public int C_SignInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Sign(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_SignUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_SignFinal(NativeLong hSession, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_SignRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_SignRecover(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLongByReference pulSignatureLen);
    public int C_VerifyInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_Verify(NativeLong hSession, byte[] pData, NativeLong ulDataLen, byte[] pSignature, NativeLong ulSignatureLen);
    public int C_VerifyUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen);
    public int C_VerifyFinal(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen);
    public int C_VerifyRecoverInit(NativeLong hSession, JNA_CKM pMechanism, NativeLong hKey);
    public int C_VerifyRecover(NativeLong hSession, byte[] pSignature, NativeLong ulSignatureLen, byte[] pData, NativeLongByReference pulDataLen);
    public int C_DigestEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_DecryptDigestUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public int C_SignEncryptUpdate(NativeLong hSession, byte[] pPart, NativeLong ulPartLen, byte[] pEncryptedPart, NativeLongByReference pulEncryptedPartLen);
    public int C_DecryptVerifyUpdate(NativeLong hSession, byte[] pEncryptedPart, NativeLong ulEncryptedPartLen, byte[] pPart, NativeLongByReference pulPartLen);
    public int C_GenerateKey(NativeLong hSession, JNA_CKM pMechanism, Template pTemplate, NativeLong ulCount, NativeLongByReference phKey);
    public int C_GenerateKeyPair(NativeLong hSession, JNA_CKM pMechanism, Template pPublicKeyTemplate, NativeLong ulPublicKeyAttributeCount, Template pPrivateKeyTemplate, NativeLong ulPrivateKeyAttributeCount, NativeLongByReference phPublicKey, NativeLongByReference phPrivateKey);
    public int C_WrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hWrappingKey, NativeLong hKey, byte[] pWrappedKey, NativeLongByReference pulWrappedKeyLen);
    public int C_UnwrapKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hUnwrappingKey, byte[] pWrappedKey, NativeLong ulWrappedKeyLen, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public int C_DeriveKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hBaseKey, Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
    public int C_SeedRandom(NativeLong hSession, byte[] pSeed, NativeLong ulSeedLen);
    public int C_GenerateRandom(NativeLong hSession, byte[] pRandom, NativeLong ulRandomLen);
    public int C_GetFunctionStatus(NativeLong hSession);
    public int C_CancelFunction(NativeLong hSession);

    /**
     * C_EncapsulateKey performs KEM encapsulation, producing an encapsulated key blob and a derived secret key object.
     * @param hSession the session's handle
     * @param pMechanism KEM mechanism (e.g., CKM.ML_KEM) with parameters if any
     * @param hPublicKey handle of recipient public key
     * @param pTemplate template for the derived secret key
     * @param ulAttributeCount number of attributes in template
     * @param pEncapsulatedKey buffer receiving encapsulated key bytes
     * @param pulEncapsulatedKeyLen in/out length for encapsulated key buffer
     * @param phKey receives handle of the derived secret key
     */
    public int C_EncapsulateKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hPublicKey,
            Template pTemplate, NativeLong ulAttributeCount,
            byte[] pEncapsulatedKey, NativeLongByReference pulEncapsulatedKeyLen,
            NativeLongByReference phKey);

    /**
     * C_DecapsulateKey performs KEM decapsulation, consuming an encapsulated key and producing a derived secret key object.
     * @param hSession the session's handle
     * @param pMechanism KEM mechanism (e.g., CKM.ML_KEM) with parameters if any
     * @param hPrivateKey handle of recipient private key
     * @param pEncapsulatedKey encapsulated key bytes
     * @param ulEncapsulatedKeyLen length of encapsulated key
     * @param pTemplate template for the derived secret key
     * @param ulAttributeCount number of attributes in template
     * @param phKey receives handle of the derived secret key
     */
    public int C_DecapsulateKey(NativeLong hSession, JNA_CKM pMechanism, NativeLong hPrivateKey,
            byte[] pEncapsulatedKey, NativeLong ulEncapsulatedKeyLen,
            Template pTemplate, NativeLong ulAttributeCount, NativeLongByReference phKey);
}
