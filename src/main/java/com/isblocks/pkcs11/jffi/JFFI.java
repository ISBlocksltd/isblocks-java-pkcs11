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

package com.isblocks.pkcs11.jffi;

import com.isblocks.pkcs11.CKA;
import com.isblocks.pkcs11.CKM;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS;
import com.isblocks.pkcs11.CK_INFO;
import com.isblocks.pkcs11.CK_MECHANISM_INFO;
import com.isblocks.pkcs11.CK_NOTIFY;
import com.isblocks.pkcs11.CK_SESSION_INFO;
import com.isblocks.pkcs11.CK_SLOT_INFO;
import com.isblocks.pkcs11.CK_TOKEN_INFO;
import com.isblocks.pkcs11.LongRef;
import com.isblocks.pkcs11.NativePointer;
import com.isblocks.pkcs11.NativeProvider;
import com.isblocks.pkcs11.ULong;

import jnr.ffi.Address;
import jnr.ffi.Pointer;
import jnr.ffi.byref.NativeLongByReference;

/**
 * JFFI PKCS#11 Provider.  Does mapping between jacknji11 structs and JFFI
 * structs and calls through to {@link JFFINative}.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI implements NativeProvider {

    {
        // set ULong size
        ULong.ULONG_SIZE = jnr.ffi.Runtime.getSystemRuntime().longSize() == 4
            ? ULong.ULongSize.ULONG4 : ULong.ULongSize.ULONG8;
    }
  /**
     * TO do:
     * @param pInitArgs
     * @return 
     */
    public long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        return JFFINative.C_Initialize(new JFFI_CK_C_INITIALIZE_ARGS(pInitArgs));
    }
 /**
     * TO do:
     * @param pReserved
     * @return 
     */
    public long C_Finalize(NativePointer pReserved) {
        return JFFINative.C_Finalize(Address.valueOf(pReserved.getAddress()));
    }
   /**
     * Returns general information about Cryptoki.
     * @param pInfo location that receives information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public long C_GetInfo(CK_INFO pInfo) {
        JFFI_CK_INFO jffi_pInfo = new JFFI_CK_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetInfo(jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }

    /**
     * Obtains a list of slots in the system.
     * @param tokenPresent only slots with tokens?
     * @param pSlotList receives array of slot IDs
     * @param pulCount receives the number of slots
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotList(boolean, long[], LongRef) 
     */
    public long C_GetSlotList(boolean tokenPresent, long[] pSlotList, LongRef pulCount) {
        NativeLongByReference jffi_pulCount = NLP(pulCount.value);
        long rv = JFFINative.C_GetSlotList(tokenPresent, pSlotList, jffi_pulCount);
        pulCount.value = jffi_pulCount.getValue().longValue();
        return rv;
    }
  /**
     * Obtains information about a particular slot in the system.
     * @param slotID the ID of the slot
     * @param pInfo receives the slot information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSlotInfo(long, CK_SLOT_pINFO)
     */
    public long C_GetSlotInfo(long slotID, CK_SLOT_INFO pInfo) {
        JFFI_CK_SLOT_INFO jffi_pInfo = new JFFI_CK_SLOT_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetSlotInfo(slotID, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }
 /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param pinfo receives the token information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_pINFO)
     */
    public long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo) {
        JFFI_CK_TOKEN_INFO jffi_pInfo = new JFFI_CK_TOKEN_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetTokenInfo(slotID, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }
 /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param pslot location that receives the slot ID
     * @param pReserved reserved. 
     * @return {@link CKR} return code
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    public long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved) {
        NativeLongByReference jffi_pSlot = NLP(pSlot.value);
        Address jffi_pReserved = Address.valueOf(pReserved.getAddress());
        long rv = JFFINative.C_WaitForSlotEvent(flags, jffi_pSlot, jffi_pReserved);
        pSlot.value = jffi_pSlot.getValue().longValue();
        pReserved.setAddress(jffi_pReserved.address());
        return rv;
    }
     /**
     * Obtains a list of mechanism types supported by a token.
     * @param slotID ID of token's slot
     * @param pMechanismList gets mechanism array
     * @param pulCount gets # of mechanisms
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetMechanismList(long, long[], LongRef)
     */
    public long C_GetMechanismList(long slotID, long[] pMechanismList, LongRef pulCount) {
        NativeLongByReference jffi_pulCount = NLP(pulCount.value);
        long rv = JFFINative.C_GetMechanismList(slotID, pMechanismList, jffi_pulCount);
        pulCount.value = jffi_pulCount.getValue().longValue();
        return rv;
    }
 /**
     * Obtains information about a particular mechanism possibly supported by a token.
     * @param slotID ID of the token's slot
     * @param type {@link CKM} type of mechanism
     * @param pInfo receives mechanism info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetMechanismInfo(long, long, CK_MECHANISM_INFO)
     */
    public long C_GetMechanismInfo(long slotID, long type, CK_MECHANISM_INFO pInfo) {
        JFFI_CK_MECHANISM_INFO jffi_pInfo = new JFFI_CK_MECHANISM_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetMechanismInfo(slotID, type, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }
    /**
     * Initialises a token.  Pad or truncate label if required.
     * @param slotID ID of the token's slot
     * @param pPin the SO's initial PIN
	 * @param ulPinLen
     * @param pLabel32 32-byte token label (space padded).  If not 32 bytes, then
     * it will be padded or truncated as required
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitToken(long, byte[], long, byte[])
     */
    public long C_InitToken(long slotID, byte[] pPin, long ulPinLen, byte[] pLabel32) {
        return JFFINative.C_InitToken(slotID, pPin, ulPinLen, pLabel32);
    }
/**
     * Initialise normal user with PIN.
     * @param hSession the session's handle
     * @param pPin the normal user's PIN
	 * @param ulPinLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_InitPIN(long, byte[], long)
     */
    public long C_InitPIN(long hSession, byte[] pPin, long ulPinLen) {
        return JFFINative.C_InitPIN(hSession, pPin, ulPinLen);
    }
 /**
     * Change PIN.
     * @param hSession the session's handle
     * @param pOldPin old PIN
	 * @param ulOldLen
     * @param pNewPin new PIN
	 * @param ulNewLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetPIN(long, byte[], long, byte[], long)
     */
    public long C_SetPIN(long hSession, byte[] pOldPin, long ulOldLen, byte[] pNewPin, long ulNewLen) {
        return JFFINative.C_SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
    }
    /**
     * Opens a session between an application and a token.
     * @param slotID the slot's ID
     * @param flags from {@link CK_SESSION_INFO}
     * @param application passed to callback (ok to leave it null)
     * @param notify callback function (ok to leave it null)
     * @param phSession gets session handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_OpenSession(long, long, NativePointer, CK_NOTIFY, LongRef)
     */
    public long C_OpenSession(long slotID, long flags, NativePointer application, final CK_NOTIFY notify, LongRef phSession) {
        Address jffi_application = Address.valueOf(application.getAddress());
        JFFI_CK_NOTIFY jffi_notify = new JFFI_CK_NOTIFY() {
            public long invoke(long hSession, long event, Pointer pApplication) {
                return notify.invoke(hSession, event, new NativePointer(pApplication.address()));
            }
        };
        NativeLongByReference jffi_phSession = NLP(phSession.value);
//        long rv = JFFINative.C_OpenSession(slotID, flags, jffi_application, jffi_notify, jffi_phSession);
long rv = JFFINative.C_OpenSession(slotID, flags, jffi_application, null, jffi_phSession);
        application.setAddress(jffi_application.address());
        phSession.value = jffi_phSession.getValue().longValue();
        return rv;
    }
 /**
     * Closes a session between an application and a token.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseSession(long)
     */
    public long C_CloseSession(long hSession) {
        return JFFINative.C_CloseSession(hSession);
    }
  /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public long C_CloseAllSessions(long slotID) {
        return JFFINative.C_CloseAllSessions(slotID);
    }
    /**
     * Obtains information about the session.
     * @param hSession the session's handle
     * @param pInfo receives session info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo) {
        JFFI_CK_SESSION_INFO jffi_pInfo = new JFFI_CK_SESSION_INFO().readFrom(pInfo);
        long rv = JFFINative.C_GetSessionInfo(hSession, jffi_pInfo);
        jffi_pInfo.writeTo(pInfo);
        return rv;
    }
 /**
     * Obtains the state of the cryptographic operation.
     * @param hSession the session's handle
     * @param pOperationState gets state
     * @param pulOperationStateLen gets state length
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetOperationState(long, byte[], LongRef)
     */
    public long C_GetOperationState(long hSession, byte[] pOperationState, LongRef pulOperationStateLen) {
        NativeLongByReference jffi_pulOperationStateLen = NLP(pulOperationStateLen.value);
        long rv = JFFINative.C_GetOperationState(hSession, pOperationState, jffi_pulOperationStateLen);
        pulOperationStateLen.value = jffi_pulOperationStateLen.getValue().longValue();
        return rv;
    }
  /**
     * Restores the state of the cryptographic operation in a session.
     * @param hSession the session's handle
     * @param pOperationState holds state
	 * @param ulOperationStateLen
     * @param hEncryptionKey en/decryption key
     * @param hAuthenticationKey sign/verify key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetOperationState(long, byte[], long, long, long)
     */
    public long C_SetOperationState(long hSession, byte[] pOperationState, long ulOperationStateLen, long hEncryptionKey,
            long hAuthenticationKey) {
        return JFFINative.C_SetOperationState(hSession, pOperationState, ulOperationStateLen,
            hEncryptionKey, hAuthenticationKey);
    }
  /**
     * Logs a user into a token.
     * @param hSession the session's handle
     * @param userType the user type from {@link CKU}
     * @param pPin the user's PIN
	 * @param ulPinLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_Login(long, long, byte[], long)
     */
    public long C_Login(long hSession, long userType, byte[] pPin, long ulPinLen) {
        return JFFINative.C_Login(hSession, userType, pPin, ulPinLen);
    }

    /**
     * Logs a user out from a token.
     * @param long hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_Logout(long)
     */
    public long C_Logout(long hSession) {
        return JFFINative.C_Logout(hSession);
    }
  /**
     * Creates a new object.
     * @param hSession the session's handle
     * @param pTemplate the objects template
	 * @param ulCount
     * @param phObject gets new object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CreateObject(long, CKA[], long, LongRef)
     */
    public long C_CreateObject(long hSession, CKA[] pTemplate, long ulCount, LongRef phObject) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phObject = NLP(phObject.value);
        long rv = JFFINative.C_CreateObject(hSession, jffi_pTemplate, ulCount, jffi_phObject);
        phObject.value = jffi_phObject.getValue().longValue();
        return rv;
    }

    /**
     * Copies an object, creating a new object for the copy.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pTemplate template for new object
	 * @param ulCount
     * @param phNewObject receives handle of copy
     * @return {@link CKR} return code
     * @see NativeProvider#C_CopyObject(long, long, CKA[], long, LongRef)
     */
    public long C_CopyObject(long hSession, long hObject, CKA[] pTemplate, long ulCount, LongRef phNewObject) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phNewObject = NLP(phNewObject.value);
        long rv = JFFINative.C_CopyObject(hSession, hObject, jffi_pTemplate, ulCount, jffi_phNewObject);
        phNewObject.value = jffi_phNewObject.getValue().longValue();
        return rv;
    }
 /**
     * Destroys an object.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_DestroyObject(long, long)
     */
    public long C_DestroyObject(long hSession, long hObject) {
        return JFFINative.C_DestroyObject(hSession, hObject);
    }
  /**
     * Gets the size of an object in bytes.
     * @param hSession the session's handle
     * @param hObject the object's handle
     * @param pulSize receives the size of object
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetObjectSize(long, long, LongRef)
     */
    public long C_GetObjectSize(long hSession, long hObject, LongRef pulSize) {
        NativeLongByReference jffi_pulSize = NLP(pulSize.value);
        long rv = JFFINative.C_GetObjectSize(hSession, hObject, jffi_pulSize);
        pulSize.value = jffi_pulSize.getValue().longValue();
        return rv;
    }
/**
     * Obtains the value of one or more object attributes.
     * @param hSession the session's handle
     * @param hObject the objects's handle
     * @param pTemplate specifies attributes, gets values
	 * @param ulCount
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetAttributeValue(long, long, CKA[], long)
     */
    public long C_GetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_GetAttributeValue(hSession, hObject, jffi_pTemplate, ulCount);
        Template.update(jffi_pTemplate, pTemplate);
        return rv;
    }
    /**
     * Modifies the values of one or more object attributes.
     * @param long hSession, long hObject, CKA[] pTemplate, long ulCount the session's handle
     * @param hObject the object's handle
     * @param pTemplate specifies attributes and values
	 * @param ulCount
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    public long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_SetAttributeValue(hSession, hObject, jffi_pTemplate, ulCount);
        return rv;
    }
 /**
     * Initialises a search for token and session objects that match a template.
     * @param hSession the session's handle
     * @param pTemplate attribute values to match
	 * @param ulCount
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsInit(long, CKA[], long)
     */
    public long C_FindObjectsInit(long hSession, CKA[] pTemplate, long ulCount) {
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        long rv = JFFINative.C_FindObjectsInit(hSession, jffi_pTemplate, ulCount);
        return rv;
    }
    /**
     * Continues a search for token and session objects that match a template,
     * obtaining additional object handles.
     * @param hSession the session's handle
	 * @param phObject
     * @param ulMaxObjectCount
     * @param pulObjectCount number of object handles returned
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjects(long, long[], long, LongRef)
     */
    public long C_FindObjects(long hSession, long[] phObject, long ulMaxObjectCount, LongRef pulObjectCount) {
        NativeLongByReference jffi_pulObjectCount = NLP(pulObjectCount.value);
        long rv = JFFINative.C_FindObjects(hSession, phObject, ulMaxObjectCount, jffi_pulObjectCount);
        pulObjectCount.value = jffi_pulObjectCount.getValue().longValue();
        return rv;
    }
  /**
     * Finishes a search for token and session objects.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public long C_FindObjectsFinal(long hSession) {
        return JFFINative.C_FindObjectsFinal(hSession);
    }

    /**
     * Initialises an encryption operation.
     * @param hSession the session's handle
     * @param pMechanism the encryption mechanism
     * @param hKey handle of encryption key
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptInit(long, CKM, long)
     */
    public long C_EncryptInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_EncryptInit(hSession, jffi_pMechanism, hKey);
    }
  /**
     * Encrypts single-part data.
     * @param hSession the session's handle
     * @param pData the plaintext data
	 * @param ulDataLen
     * @param pEncryptedData gets ciphertext
     * @param pulEncryptedDataLen gets c-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Encrypt(long, byte[], long, byte[], LongRef)
     */
    public long C_Encrypt(long hSession, byte[] pData, long ulDataLen, byte[] pEncryptedData, LongRef pulEncryptedDataLen) {
        NativeLongByReference jffi_pulEncryptedDataLen = NLP(pulEncryptedDataLen.value);
        long rv = JFFINative.C_Encrypt(hSession, pData, ulDataLen, pEncryptedData, jffi_pulEncryptedDataLen);
        pulEncryptedDataLen.value = jffi_pulEncryptedDataLen.getValue().longValue();
        return rv;
    }
    /**
     * Continues a multiple-part encryption.
     * @param hSession the session's handle
     * @param pPart the plaintext data
	 * @param ulPartLen
     * @param pEncryptedPart get ciphertext
     * @param pulEncryptedPartLen gets c-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_EncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_EncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }
    /**
     * Finishes a multiple-part encryption.
     * @param hSession the session's handle
     * @param pLastEncryptedPart last c-text
     * @param pulLastEncryptedPartLen gets last size
     * @return {@link CKR} return code
     * @see NativeProvider#C_EncryptFinal(long, byte[], LongRef)
     */
    public long C_EncryptFinal(long hSession, byte[] pLastEncryptedPart, LongRef pulLastEncryptedPartLen) {
        NativeLongByReference jffi_pulLastEncryptedPartLen = NLP(pulLastEncryptedPartLen.value);
        long rv = JFFINative.C_EncryptFinal(hSession, pLastEncryptedPart, jffi_pulLastEncryptedPartLen);
        pulLastEncryptedPartLen.value = jffi_pulLastEncryptedPartLen.getValue().longValue();
        return rv;
    }
    /**
     * Intialises a decryption operation.
     * @param hSession the session's handle
     * @param pMechanism the decryption mechanism
     * @param hKey handle of decryption key
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptInit(long, CKM, long)
     */
    public long C_DecryptInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_DecryptInit(hSession, jffi_pMechanism, hKey);
    }

    /**
     * Decrypts encrypted data in a single part.
     * @param hSession the session's handle
     * @param pEncryptedData cipertext
	 * @param ulEncryptedDataLen
     * @param pData gets plaintext
     * @param pulDataLen gets p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_Decrypt(long, byte[], long, byte[], LongRef)
     */
    public long C_Decrypt(long hSession, byte[] pEncryptedData, long ulEncryptedDataLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_Decrypt(hSession, pEncryptedData, ulEncryptedDataLen, pData, jffi_pulDataLen);
        pulDataLen.value= jffi_pulDataLen.getValue().longValue();
        return rv;
    }
   /**
     * Continues a multiple-part decryption.
     * @param hSession the session's handle
     * @param pEncryptedPart encrypted data
	 * @param ulEncryptedPartLen
     * @param pData gets plaintext
     * @param pulDataLen get p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_DecryptUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_DecryptUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pData, jffi_pulDataLen);
        pulDataLen.value = jffi_pulDataLen.getValue().longValue();
        return rv;
    }
    /**
     * Finishes a multiple-part decryption.
     * @param hSession the session's handle
     * @param pLastPart gets plaintext
     * @param pulLastPartLen p-text size
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptFinal(long, byte[], LongRef)
     */
    public long C_DecryptFinal(long hSession, byte[] pLastPart, LongRef pulLastPartLen) {
        NativeLongByReference jffi_pulLastPartLen = NLP(pulLastPartLen.value);
        long rv = JFFINative.C_DecryptFinal(hSession, pLastPart, jffi_pulLastPartLen);
        pulLastPartLen.value = jffi_pulLastPartLen.getValue().longValue();
        return rv;
    }
    /**
     * Initialises a message-digesting operation.
     * @param hSession the session's handle
     * @param pMechanism the digesting mechanism
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestInit(long, CKM)
     */
    public long C_DigestInit(long hSession, CKM pMechanism) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_DigestInit(hSession, jffi_pMechanism);
    }
   /**
     * Digests data in a single part.
     * @param hSession the session's handle
     * @param pData data to be digested
	 * @param ulDataLen
     * @param pDigest gets the message digest
     * @param pulDigestLen gets digest length
     * @return {@link CKR} return code
     * @see NativeProvider#C_Digest(long, byte[], long, byte[], LongRef)
     */
    public long C_Digest(long hSession, byte[] pData, long ulDataLen, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jffi_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JFFINative.C_Digest(hSession, pData, ulDataLen, pDigest, jffi_pulDigestLen);
        pulDigestLen.value = jffi_pulDigestLen.getValue().longValue();
        return rv;
    }
    /**
     * Continues a multiple-part message-digesting.
     * @param hSession the session's handle
     * @param pPart data to be digested
	 * @param ulPartLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestUpdate(long, byte[], long)
     */
    public long C_DigestUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_DigestUpdate(hSession, pPart, ulPartLen);
    }
/**
     * Continues a multi-part message-digesting operation, by digesting
     * the value of a secret key as part of the data already digested.
     * @param hSession the session's handle
     * @param hKey secret key to digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestKey(long, long)
     */
    public long C_DigestKey(long hSession, long hKey) {
        return JFFINative.C_DigestKey(hSession, hKey);
    }
  /**
     * Finishes a multiple-part message-digesting operation.
     * @param hSession the session's handle
     * @param pDigest gets the message digest
     * @param pulDigestLen gets byte count of digest
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestFinal(long, byte[], LongRef)
     */
    public long C_DigestFinal(long hSession, byte[] pDigest, LongRef pulDigestLen) {
        NativeLongByReference jffi_pulDigestLen = NLP(pulDigestLen.value);
        long rv = JFFINative.C_DigestFinal(hSession, pDigest, jffi_pulDigestLen);
        pulDigestLen.value = jffi_pulDigestLen.getValue().longValue();
        return rv;
    }
    /**
     * Initialises a signature (private key encryption) operation, where
     * the signature is (will be) an appendix to the data, and plaintext
     * cannot be recovered from the signature.
     * @param hSession the session's handle
     * @param pMechanism the signature mechanism
     * @param hKey handle of signature key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignInit(long, CKM, long)
     */
    public long C_SignInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_SignInit(hSession, jffi_pMechanism, hKey);
    }
   /**
     * Signs (encrypts with private key) data in a single part, where the signature is (will be)
     * an appendix to the data, and plaintext canot be recovered from the signature.
     * @param hSession the session's handle
     * @param pData the data to sign
	 * @param ulDataLen
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_Sign(long, byte[], long, byte[], LongRef)
     */
    public long C_Sign(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_Sign(hSession, pData, ulDataLen, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }
 /**
     * Continues a multiple-part signature operation where the signature is
     * (will be) an appendix to the data, and plaintext cannot be recovered from
     * the signature.
     * @param hSession the session's handle
     * @param pPart data to sign
	 * @param ulPartLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignUpdate(long, byte[], long)
     */
    public long C_SignUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_SignUpdate(hSession, pPart, ulPartLen);
    }
    /**
     * Finishes a multiple-part signature operation, returning the signature.
     * @param hSession the session's handle
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignFinal(long, byte[], LongRef)
     */
    public long C_SignFinal(long hSession, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_SignFinal(hSession, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }
 /**
     * Initialises a signature operation, where the data can be recovered from the signature.
     * @param hSession the session's handle
     * @param pMechanism the signature mechanism
     * @param hKey handle f the signature key
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignRecoverInit(long, CKM, long)
     */
    public long C_SignRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_SignRecoverInit(hSession, jffi_pMechanism, hKey);
    }
  /**
     * Signs data in a single operation, where the data can be recovered from the signature.
     * @param hSession the session's handle
     * @param pData the data to sign
	 * @param  ulDataLen
     * @param pSignature gets the signature
     * @param pulSignatureLen gets signature length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignRecover(long, byte[], long, byte[], LongRef)
     */
    public long C_SignRecover(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, LongRef pulSignatureLen) {
        NativeLongByReference jffi_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = JFFINative.C_SignRecover(hSession, pData, ulDataLen, pSignature, jffi_pulSignatureLen);
        pulSignatureLen.value = jffi_pulSignatureLen.getValue().longValue();
        return rv;
    }
/**
     * Initialises a verification operation, where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature (e.g. DSA).
     * @param hSession the session's handle
     * @param pMechanism the verification mechanism
     * @param hKey verification key
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyInit(long, CKM, long)
     */
    public long C_VerifyInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_VerifyInit(hSession, jffi_pMechanism, hKey);
    }
 /**
     * Verifies a signature in a single-part operation, where the signature is an appendix to the data,
     * and plaintext cannot be recovered from the signature.
     * @param hSession the session's handle
     * @param pData signed data
	 * @param  ulDataLen
     * @param pSignature signature
	 * @param ulSignatureLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_Verify(long, byte[], long, byte[], long)
     */
    public long C_Verify(long hSession, byte[] pData, long ulDataLen, byte[] pSignature, long ulSignatureLen) {
        return JFFINative.C_Verify(hSession, pData, ulDataLen, pSignature, ulSignatureLen);
    }
 /**
     * Continues a multiple-part verification operation where the signature is an appendix to the data,
     * and plaintet cannot be recovered from the signature.
     * @param hSession the session's handle
     * @param pPart signed data
	 * @param ulPartLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyUpdate(long, byte[], long)
     */
    public long C_VerifyUpdate(long hSession, byte[] pPart, long ulPartLen) {
        return JFFINative.C_VerifyUpdate(hSession, pPart, ulPartLen);
    }
/**
     * Finishes a multiple-part verification operation, checking the signature.
     * @param hSession the session's handle
     * @param pSignature signature to verify
	 * @param ulSignatureLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyFinal(long, byte[], long)
     */
    public long C_VerifyFinal(long hSession, byte[] pSignature, long ulSignatureLen) {
        return JFFINative.C_VerifyFinal(hSession, pSignature, ulSignatureLen);
    }

    /**
     * Initialises a signature verification operation, where the data is recovered from the signature.
     * @param hSession the session's handle
     * @param pMechanism the verification mechanism
     * @param hKey verification key
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecoverInit(long, CKM, long)
     */
    public long C_VerifyRecoverInit(long hSession, CKM pMechanism, long hKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        return JFFINative.C_VerifyRecoverInit(hSession, jffi_pMechanism, hKey);
    }

    /**
     * Verifies a signature in a single-part operation, where the data is recovered from the signature.
     * @param hSession the session's handle
     * @param pSignature signature to verify
	 * @param ulSignatureLen
     * @param pData gets signed data
     * @param pulDataLen gets signed data length
     * @return {@link CKR} return code
     * @see NativeProvider#C_VerifyRecover(long, byte[], long, byte[], LongRef)
     */
    public long C_VerifyRecover(long hSession, byte[] pSignature, long ulSignatureLen, byte[] pData, LongRef pulDataLen) {
        NativeLongByReference jffi_pulDataLen = NLP(pulDataLen.value);
        long rv = JFFINative.C_VerifyRecover(hSession, pSignature, ulSignatureLen, pData, jffi_pulDataLen);
        pulDataLen.value = jffi_pulDataLen.getValue().longValue();
        return rv;
    }
 /**
     * Continues a multiple-part digesting and encryption operation.
     * @param hSession the session's handle
     * @param pPart the plaintext data
	 * @param ulPartLen
     * @param pEncryptedPart gets ciphertext
     * @param pulEncryptedPartLen get c-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DigestEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_DigestEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_DigestEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptedPartLen.getValue().longValue();
        return rv;
    }
   /**
     * Continues a multiple-part decryption and digesting operation.
     * @param hSession the session's handle
     * @param pEncryptedPart ciphertext
	 * @param ulEncryptedPartLen
     * @param pPart gets plaintext
     * @param pulPartLen gets plaintext length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptDigestUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_DecryptDigestUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jffi_pulPartLen = NLP(pulPartLen.value);
        long rv = JFFINative.C_DecryptDigestUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, jffi_pulPartLen);
        pulPartLen.value = jffi_pulPartLen.getValue().longValue();
        return rv;
    }
  /**
     * Continues a multiple-part signing and encryption operation.
     * @param hSession the session's handle
     * @param pPart the plaintext data
	 * @param ulPartLen
     * @param pEncryptedPart gets ciphertext
     * @param pulEncryptedPartLen gets c-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_SignEncryptUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_SignEncryptUpdate(long hSession, byte[] pPart, long ulPartLen, byte[] pEncryptedPart, LongRef pulEncryptedPartLen) {
        NativeLongByReference jffi_pulEncryptPartLen = NLP(pulEncryptedPartLen.value);
        long rv = JFFINative.C_SignEncryptUpdate(hSession, pPart, ulPartLen, pEncryptedPart, jffi_pulEncryptPartLen);
        pulEncryptedPartLen.value = jffi_pulEncryptPartLen.getValue().longValue();
        return rv;
    }
 /**
     * Continues a multiple-part decryption and verify operation.
     * @param hSession the session's handle
     * @param pEncryptedPart ciphertext
	 * @param ulEncryptedPartLen
     * @param pPart gets plaintext
     * @param pulPartLen gets p-text length
     * @return {@link CKR} return code
     * @see NativeProvider#C_DecryptVerifyUpdate(long, byte[], long, byte[], LongRef)
     */
    public long C_DecryptVerifyUpdate(long hSession, byte[] pEncryptedPart, long ulEncryptedPartLen, byte[] pPart, LongRef pulPartLen) {
        NativeLongByReference jffi_pulPartLen = NLP(pulPartLen.value);
        long rv = JFFINative.C_DecryptVerifyUpdate(hSession, pEncryptedPart, ulEncryptedPartLen, pPart, jffi_pulPartLen);
        pulPartLen.value = jffi_pulPartLen.getValue().longValue();
        return rv;
    }

    /**
     * Generates a secret key, creating a new key.
     * @param hSession the session's handle
     * @param pMechanism key generation mechanism
     * @param pTemplate template for the new key
	 * @param ulCount
     * @param phKey gets handle of new key
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateKey(long, CKM, CKA[], long, LongRef)
     */
    public long C_GenerateKey(long hSession, CKM pMechanism, CKA[] pTemplate, long ulCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_GenerateKey(hSession, jffi_pMechanism, jffi_pTemplate, ulCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }

 /**
     * Generates a public-key / private-key pair, create new key objects.
     * @param hSession the session's handle
     * @param pMechanism key generation mechansim
     * @param pPublicKeyTemplate template for the new public key
	 * @param ulPublicKeyAttributeCount
     * @param pPrivateKeyTemplate template for the new private key
	 * @param ulPrivateKeyAttributeCount
     * @param phPublicKey gets handle of new public key
     * @param phPrivateKey gets handle of new private key
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateKeyPair(long, CKM, CKA[], long, CKA[], long, LongRef, LongRef)
     */
    public long C_GenerateKeyPair(long hSession, CKM pMechanism, CKA[] pPublicKeyTemplate, long ulPublicKeyAttributeCount,
            CKA[] pPrivateKeyTemplate, long ulPrivateKeyAttributeCount, LongRef phPublicKey, LongRef phPrivateKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pPublicKeyTemplate = Template.templ(pPublicKeyTemplate);
        Pointer jffi_pPrivateKeyTemplate = Template.templ(pPrivateKeyTemplate);
        NativeLongByReference jffi_phPublicKey = NLP(phPublicKey.value);
        NativeLongByReference jffi_phPrivateKey = NLP(phPrivateKey.value);
        long rv = JFFINative.C_GenerateKeyPair(hSession, jffi_pMechanism, jffi_pPublicKeyTemplate, ulPublicKeyAttributeCount,
            jffi_pPrivateKeyTemplate, ulPrivateKeyAttributeCount, jffi_phPublicKey, jffi_phPrivateKey);
        phPublicKey.value = jffi_phPublicKey.getValue().longValue();
        phPrivateKey.value = jffi_phPrivateKey.getValue().longValue();
        return rv;
    }

    /**
     * Wraps (encrypts) a key.
     * @param hSession the session's handle
     * @param pMechanism the wrapping mechanism
     * @param hWrappingKey wrapping key
     * @param hKey key to be wrapped
     * @param pWrappedKey gets wrapped key
     * @param pulWrappedKeyLen gets wrapped key length
     * @return {@link CKR} return code
     * @see NativeProvider#C_WrapKey(long, CKM, long, long, byte[], LongRef)
     */
    public long C_WrapKey(long hSession, CKM pMechanism, long hWrappingKey, long hKey, byte[] pWrappedKey, LongRef pulWrappedKeyLen) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        NativeLongByReference jffi_pulWrappedKeyLen = NLP(pulWrappedKeyLen.value);
        long rv = JFFINative.C_WrapKey(hSession, jffi_pMechanism, hWrappingKey, hKey, pWrappedKey, jffi_pulWrappedKeyLen);
        pulWrappedKeyLen.value = jffi_pulWrappedKeyLen.getValue().longValue();
        return rv;
    }
    /**
     * Unwraps (decrypts) a wrapped key, creating a new key object.
     * @param hSession the session's handle
     * @param pMechanism unwrapping mechanism
     * @param hUnwrappingKey unwrapping key
     * @param pWrappedKey the wrapped key
	 * @param ulWrappedKeyLen
     * @param pTemplate new key template
	 * @param ulAttributeCount
     * @param phKey gets new handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_UnwrapKey(long, CKM, long, byte[], long, CKA[], long, LongRef)
     */
    public long C_UnwrapKey(long hSession, CKM pMechanism, long hUnwrappingKey, byte[] pWrappedKey, long ulWrappedKeyLen,
            CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_UnwrapKey(hSession, jffi_pMechanism, hUnwrappingKey, pWrappedKey, ulWrappedKeyLen,
            jffi_pTemplate, ulAttributeCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }
 /**
     * Derives a key from a base key, creating a new key object.
     * @param hSession the session's handle
     * @param pMechanism key derivation mechanism
     * @param hBaseKey base key
     * @param pTemplate new key template
	 * @param ulAttributeCount
     * @param phKey ges new handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_DeriveKey(long, CKM, long, CKA[], long, LongRef)
     */
    public long C_DeriveKey(long hSession, CKM pMechanism, long hBaseKey, CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JFFI_CKM jffi_pMechanism = new JFFI_CKM().readFrom(pMechanism);
        Pointer jffi_pTemplate = Template.templ(pTemplate);
        NativeLongByReference jffi_phKey = NLP(phKey.value);
        long rv = JFFINative.C_DeriveKey(hSession, jffi_pMechanism, hBaseKey, jffi_pTemplate, ulAttributeCount, jffi_phKey);
        phKey.value = jffi_phKey.getValue().longValue();
        return rv;
    }
  /**
     * Mixes additional seed material into the token's random number generator.
     * @param hSession the session's handle
     * @param pSeed the seed material
	 * @param ulSeedLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_SeedRandom(long, byte[], long)
     */
    public long C_SeedRandom(long hSession, byte[] pSeed, long ulSeedLen) {
        return JFFINative.C_SeedRandom(hSession, pSeed, ulSeedLen);
    }
 /**
     * Generates random or pseudo-random data.
     * @param hSession the session's handle
     * @param pRandomData receives the random data
	 * @param ulRandomLen
     * @return {@link CKR} return code
     * @see NativeProvider#C_GenerateRandom(long, byte[], long)
     */
    public long C_GenerateRandom(long hSession, byte[] pRandomData, long ulRandomLen) {
        return JFFINative.C_GenerateRandom(hSession, pRandomData, ulRandomLen);
    }
/**
     * In previous versions of Cryptoki, C_GetFunctionStatus obtained the status of a function running in parallel
     * with an application. Now, however, C_GetFunctionStatus is a legacy function which should simply return
     * the value CKR_FUNCTION_NOT_PARALLEL.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetFunctionStatus(long)
     */
    public long C_GetFunctionStatus(long hSession) {
        return JFFINative.C_GetFunctionStatus(hSession);
    }
  /**
     * In previous versions of Cryptoki, C_CancelFunction cancelled a function running in parallel with an application.
     * Now, however, C_CancelFunction is a legacy function which should simply return the value
     * CKR_FUNCTION_NOT_PARALLEL.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CancelFunction(long)
     */
    public long C_CancelFunction(long hSession) {
        return JFFINative.C_CancelFunction(hSession);
    }
  /**
      TO DO:
     * @param 1
     * @return {@link CKR} return code
     * @see NativeProvider
     */
    private static NativeLongByReference NLP(long l)
	{ return new NativeLongByReference(l); 
	}
}
