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

import java.security.SecureRandom;

import com.isblocks.pkcs11.C;
import com.isblocks.pkcs11.CKA;
import com.isblocks.pkcs11.CKR;
import com.isblocks.pkcs11.CKM;
import com.isblocks.pkcs11.CKU;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS;
import com.isblocks.pkcs11.CK_INFO;
import com.isblocks.pkcs11.CK_MECHANISM;
import com.isblocks.pkcs11.CK_MECHANISM_INFO;
import com.isblocks.pkcs11.CK_NOTIFY;
import com.isblocks.pkcs11.CK_SESSION_INFO;
import com.isblocks.pkcs11.CK_SLOT_INFO;
import com.isblocks.pkcs11.CK_TOKEN_INFO;
import com.isblocks.pkcs11.LongRef;
import com.isblocks.pkcs11.NativePointer;
import com.isblocks.pkcs11.NativeProvider;
import com.isblocks.pkcs11.ULong;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Memory;
import com.sun.jna.ptr.NativeLongByReference;

/**
 * JNA PKCS#11 provider.  Does mapping between jacknji11 structs and
 * JNA structs and calls through to {@link JNANativeI} native methods.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JNA implements NativeProvider {

    {
        // set ULong size
        ULong.ULONG_SIZE = NativeLong.SIZE == 4
            ? ULong.ULongSize.ULONG4 : ULong.ULongSize.ULONG8;
    }

    private JNANativeI jnaNative = null;
    
    public JNA(){
        this(C.getLibraryName());
    }
      /**
     * JNA Constructor 
     * @param customLibrary

     */
    public JNA(String customLibrary) {
        jnaNative = (JNANativeI) com.sun.jna.Native.load(customLibrary, JNANativeI.class);
    }


    public JNA(JNANativeI jnaNative) {
        this.jnaNative = jnaNative;
    }

    

    public long C_Initialize(CK_C_INITIALIZE_ARGS pInitArgs) {
        if(pInitArgs.createMutex == null && pInitArgs.destroyMutex == null && pInitArgs.lockMutex == null && pInitArgs.unlockMutex == null)
            return jnaNative.C_Initialize(null);
        return jnaNative.C_Initialize(new JNA_CK_C_INITIALIZE_ARGS(pInitArgs));
    }
 /**
     * TO do:
     * @param pReserved
     * @return 
     */
    public long C_Finalize(NativePointer pReserved) {
        return jnaNative.C_Finalize(new Pointer(pReserved.getAddress()));
    }
  /**
     * Returns general information about Cryptoki.
     * @param pInfo location that receives information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetInfo(CK_INFO)
     */
    public long C_GetInfo(CK_INFO pInfo) {
        JNA_CK_INFO jna_pInfo = new JNA_CK_INFO().readFrom(pInfo);
        long rv = jnaNative.C_GetInfo(jna_pInfo);
        jna_pInfo.writeTo(pInfo);
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
        LongArray jna_pSlotList = new LongArray(pSlotList);
        NativeLongByReference jna_pulCount = NLP(pulCount.value);
        long rv = jnaNative.C_GetSlotList(tokenPresent ? (byte)1 : (byte)0, jna_pSlotList, jna_pulCount);
        jna_pSlotList.update();
        pulCount.value = jna_pulCount.getValue().longValue();
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
        JNA_CK_SLOT_INFO jna_pInfo = new JNA_CK_SLOT_INFO().readFrom(pInfo);
        long rv = jnaNative.C_GetSlotInfo(NL(slotID), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }
 /**
     * Obtains information about a particular token in the system.
     * @param slotID ID of the token's slot
     * @param pInfo receives the token information
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetTokenInfo(long, CK_TOKEN_pINFO)
     */
    public long C_GetTokenInfo(long slotID, CK_TOKEN_INFO pInfo) {
        JNA_CK_TOKEN_INFO jna_pInfo = new JNA_CK_TOKEN_INFO().readFrom(pInfo);
        long rv = jnaNative.C_GetTokenInfo(NL(slotID), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
        return rv;
    }
 /**
     * Waits for a slot event (token insertion, removal, etc.) to occur.
     * @param flags blocking/nonblocking flag
     * @param pSlot location that receives the slot ID
     * @param pReserved reserved. 
     * @return {@link CKR} return code
     * @see NativeProvider#C_WaitForSlotEvent(long, LongRef, NativePointer)
     */
    public long C_WaitForSlotEvent(long flags, LongRef pSlot, NativePointer pReserved) {
        NativeLongByReference jna_pSlot = NLP(pSlot.value);
        Pointer jna_pReserved = new Pointer(pReserved.getAddress());
        long rv = jnaNative.C_WaitForSlotEvent(NL(flags), jna_pSlot, jna_pReserved);
        pSlot.value = jna_pSlot.getValue().longValue();
        pReserved.setAddress(Pointer.nativeValue(jna_pReserved));
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
        LongArray jna_pMechanismList = new LongArray(pMechanismList);
        NativeLongByReference jna_pulCount = NLP(pulCount.value);
        long rv = jnaNative.C_GetMechanismList(NL(slotID), jna_pMechanismList, jna_pulCount);
        jna_pMechanismList.update();
        pulCount.value = jna_pulCount.getValue().longValue();
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
        JNA_CK_MECHANISM_INFO jna_pInfo = new JNA_CK_MECHANISM_INFO().readFrom(pInfo);
        long rv = jnaNative.C_GetMechanismInfo(NL(slotID), NL(type), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
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
        return jnaNative.C_InitToken(NL(slotID), pPin, NL(ulPinLen), pLabel32);
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
        return jnaNative.C_InitPIN(NL(hSession), pPin, NL(ulPinLen));
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
        return jnaNative.C_SetPIN(NL(hSession), pOldPin, NL(ulOldLen), pNewPin, NL(ulNewLen));
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
        Pointer jna_application = new Pointer(application.getAddress());
        final JNA_CK_NOTIFY  jna_notify;
        if (notify == null) {
            jna_notify = null; 
        } else {
            jna_notify = new JNA_CK_NOTIFY() {
                public NativeLong invoke(NativeLong hSession, NativeLong event, Pointer pApplication) {
                    return NL(notify.invoke(hSession.longValue(), event.longValue(), new NativePointer(Pointer.nativeValue(pApplication))));
                }
            };
        }
        NativeLongByReference jna_phSession = NLP(phSession.value);
        long rv = jnaNative.C_OpenSession(NL(slotID), NL(flags), jna_application, jna_notify, jna_phSession);
        application.setAddress(Pointer.nativeValue(jna_application));
        phSession.value = jna_phSession.getValue().longValue();
        return rv;
    }
 /**
     * Closes a session between an application and a token.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseSession(long)
     */
    public long C_CloseSession(long hSession) {
        return jnaNative.C_CloseSession(NL(hSession));
    }
  /**
     * Closes all sessions with a token.
     * @param slotID the token's slot
     * @return {@link CKR} return code
     * @see NativeProvider#C_CloseAllSessions(long)
     */
    public long C_CloseAllSessions(long slotID) {
        return jnaNative.C_CloseAllSessions(NL(slotID));
    }
    /**
     * Obtains information about the session.
     * @param hSession the session's handle
     * @param pInfo receives session info
     * @return {@link CKR} return code
     * @see NativeProvider#C_GetSessionInfo(long, CK_SESSION_INFO)
     */
    public long C_GetSessionInfo(long hSession, CK_SESSION_INFO pInfo) {
        JNA_CK_SESSION_INFO jna_pInfo = new JNA_CK_SESSION_INFO().readFrom(pInfo);
        long rv = jnaNative.C_GetSessionInfo(NL(hSession), jna_pInfo);
        jna_pInfo.writeTo(pInfo);
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
        NativeLongByReference jna_pulOperationStateLen = NLP(pulOperationStateLen.value);
        long rv = jnaNative.C_GetOperationState(NL(hSession), pOperationState, jna_pulOperationStateLen);
        pulOperationStateLen.value = jna_pulOperationStateLen.getValue().longValue();
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
        return jnaNative.C_SetOperationState(NL(hSession), pOperationState, NL(ulOperationStateLen),
            NL(hEncryptionKey), NL(hAuthenticationKey));
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
        return jnaNative.C_Login(NL(hSession), NL(userType), pPin, NL(ulPinLen));
    }
    /**
     * Logs a user out from a token.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_Logout(long)
     */
    public long C_Logout(long hSession) {
        return jnaNative.C_Logout(NL(hSession));
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
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phObject = NLP(phObject.value);
        long rv = jnaNative.C_CreateObject(NL(hSession), jna_pTemplate, NL(ulCount), jna_phObject);
        jna_pTemplate.update();
        phObject.value = jna_phObject.getValue().longValue();
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
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phNewObject = NLP(phNewObject.value);
        long rv = jnaNative.C_CopyObject(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount), jna_phNewObject);
        jna_pTemplate.update();
        phNewObject.value = jna_phNewObject.getValue().longValue();
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
        return jnaNative.C_DestroyObject(NL(hSession), NL(hObject));
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
        NativeLongByReference jna_pulSize = NLP(pulSize.value);
        long rv = jnaNative.C_GetObjectSize(NL(hSession), NL(hObject), jna_pulSize);
        pulSize.value = jna_pulSize.getValue().longValue();
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
        Template jna_pTemplate = new Template(pTemplate);
        long rv = jnaNative.C_GetAttributeValue(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
        return rv;
    }

     /**
     * Modifies the values of one or more object attributes.
     * @param hSession, long hObject, CKA[] pTemplate, long ulCount the session's handle
     * @param hObject the object's handle
     * @param pTemplate specifies attributes and values
	 * @param ulCount
     * @return {@link CKR} return code
     * @see NativeProvider#C_SetAttributeValue(long, long, CKA[], long)
     */
    public long C_SetAttributeValue(long hSession, long hObject, CKA[] pTemplate, long ulCount) {
        Template jna_pTemplate = new Template(pTemplate);
        long rv = jnaNative.C_SetAttributeValue(NL(hSession), NL(hObject), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
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
        Template jna_pTemplate = new Template(pTemplate);
        long rv = jnaNative.C_FindObjectsInit(NL(hSession), jna_pTemplate, NL(ulCount));
        jna_pTemplate.update();
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
        LongArray jna_phObject = new LongArray(phObject);
        NativeLongByReference jna_pulObjectCOunt = NLP(pulObjectCount.value);
        long rv = jnaNative.C_FindObjects(NL(hSession), jna_phObject, NL(ulMaxObjectCount), jna_pulObjectCOunt);
        jna_phObject.update();
        pulObjectCount.value = jna_pulObjectCOunt.getValue().longValue();
        return rv;
    }
  /**
     * Finishes a search for token and session objects.
     * @param hSession the session's handle
     * @return {@link CKR} return code
     * @see NativeProvider#C_FindObjectsFinal(long)
     */
    public long C_FindObjectsFinal(long hSession) {
        return jnaNative.C_FindObjectsFinal(NL(hSession));
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

        // If the mechanism has parameters (e.g., IV for CBC), provide them: 
        Memory ivMem = new Memory(pMechanism.getParameterBytes().length); 
        ivMem.write(0, pMechanism.getParameterBytes(), 0, (int)pMechanism.ulParameterLen); 

    
        CK_MECHANISM pCKMMechanism = new CK_MECHANISM(  new NativeLong(pMechanism.mechanism), 
                                                        ivMem ,
                                                        new NativeLong(pMechanism.ulParameterLen));
        //jnaMech.writeTo(pMechanism); // write() not needed, readFrom

        long rv = jnaNative.C_EncryptInit(new NativeLong(hSession), 
                                pCKMMechanism, 
                                new NativeLong(hKey));


        return rv;
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
        NativeLongByReference jna_pulEncryptedDataLen = NLP(pulEncryptedDataLen.value);
        long rv = jnaNative.C_Encrypt(NL(hSession), pData, NL(ulDataLen), pEncryptedData, jna_pulEncryptedDataLen);
        pulEncryptedDataLen.value = jna_pulEncryptedDataLen.getValue().longValue();
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
        NativeLongByReference jna_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = jnaNative.C_EncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptedPartLen.getValue().longValue();
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
        NativeLongByReference jna_pulLastEncryptedPartLen = NLP(pulLastEncryptedPartLen.value);
        long rv = jnaNative.C_EncryptFinal(NL(hSession), pLastEncryptedPart, jna_pulLastEncryptedPartLen);
        pulLastEncryptedPartLen.value = jna_pulLastEncryptedPartLen.getValue().longValue();
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
        
        // If the mechanism has parameters (e.g., IV for CBC), provide them: 
        Memory ivMem = new Memory(pMechanism.getParameterBytes().length); 
        ivMem.write(0, pMechanism.getParameterBytes(), 0, pMechanism.getParameterBytes().length); 

    
        CK_MECHANISM pCKMMechanism = new CK_MECHANISM(  new NativeLong(pMechanism.mechanism), 
                                                        ivMem ,
                                                        new NativeLong(pMechanism.ulParameterLen));
        //jnaMech.writeTo(pMechanism); // write() not needed, readFrom

        long rv = jnaNative.C_DecryptInit(new NativeLong(hSession), 
                                pCKMMechanism, 
                                new NativeLong(hKey));


        return rv;
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
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = jnaNative.C_Decrypt(NL(hSession), pEncryptedData, NL(ulEncryptedDataLen), pData, jna_pulDataLen);
        pulDataLen.value= jna_pulDataLen.getValue().longValue();
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
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = jnaNative.C_DecryptUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pData, jna_pulDataLen);
        pulDataLen.value = jna_pulDataLen.getValue().longValue();
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
        NativeLongByReference jna_pulLastPartLen = NLP(pulLastPartLen.value);
        long rv = jnaNative.C_DecryptFinal(NL(hSession), pLastPart, jna_pulLastPartLen);
        pulLastPartLen.value = jna_pulLastPartLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return jnaNative.C_DigestInit(NL(hSession), jna_pMechanism);
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
        NativeLongByReference jna_pulDigestLen = NLP(pulDigestLen.value);
        long rv = jnaNative.C_Digest(NL(hSession), pData, NL(ulDataLen), pDigest, jna_pulDigestLen);
        pulDigestLen.value = jna_pulDigestLen.getValue().longValue();
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
        return jnaNative.C_DigestUpdate(NL(hSession), pPart, NL(ulPartLen));
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
        return jnaNative.C_DigestKey(NL(hSession), NL(hKey));
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
        NativeLongByReference jna_pulDigestLen = NLP(pulDigestLen.value);
        long rv = jnaNative.C_DigestFinal(NL(hSession), pDigest, jna_pulDigestLen);
        pulDigestLen.value = jna_pulDigestLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return jnaNative.C_SignInit(NL(hSession), jna_pMechanism, NL(hKey));
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
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = jnaNative.C_Sign(NL(hSession), pData, NL(ulDataLen), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
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
        return jnaNative.C_SignUpdate(NL(hSession), pPart, NL(ulPartLen));
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
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = jnaNative.C_SignFinal(NL(hSession), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return jnaNative.C_SignRecoverInit(NL(hSession), jna_pMechanism, NL(hKey));
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
        NativeLongByReference jna_pulSignatureLen = NLP(pulSignatureLen.value);
        long rv = jnaNative.C_SignRecover(NL(hSession), pData, NL(ulDataLen), pSignature, jna_pulSignatureLen);
        pulSignatureLen.value = jna_pulSignatureLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return jnaNative.C_VerifyInit(NL(hSession), jna_pMechanism, NL(hKey));
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
        return jnaNative.C_Verify(NL(hSession), pData, NL(ulDataLen), pSignature, NL(ulSignatureLen));
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
        return jnaNative.C_VerifyUpdate(NL(hSession), pPart, NL(ulPartLen));
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
        return jnaNative.C_VerifyFinal(NL(hSession), pSignature, NL(ulSignatureLen));
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        return jnaNative.C_VerifyRecoverInit(NL(hSession), jna_pMechanism, NL(hKey));
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
        NativeLongByReference jna_pulDataLen = NLP(pulDataLen.value);
        long rv = jnaNative.C_VerifyRecover(NL(hSession), pSignature, NL(ulSignatureLen), pData, jna_pulDataLen);
        pulDataLen.value = jna_pulDataLen.getValue().longValue();
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
        NativeLongByReference jna_pulEncryptedPartLen = NLP(pulEncryptedPartLen.value);
        long rv = jnaNative.C_DigestEncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptedPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptedPartLen.getValue().longValue();
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
        NativeLongByReference jna_pulPartLen = NLP(pulPartLen.value);
        long rv = jnaNative.C_DecryptDigestUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pPart, jna_pulPartLen);
        pulPartLen.value = jna_pulPartLen.getValue().longValue();
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
        NativeLongByReference jna_pulEncryptPartLen = NLP(pulEncryptedPartLen.value);
        long rv = jnaNative.C_SignEncryptUpdate(NL(hSession), pPart, NL(ulPartLen), pEncryptedPart, jna_pulEncryptPartLen);
        pulEncryptedPartLen.value = jna_pulEncryptPartLen.getValue().longValue();
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
        NativeLongByReference jna_pulPartLen = NLP(pulPartLen.value);
        long rv = jnaNative.C_DecryptVerifyUpdate(NL(hSession), pEncryptedPart, NL(ulEncryptedPartLen), pPart, jna_pulPartLen);
        pulPartLen.value = jna_pulPartLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = jnaNative.C_GenerateKey(NL(hSession), jna_pMechanism, jna_pTemplate, NL(ulCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pPublicKeyTemplate = new Template(pPublicKeyTemplate);
        Template jna_pPrivateKeyTemplate = new Template(pPrivateKeyTemplate);
        NativeLongByReference jna_phPublicKey = NLP(phPublicKey.value);
        NativeLongByReference jna_phPrivateKey = NLP(phPrivateKey.value);
        long rv = jnaNative.C_GenerateKeyPair(NL(hSession), jna_pMechanism, jna_pPublicKeyTemplate, NL(ulPublicKeyAttributeCount),
            jna_pPrivateKeyTemplate, NL(ulPrivateKeyAttributeCount), jna_phPublicKey, jna_phPrivateKey);
        phPublicKey.value = jna_phPublicKey.getValue().longValue();
        phPrivateKey.value = jna_phPrivateKey.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        NativeLongByReference jna_pulWrappedKeyLen = NLP(pulWrappedKeyLen.value);
        long rv = jnaNative.C_WrapKey(NL(hSession), jna_pMechanism, NL(hWrappingKey), NL(hKey), pWrappedKey, jna_pulWrappedKeyLen);
        pulWrappedKeyLen.value = jna_pulWrappedKeyLen.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = jnaNative.C_UnwrapKey(NL(hSession), jna_pMechanism, NL(hUnwrappingKey), pWrappedKey, NL(ulWrappedKeyLen),
            jna_pTemplate, NL(ulAttributeCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
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
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = jnaNative.C_DeriveKey(NL(hSession), jna_pMechanism, NL(hBaseKey), jna_pTemplate, NL(ulAttributeCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
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
        return jnaNative.C_SeedRandom(NL(hSession), pSeed, NL(ulSeedLen));
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
        return jnaNative.C_GenerateRandom(NL(hSession), pRandomData, NL(ulRandomLen));
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
        return jnaNative.C_GetFunctionStatus(NL(hSession));
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
        return jnaNative.C_CancelFunction(NL(hSession));
    }

    /**
     * Performs KEM encapsulation, producing encapsulated key bytes and a derived secret key object.
     * @param hSession the session's handle
     * @param pMechanism KEM mechanism
     * @param hPublicKey handle of recipient public key
     * @param pTemplate template for derived secret key
     * @param ulAttributeCount number of template attributes
     * @param pEncapsulatedKey receives encapsulated key bytes (optional: null for size query)
     * @param pulEncapsulatedKeyLen in/out length of encapsulated key buffer
     * @param phKey receives handle of derived secret key
     * @return CKR
     */
    public long C_EncapsulateKey(long hSession, CKM pMechanism, long hPublicKey,
            CKA[] pTemplate, long ulAttributeCount,
            byte[] pEncapsulatedKey, LongRef pulEncapsulatedKeyLen,
            LongRef phKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_pulEncapsulatedKeyLen = NLP(pulEncapsulatedKeyLen.value);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = jnaNative.C_EncapsulateKey(NL(hSession), jna_pMechanism, NL(hPublicKey),
                jna_pTemplate, NL(ulAttributeCount),
                pEncapsulatedKey, jna_pulEncapsulatedKeyLen,
                jna_phKey);
        pulEncapsulatedKeyLen.value = jna_pulEncapsulatedKeyLen.getValue().longValue();
        phKey.value = jna_phKey.getValue().longValue();
        return rv;
    }

    /**
     * Performs KEM decapsulation, consuming encapsulated key bytes and producing a derived secret key object.
     * @param hSession the session's handle
     * @param pMechanism KEM mechanism
     * @param hPrivateKey handle of recipient private key
     * @param pEncapsulatedKey encapsulated key bytes
     * @param ulEncapsulatedKeyLen length of encapsulated key bytes
     * @param pTemplate template for derived secret key
     * @param ulAttributeCount number of template attributes
     * @param phKey receives handle of derived secret key
     * @return CKR
     */
    public long C_DecapsulateKey(long hSession, CKM pMechanism, long hPrivateKey,
            byte[] pEncapsulatedKey, long ulEncapsulatedKeyLen,
            CKA[] pTemplate, long ulAttributeCount, LongRef phKey) {
        JNA_CKM jna_pMechanism = new JNA_CKM().readFrom(pMechanism);
        Template jna_pTemplate = new Template(pTemplate);
        NativeLongByReference jna_phKey = NLP(phKey.value);
        long rv = jnaNative.C_DecapsulateKey(NL(hSession), jna_pMechanism, NL(hPrivateKey),
                pEncapsulatedKey, NL(ulEncapsulatedKeyLen),
                jna_pTemplate, NL(ulAttributeCount), jna_phKey);
        phKey.value = jna_phKey.getValue().longValue();
        return rv;
    }

    private static NativeLong NL(long l) { return new NativeLong(l); }
    private static NativeLongByReference NLP(long l) { return new NativeLongByReference(new NativeLong(l)); }
}
