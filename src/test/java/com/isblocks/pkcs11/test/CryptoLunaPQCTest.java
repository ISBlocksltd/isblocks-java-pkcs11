/*************************************************************************
 *  Copyright 2021 IS Blocks, Ltd. and/or its affiliates 				 *
 *  and other contributors as indicated by the @author tags.	         *
 *																		 *
 *  All rights reserved													 *
 * 																		 *
 *  The use of this Proprietary Software are subject to specific         *
 *  commercial license terms											 *
 * 																		 *
 *  To purchase a licence agreement for any use of this code please 	 *
 *  contact info@isblocks.com 											 *
 *																		 *
 *  Unless required by applicable law or agreed to in writing, software  *
 *  distributed under the License is distributed on an "AS IS" BASIS,    *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      *
 *  implied.															 *
 *  See the License for the specific language governing permissions and  *
 *  limitations under the License.                                       *
 *                                                                       *
 *************************************************************************/

 /**
 * JUnit tests for isblocks-pkcs11
 * Tests all the cryptoki functions using the Thales Luna 7 HSM
 * The functions not tested are in commented lines.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
 package com.isblocks.pkcs11.test;
 import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.isblocks.pkcs11.Buf;
import com.isblocks.pkcs11.C;
import com.isblocks.pkcs11.CE;
import com.isblocks.pkcs11.CKA;
import com.isblocks.pkcs11.CKG;
import com.isblocks.pkcs11.CKK;
import com.isblocks.pkcs11.CKM;
import com.isblocks.pkcs11.CKO;
import com.isblocks.pkcs11.CKP;
import com.isblocks.pkcs11.CKR;
import com.isblocks.pkcs11.CKRException;
import com.isblocks.pkcs11.CKU;
import com.isblocks.pkcs11.CK_INFO;
import com.isblocks.pkcs11.CK_MECHANISM_INFO;
import com.isblocks.pkcs11.CK_SESSION_INFO;
import com.isblocks.pkcs11.CK_SLOT_INFO;
import com.isblocks.pkcs11.CK_TOKEN_INFO;
import com.isblocks.pkcs11.Hex;
import com.isblocks.pkcs11.LongRef;
import com.isblocks.pkcs11.ULong;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import javax.security.auth.x500.X500Principal;
import com.isblocks.pkcs11.Buf;
import com.isblocks.pkcs11.C;
import com.isblocks.pkcs11.CE;
import com.isblocks.pkcs11.CKA;
import com.isblocks.pkcs11.CKK;
import com.isblocks.pkcs11.CKM;
import com.isblocks.pkcs11.CKO;
import com.isblocks.pkcs11.CKR;
import com.isblocks.pkcs11.CKRException;
import com.isblocks.pkcs11.CKU;
import com.isblocks.pkcs11.CK_SESSION_INFO;
import com.isblocks.pkcs11.Hex;
import com.isblocks.pkcs11.LongRef;
import com.isblocks.pkcs11.jna.JNA;
import java.io.ByteArrayOutputStream;

 public class CryptoLunaPQCTest {

    static long session;
	long[] slots;
	int slotId;
	byte[] password;
	String library;

    @BeforeAll
    public static void setUp() {

        C.NATIVE = new com.isblocks.pkcs11.jna.JNA("C:\\Program Files\\SafeNet\\LunaClient\\cklog201.dll");
        String testSlotEnv = "0";
        String soPinEnv = "1234567";
        String UserPinEnv = "Thales12345!";
        
        if(!CE.isInitialized()) {
            CE.Initialize();
			long[] slots = CE.GetSlotList(true);

			session = CE.OpenSession(slots[0], (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);        
			CE.Login(session, CKU.USER, "Thales12345!".getBytes());
			System.out.println(CE.GetSessionInfo(session));
			//CE.Login(this.session, CKU.USER, this.password);
			System.out.println("Logged into the HSM");
	
	        
		}
    }

    @AfterAll
    static public void tearDown() {
        CE.Finalize();

    }

    @Test
    public void testGetInfo() {
        CK_INFO info = new CK_INFO();
        CE.GetInfo(info);
        System.out.println(info);
    }

    @Test
    public void testEncryptDecryptCBCPAD() {

        long aeskey = CE.GenerateKey(session, 
                    new CKM(CKM.AES_KEY_GEN),
					new CKA(CKA.VALUE_LEN, 32),
					new CKA(CKA.LABEL, "label"),
					new CKA(CKA.ID, "uuid.toString()"),
					new CKA(CKA.CLASS, CKO.SECRET_KEY),
					new CKA(CKA.PRIVATE, true),
					new CKA(CKA.EXTRACTABLE, true),
					new CKA(CKA.MODIFIABLE, true),
					new CKA(CKA.TOKEN, false),
					new CKA(CKA.SENSITIVE, true),
					new CKA(CKA.ENCRYPT, true),
					new CKA(CKA.DECRYPT, true),
					new CKA(CKA.WRAP, false),
					new CKA(CKA.UNWRAP, false));

        System.out.println("Session: " + session);
        if (session == 0) {
            throw new IllegalStateException("Session is not initialized.");
        }
        System.out.println("AES Key: " + aeskey);
        if (aeskey == 0) {
            throw new IllegalStateException("AES key is not initialized.");
        }
        // Generate a valid IV
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        CKM mechanism = new CKM(CKM.AES_CBC_PAD, iv);

        byte[] plaintext = "Hello, World!123".getBytes(StandardCharsets.UTF_8);



        LongRef ref = new LongRef();
        LongRef ref2 = new LongRef();
        new SecureRandom().nextBytes(iv);

        //CE.EncryptInit(session, mechanism, aeskey);
        CE.EncryptInit(session, mechanism, aeskey);
        byte [] encrypted1 = CE.EncryptPad(session, plaintext);

        CE.DecryptInit(session, mechanism, aeskey);
        byte [] plaintext1 = CE.DecryptPad(session, encrypted1);

        System.out.println(new String(plaintext1,StandardCharsets.UTF_8) + " "+ new String(plaintext, StandardCharsets.UTF_8));
    }

    @Test
    @Disabled
    public void testGenerateMLDSA()  {

        long mldsaParams = CKP.CKP_ML_DSA_44;
        String label = "Test ML-DSA Key 44" + UUID.randomUUID().toString();
        byte keyID[] = label.getBytes();

        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.PARAMETER_SET, mldsaParams),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, false),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, label +"-public"),
            new CKA(CKA.ID, keyID),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, false),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, label + "-private"),
            new CKA(CKA.ID, keyID),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        final byte[] rawPoint;
        System.out.println(this.session);
        CE.GenerateKeyPair(this.session, new CKM(CKM.ML_DSA_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        System.out.println("Thales ML-DSA key: Generated Key");
        //CE.GenerateKeyPair(session, new CKM(CKM.CKM, pubTempl, privTempl, pubKey, privKey);
        final CKA[] pubEDKey = CE.GetAttributeValue(session, pubKey.value(), new long[] {CKA.EC_PARAMS, CKA.EC_POINT });
        /* 
        CK_MECHANISM mech = {CKM_ML_DSA_KEY_PAIR_GEN};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
	    CK_OBJECT_CLASS objClassPub = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS objClassPri = CKO_PRIVATE_KEY;

    	inputKeyLabel();
	    inputParameter();

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
                {CKA_CLASS,             &objClassPub,   sizeof(CK_OBJECT_CLASS)},
                {CKA_PRIVATE,           &no,	        sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &yes,           sizeof(CK_BBOOL)},
	        	{CKA_PARAMETER_SET,	&paramType,	sizeof(CK_ML_DSA_PARAMETER_SET_TYPE)},
                {CKA_LABEL,             pubKeyLabel,    labelLen-1}
        };
        CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,        	sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClassPri,   sizeof(CK_OBJECT_CLASS)},
	        	{CKA_LABEL,             privKeyLabel,   labelLen-1}
        };
        CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri), "C_GenerateKeyPair");
        printf("\n> ML-DSA keypair generated.\n");
        printf("  --> Private key handle : %lu\n", objHandlePri);
        printf("  --> Public key handle : %lu\n", objHandlePub);
        */
    }


    
    @Test
    @Disabled
    public void testGenerateMLKEMKeyGen()  {

        long mldsaParams = CKP.CKP_ML_KEM_512;
        String label = "Test ML-KEM Key 512" + UUID.randomUUID().toString();
        byte keyID[] = label.getBytes();

        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.PARAMETER_SET, mldsaParams),
            new CKA(CKA.WRAP, false),
            new CKA(CKA.ENCRYPT, false),
            new CKA(CKA.VERIFY, true),
            new CKA(CKA.VERIFY_RECOVER, false),
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.LABEL, label +"-public"),
            new CKA(CKA.ID, keyID),
        };
        CKA[] privTempl = new CKA[] {
            new CKA(CKA.TOKEN, true),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SIGN_RECOVER, false),
            new CKA(CKA.DECRYPT, false),
            new CKA(CKA.UNWRAP, false),
            new CKA(CKA.EXTRACTABLE, false),
            new CKA(CKA.LABEL, label + "-private"),
            new CKA(CKA.ID, keyID),
        };
        LongRef pubKey = new LongRef();
        LongRef privKey = new LongRef();
        final byte[] rawPoint;
        System.out.println(this.session);
        CE.GenerateKeyPair(this.session, new CKM(CKM.ML_KEM_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        System.out.println("Thales ML-DSA key: Generated Key");
        //CE.GenerateKeyPair(session, new CKM(CKM.CKM, pubTempl, privTempl, pubKey, privKey);
        final CKA[] pubEDKey = CE.GetAttributeValue(session, pubKey.value(), new long[] {CKA.EC_PARAMS, CKA.EC_POINT });
        /* 
        CK_MECHANISM mech = {CKM_ML_DSA_KEY_PAIR_GEN};
        CK_BBOOL yes = CK_TRUE;
        CK_BBOOL no = CK_FALSE;
	    CK_OBJECT_CLASS objClassPub = CKO_PUBLIC_KEY;
        CK_OBJECT_CLASS objClassPri = CKO_PRIVATE_KEY;

    	inputKeyLabel();
	    inputParameter();

        CK_ATTRIBUTE attribPub[] =
        {
                {CKA_TOKEN,             &no,            sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
                {CKA_CLASS,             &objClassPub,   sizeof(CK_OBJECT_CLASS)},
                {CKA_PRIVATE,           &no,	        sizeof(CK_BBOOL)},
                {CKA_VERIFY,            &yes,           sizeof(CK_BBOOL)},
	        	{CKA_PARAMETER_SET,	&paramType,	sizeof(CK_ML_DSA_PARAMETER_SET_TYPE)},
                {CKA_LABEL,             pubKeyLabel,    labelLen-1}
        };
        CK_ULONG attribPubLen = sizeof(attribPub) / sizeof(*attribPub);

        CK_ATTRIBUTE attribPri[] =
        {
                {CKA_TOKEN,             &no,        	sizeof(CK_BBOOL)}, // Change to yes to generate a token object.
                {CKA_PRIVATE,           &yes,           sizeof(CK_BBOOL)},
                {CKA_SENSITIVE,         &yes,           sizeof(CK_BBOOL)},
                {CKA_MODIFIABLE,        &no,            sizeof(CK_BBOOL)},
                {CKA_EXTRACTABLE,       &no,            sizeof(CK_BBOOL)},
                {CKA_SIGN,              &yes,           sizeof(CK_BBOOL)},
                {CKA_CLASS,             &objClassPri,   sizeof(CK_OBJECT_CLASS)},
	        	{CKA_LABEL,             privKeyLabel,   labelLen-1}
        };
        CK_ULONG attribPriLen = sizeof(attribPri) / sizeof(*attribPri);

        checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, attribPub, attribPubLen, attribPri, attribPriLen, &objHandlePub, &objHandlePri), "C_GenerateKeyPair");
        printf("\n> ML-DSA keypair generated.\n");
        printf("  --> Private key handle : %lu\n", objHandlePri);
        printf("  --> Public key handle : %lu\n", objHandlePub);
        */
    }
        // Signs a plaintext using ML-DSA private key.
        /*void signData()
        {
            initParam();
            CK_MECHANISM mech = {CKM_ML_DSA, &optionalParam, sizeof(optionalParam)};
            checkOperation(p11Func->C_SignInit(hSession, &mech, objPrikey), "C_SignInit");
            checkOperation(p11Func->C_Sign(hSession, plainText, sizeof(plainText)-1, NULL, &signatureLen), "C_Sign");
            signature = (CK_BYTE*)malloc(signatureLen);
            checkOperation(p11Func->C_Sign(hSession, plainText, sizeof(plainText)-1, signature, &signatureLen), "C_Sign");
            printf("\n> Plaintext signed.\n");
            printf("  --> Signature Length : %ld.\n", signatureLen);
        }



        // Verifies signature
        void verifyData()
        {
            CK_MECHANISM mech = {CKM_ML_DSA, &optionalParam, sizeof(optionalParam)};
            checkOperation(p11Func->C_VerifyInit(hSession, &mech, objPubkey), "C_VerifyInit");
            checkOperation(p11Func->C_Verify(hSession, plainText, sizeof(plainText)-1, signature, signatureLen), "C_Verify");
            printf("\n> Signature Verified.");
        }*/

}
