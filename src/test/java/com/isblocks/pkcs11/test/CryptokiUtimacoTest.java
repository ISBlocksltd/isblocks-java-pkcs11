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
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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


/**
 * JUnit tests for isblocks-pkcs11
 * Tests all the cryptoki functions using the Utimaco Simulator
 * The functions not tested are in commented lines.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
@Disabled
public class CryptokiUtimacoTest {

	static long session;
	static long[] slots;
	static int slotId;
	static byte[] password;
	static String library;
	
    @BeforeAll
    public static void setUp() {
        // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such as:
        // C.NATIVE = new com.isblocks.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new com.isblocks.jffi.JFFI();
		if(!CE.isInitialized()) {
			
			long[] slots = CE.GetSlotList(true);
			
			session = CE.OpenSession(slots[slotId], (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);        
			CE.Login(session, CKU.USER, "123456".getBytes());
			CE.GetSessionInfo(session);
			//CE.Login(this.session, CKU.USER, this.password);
			System.out.println("Logged into the HSM");
	        CE.Initialize();
		}
    }
    
    @AfterAll
    public static void tearDown() {
        CE.Finalize();
    }

    @Test
    public void testSetUp1() throws IOException{
    	  // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such as:
        // C.NATIVE = new com.isblocks.pkcs11.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new com.isblocks.pkcs11.jffi.JFFI();
        
		if(!CE.isInitialized()) {
			long[] slots = CE.GetSlotList(true);
			CE.Logout(session);
			session = CE.OpenSession(slots[slotId], (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);        
			CE.Login(session, CKU.USER, "123456".getBytes());
			System.out.println(CE.GetSessionInfo(session));
			//CE.Login(this.session, CKU.USER, this.password);
			System.out.println("Logged into the HSM");
	        CE.Initialize();
	        
		}
		
			
		
    }
    
    @Test
    public void testSetUp2() throws IOException{
    	  // Library path can be set with JACKNJI11_PKCS11_LIB_PATH, or done in code such as:
        // C.NATIVE = new com.isblocks.pkcs11.jna.JNA("/usr/lib/softhsm/libsofthsm2.so");
        // Or JFFI can be used rather than JNA:
        // C.NATIVE = new com.isblocks.pkcs11.jffi.JFFI();
		if(!CE.isInitialized()) {
			long[] slots = CE.GetSlotList(true);
			CE.Logout(this.session);
			this.session = CE.OpenSession(slots[this.slotId], (CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION), null, null);        
			
            //Option 1 for loggin in using a password; 123456
            //CE.Login(this.session, CKU.USER, "123456".getBytes());
			
            //Option 2 for loggin in using a quorum of 2/3 hsm user cards
            CE.Login(this.session, CKU.USER, "hsmusr1,:cs2:auth:USB0".getBytes());
			CE.Login(this.session, CKU.USER, "hsmusr2,:cs2:auth:USB0".getBytes());
			System.out.println(CE.GetSessionInfo(this.session));
			//CE.Login(this.session, CKU.USER, this.password);
			System.out.println("Logged into the HSM");
	        CE.Initialize();
	        
		}
		
    }
    
    @Test
    void testGenerateEDDSAonUtimaco() throws IOException{
		
    	String keyID = "123456";
    	String label = "label1";
        // CKM_EC_EDWARDS_KEY_PAIR_GEN
        /*
            The mechanism can only generate EC public/private key pairs over the curves edwards25519 and edwards448 as defined in RFC 8032 or the curves 
            id-Ed25519 and id-Ed448 as defined in RFC 8410. These curves can only be specified in the CKA_EC_PARAMS attribute of the template for the 
            public key using the curveName or the oID methods 
        */
        // CKM_EDDSA (signature mechanism)
        /*
            CK_EDDSA_PARAMS is a structure that provides the parameters for the CKM_EDDSA signature mechanism.  The structure is defined as follows:
            typedef struct CK_EDDSA_PARAMS {
                CK_BBOOL     phFlag;
                CK_ULONG     ulContextDataLen;
                CK_BYTE_PTR  pContextData;
            }  CK_EDDSA_PARAMS
        */
        // CK_EDDSA_PARAMS (no params means Ed25519 in keygen?)
        // CK_EDDSA_PARAMS_PTR is a pointer to a CK_EDDSA_PARAMS
        // CKK_EC_EDWARDS (private and public key)
        
        // Attributes from PKCS #11 Cryptographic Token Interface Current Mechanisms Specification Version 2.40 section 2.3.3 - ECDSA public key objects
        /* DER-encoding of an ANSI X9.62 Parameters, also known as "EC domain parameters". */
        // We use a Ed25519 key, the oid 1.3.101.112 has DER encoding in Hex 06032b6570

    	String hexAlgorithm = "060A2B060104019857020301";
    		
  		
   
        byte[] ecCurveParams = Hex.s2b(hexAlgorithm);
        byte[] ecCurveParams1 = "edwards25519".getBytes();
        CKA[] pubTempl = new CKA[] {
            new CKA(CKA.EC_PARAMS, ecCurveParams1),
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
        CE.GenerateKeyPair(this.session, new CKM(CKM.EC_KEY_PAIR_GEN), pubTempl, privTempl, pubKey, privKey);
        System.out.println("Utimaco key: Generated Key");
        //CE.GenerateKeyPair(session, new CKM(CKM.CKM, pubTempl, privTempl, pubKey, privKey);
        final CKA[] pubEDKey = CE.GetAttributeValue(session, pubKey.value(), new long[] {CKA.EC_PARAMS, CKA.EC_POINT });
        

	}

}
