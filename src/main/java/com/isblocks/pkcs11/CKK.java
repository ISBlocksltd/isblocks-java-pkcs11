/*/*************************************************************************
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

package com.isblocks.pkcs11;

import java.util.Map;
 
/**
 * CKK_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKK {

    public static final long RSA             = 0x00000000;
    public static final long DSA             = 0x00000001;
    public static final long DH              = 0x00000002;
    public static final long EC              = 0x00000003;
    public static final long X9_42_DH        = 0x00000004;
    public static final long KEA             = 0x00000005;
    public static final long GENERIC_SECRET  = 0x00000010;
    public static final long RC2             = 0x00000011;
    public static final long RC4             = 0x00000012;
    public static final long DES             = 0x00000013;
    public static final long DES2            = 0x00000014;
    public static final long DES3            = 0x00000015;
    public static final long CAST            = 0x00000016;
    public static final long CAST3           = 0x00000017;
    public static final long CAST128         = 0x00000018;
    public static final long RC5             = 0x00000019;
    public static final long IDEA            = 0x0000001a;
    public static final long SKIPJACK        = 0x0000001b;
    public static final long BATON           = 0x0000001c;
    public static final long JUNIPER         = 0x0000001d;
    public static final long CDMF            = 0x0000001e;
    public static final long AES             = 0x0000001f;
    public static final long SECURID         = 0x00000022;
    public static final long HOTP            = 0x00000023;
    public static final long ACTI            = 0x00000024;
    public static final long CAMELLIA        = 0x00000025;
    public static final long ARIA            = 0x00000026;
    public static final long MD5_HMAC        = 0x00000027;
    public static final long SHA_1_HMAC      = 0x00000028;
    public static final long RIPEMD128_HMAC  = 0x00000029;
    public static final long RIPEMD160_HMAC  = 0x0000002a;
    public static final long SHA256_HMAC     = 0x0000002b;
    public static final long SHA384_HMAC     = 0x0000002c;
    public static final long SHA512_HMAC     = 0x0000002d;
    public static final long SHA224_HMAC     = 0x0000002e;
    public static final long SEED            = 0x0000002f;
    public static final long GOSTR3410       = 0x00000030;
    public static final long GOSTR3411       = 0x00000031;
    public static final long GOST28147       = 0x00000032;
    public static final long CKK_EC_EDWARDS  = 0x00000040;

    // Vendor defined values
    // Eracom PTK
    public static final long VENDOR_PTK_RSA_DISCRETE    = 0x80000201L;
    public static final long VENDOR_PTK_DSA_DISCRETE    = 0x80000202L;
    public static final long VENDOR_PTK_SEED            = 0x80000203L;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKK.class);
    /**
     * Convert long constant value to name.
     * @param ckk value
     * @return name
     */
    public static final String L2S(long ckk) { return C.l2s(L2S, CKK.class.getSimpleName(), ckk); }
}
