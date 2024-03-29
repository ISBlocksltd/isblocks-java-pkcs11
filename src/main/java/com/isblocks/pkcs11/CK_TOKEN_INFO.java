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

package com.isblocks.pkcs11;

import java.util.Map;

/**
 * PKCS#11 CK_TOKEN_INFO struct.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CK_TOKEN_INFO {
    public static final long CKF_RNG                   = 0x00000001;
    public static final long CKF_WRITE_PROTECTED       = 0x00000002;
    public static final long CKF_LOGIN_REQUIRED        = 0x00000004;
    public static final long CKF_USER_PIN_INITIALIZED  = 0x00000008;
    public static final long CKF_RESTORE_KEY_NOT_NEEDED=  0x00000020;
    public static final long CKF_CLOCK_ON_TOKEN        =  0x00000040;
    public static final long CKF_PROTECTED_AUTHENTICATION_PATH =0x00000100;
    public static final long CKF_DUAL_CRYPTO_OPERATIONS  =0x00000200;
    public static final long CKF_TOKEN_INITIALIZED       =0x00000400;
    public static final long CKF_SECONDARY_AUTHENTICATION = 0x00000800;
    public static final long CKF_USER_PIN_COUNT_LOW       =0x00010000;
    public static final long CKF_USER_PIN_FINAL_TRY       =0x00020000;
    public static final long CKF_USER_PIN_LOCKED          =0x00040000;
    public static final long CKF_USER_PIN_TO_BE_CHANGED   =0x00080000;
    public static final long CKF_SO_PIN_COUNT_LOW         =0x00100000;
    public static final long CKF_SO_PIN_FINAL_TRY         =0x00200000;
    public static final long CKF_SO_PIN_LOCKED            =0x00400000;
    public static final long CKF_SO_PIN_TO_BE_CHANGED     =0x00800000;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_TOKEN_INFO.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String L2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }

    public byte[] label = new byte[32];
    public byte[] manufacturerID = new byte[32];
    public byte[] model = new byte[16];
    public byte[] serialNumber = new byte[16];
    public long flags;
    public long ulMaxSessionCount;
    public long ulSessionCount;
    public long ulMaxRwSessionCount;
    public long ulRwSessionCount;
    public long ulMaxPinLen;
    public long ulMinPinLen;
    public long ulTotalPublicMemory;
    public long ulFreePublicMemory;
    public long ulTotalPrivateMemory;
    public long ulFreePrivateMemory;
    public CK_VERSION hardwareVersion = new CK_VERSION();
    public CK_VERSION firmwareVersion = new CK_VERSION();
    public byte[] utcTime = new byte[16];

    /** To Do:
     * @return True, if the provided flag is set */
    public boolean isFlagSet(long CKF_FLAG) {
        return (flags & CKF_FLAG) != 0L;
    }
    
    /** To Do:
     * @return string */
    public String toString() {
        return String.format("(\n  label=%s\n  manufacturerID=%s\n  model=%s\n  serialNumber=%s\n  flags=0x%08x{%s}" +
                "\n  maxSessionCount=%d\n  sessionCount=%d\n  maxRwSessionCount=%d\n  rwSessionCount=%d" +
                "\n  maxPinLen=%d\n  minPinLen=%d\n  totalPublicMemory=%d\n  freePublicMemory=%d" +
                "\n  totalPrivateMemory=%d\n  freePrivateMemory=%d" +
                "\n  hardwareVersion=%d.%d\n  firmwareVersion=%d.%d\n  utcTime=%s\n)",
                Buf.escstr(label), Buf.escstr(manufacturerID), Buf.escstr(model), Buf.escstr(serialNumber),
                flags, f2s(flags), ulMaxSessionCount, ulSessionCount,
                ulMaxRwSessionCount, ulRwSessionCount,
                ulMaxPinLen, ulMinPinLen,
                ulTotalPublicMemory, ulFreePublicMemory,
                ulTotalPrivateMemory, ulFreePrivateMemory,
                hardwareVersion.major & 0xff, hardwareVersion.minor & 0xff,
                firmwareVersion.major & 0xff, firmwareVersion.minor & 0xff,
                Buf.escstr(utcTime));
    }
}
