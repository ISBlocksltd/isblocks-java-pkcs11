
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
 * PKCS#11 CK_MECHANSIM_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_MECHANISM_INFO {
    public static final long CKF_HW                  = 0x00000001;
    public static final long CKF_ENCRYPT             = 0x00000100;
    public static final long CKF_DECRYPT             = 0x00000200;
    public static final long CKF_DIGEST              = 0x00000400;
    public static final long CKF_SIGN                = 0x00000800;
    public static final long CKF_SIGN_RECOVER        = 0x00001000;
    public static final long CKF_VERIFY              = 0x00002000;
    public static final long CKF_VERIFY_RECOVER      = 0x00004000;
    public static final long CKF_GENERATE            = 0x00008000;
    public static final long CKF_GENERATE_KEY_PAIR   = 0x00010000;
    public static final long CKF_WRAP                = 0x00020000;
    public static final long CKF_UNWRAP              = 0x00040000;
    public static final long CKF_DERIVE              = 0x00080000;
    public static final long CKF_EC_F_P              = 0x00100000;
    public static final long CKF_EC_F_2M             = 0x00200000;
    public static final long CKF_EC_ECPARAMETERS     = 0x00400000;
    public static final long CKF_EC_NAMEDCURVE       = 0x00800000;
    public static final long CKF_EC_UNCOMPRESS       = 0x01000000;
    public static final long CKF_EC_COMPRESS         = 0x02000000;
    public static final long CKF_EXTENSION           = 0x80000000;


    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_MECHANISM_INFO.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String I2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }


    public long ulMinKeySize;
    public long ulMaxKeySize;
    public long flags;

    /**To Do:
     *  @return True, if the provided flag is set */
    public boolean isFlagSet(long CKF_FLAG) {
        return (flags & CKF_FLAG) != 0L;
    }
    
    /** To Do:
     * @return string */
    public String toString() {
        return String.format("(\n  minKeySize=%d\n  maxKeySize=%d\n  flags=0x%08x{%s}\n)",
                ulMinKeySize, ulMaxKeySize, flags, f2s(flags));

    }
}
