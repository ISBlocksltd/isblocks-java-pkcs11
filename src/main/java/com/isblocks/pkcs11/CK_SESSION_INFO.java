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
 * PKCS#11 CK_SESSION_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_SESSION_INFO {

    public static final long CKF_RW_SESSION     = 0x00000002;
    public static final long CKF_SERIAL_SESSION = 0x00000004;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_SESSION_INFO.class);
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

    public long slotID;
    public long state;
    public long flags;
    public long ulDeviceError;

    /** To Do:
     * @return True, if the provided flag is set */
    public boolean isFlagSet(long CKF_FLAG) {
        return (flags & CKF_FLAG) != 0L;
    }
    
    /** To DO:
     * @return string */
    public String toString() {
        return String.format("(\n  slotID=0x%08x\n  state=0x%08x{%s}\n  flags=0x%08x{%s}\n  deviceError=%d\n)",
                slotID, state, CKS.L2S(state), flags, f2s(flags), ulDeviceError);
    }
}