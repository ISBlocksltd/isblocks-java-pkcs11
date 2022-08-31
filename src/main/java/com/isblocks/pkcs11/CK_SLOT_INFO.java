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
 * PKCS#11 CK_SLOT_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_SLOT_INFO {

    public static final long CKF_TOKEN_PRESENT    = 0x00000001;
    public static final long CKF_REMOVABLE_DEVICE = 0x00000002;
    public static final long CKF_HW_SLOT          = 0x00000004;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_SLOT_INFO.class);
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

    public byte[] slotDescription = new byte[64];
    public byte[] manufacturerID = new byte[32];
    public long flags;
    public CK_VERSION hardwareVersion = new CK_VERSION();
    public CK_VERSION firmwareVersion = new CK_VERSION();

    /** To Do:
     *  @return True, if the provided flag is set */
    public boolean isFlagSet(long CKF_FLAG) {
        return (flags & CKF_FLAG) != 0L;
    }
    
    /** To Do:
   @return string */
    public String toString() {
        return String.format("(\n  slotDescription=%s\n  manufacturerID=%s\n  flags=0x%08x{%s}\n  hardwareVersion=%d.%d\n  firmwareVersion=%d.%d\n)",
                Buf.escstr(slotDescription), Buf.escstr(manufacturerID), flags, f2s(flags),
                hardwareVersion.major & 0xff, hardwareVersion.minor & 0xff,
                firmwareVersion.major & 0xff, firmwareVersion.minor & 0xff);
    }
}
