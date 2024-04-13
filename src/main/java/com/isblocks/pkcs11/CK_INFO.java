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
 * PKCS#11 CK_INFO struct.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CK_INFO {

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_INFO.class);
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

    public CK_VERSION cryptokiVersion = new CK_VERSION();
    public byte[] manufacturerID = new byte[32];
    public long flags;
    public byte[] libraryDescription = new byte[32];
    public CK_VERSION libraryVersion = new CK_VERSION();

    /** To DO:
     *  @return string */
    public String toString() {
        return String.format("(\n  version=%d.%d\n  manufacturerID=%s\n  flags=0x%08x{%s}\n  libraryDescription=%s\n  libraryVersion=%d.%d\n)",
                cryptokiVersion.major & 0xff, cryptokiVersion.minor & 0xff, Buf.escstr(manufacturerID),
                flags, f2s(flags), Buf.escstr(libraryDescription),
                libraryVersion.major & 0xff, libraryVersion.minor & 0xff);

    }
}
