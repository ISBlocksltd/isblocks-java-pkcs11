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
 * CKG_? constants.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CKG {
    public static final long MGF1_SHA1   = 0x00000001;
    public static final long MGF1_SHA256 = 0x00000002;
    public static final long MGF1_SHA384 = 0x00000003;
    public static final long MGF1_SHA512 = 0x00000004;
    public static final long MGF1_SHA224 = 0x00000005;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKG.class);
    /**
     * Convert long constant value to name.
     * @param ckg value
     * @return name
     */
    public static final String L2S(long ckg) { return C.l2s(L2S, CKG.class.getSimpleName(), ckg); }
}
  