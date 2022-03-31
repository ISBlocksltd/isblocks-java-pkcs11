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
 * CKS_? (CK_STATE) constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKS {
    public static final long RO_PUBLIC_SESSION = 0;
    public static final long RO_USER_FUNCTIONS = 1;
    public static final long RW_PUBLIC_SESSION = 2;
    public static final long RW_USER_FUNCTIONS = 3;
    public static final long RW_SO_FUNCTIONS = 4;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKS.class);
    /**
     * Convert long constant value to name.
     * @param cks value
     * @return name
     */ 
    public static final String L2S(long cks) { return C.l2s(L2S, CKS.class.getSimpleName(), cks); }
}
