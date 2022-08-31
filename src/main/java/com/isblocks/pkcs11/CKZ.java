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
 * CKZ_? constants.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CKZ {
    public static final long DATA_SPECIFIED = 0x00000001;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKZ.class);
    /**
     * Convert long constant value to name.
     * @param ckz value
     * @return name
     */
    public static final String L2S(long ckz) { return C.l2s(L2S, CKZ.class.getSimpleName(), ckz); }
}
