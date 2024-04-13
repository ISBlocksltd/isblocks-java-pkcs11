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
 * CKO_? constants.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CKO {

    public static final long DATA                = 0x00000000;
    public static final long CERTIFICATE         = 0x00000001;
    public static final long PUBLIC_KEY          = 0x00000002;
    public static final long PRIVATE_KEY         = 0x00000003;
    public static final long SECRET_KEY          = 0x00000004;
    public static final long HW_FEATURE          = 0x00000005;
    public static final long DOMAIN_PARAMETERS   = 0x00000006;
    public static final long MECHANISM           = 0x00000007;
    public static final long OTP_KEY             = 0x00000008;

    // Vendor defined values
    // Eracom PTK 
    public static final long VENDOR_PTK_CERTIFICATE_REQUEST  = 0x80000201;
    public static final long VENDOR_PTK_CRL                  = 0x80000202;
    public static final long VENDOR_PTK_ADAPTER              = 0x8000020a;
    public static final long VENDOR_PTK_SLOT                 = 0x8000020b;
    public static final long VENDOR_PTK_FM                   = 0x8000020c;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKO.class);
    /**
     * Convert long constant value to name.
     * @param cko value
     * @return name
     */
    public static final String L2S(long cko) { return C.l2s(L2S, CKO.class.getSimpleName(), cko); }
}
