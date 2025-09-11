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
 * CKP_? constants.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CKP {
    public static final long CKP_PKCS5_PBKD2_HMAC_SHA1 = 0x00000001;

    /* ML-DSA values for CKA_PARAMETER_SETS */
    public static final long CKP_ML_DSA_44          = 0x00000001;
    public static final long CKP_ML_DSA_65          = 0x00000002;
    public static final long CKP_ML_DSA_87          = 0x00000003;

    /* SLH-DSA values for CKA_PARAMETER_SETS */
    public static final long CKP_SLH_DSA_SHA2_128S  = 0x00000001;
    public static final long CKP_SLH_DSA_SHAKE_128S = 0x00000002;
    public static final long CKP_SLH_DSA_SHA2_128F  = 0x00000003;
    public static final long CKP_SLH_DSA_SHAKE_128F = 0x00000004;
    public static final long CKP_SLH_DSA_SHA2_192S  = 0x00000005;
    public static final long CKP_SLH_DSA_SHAKE_192S = 0x00000006;
    public static final long CKP_SLH_DSA_SHA2_192F  = 0x00000007;
    public static final long CKP_SLH_DSA_SHAKE_192F = 0x00000008;
    public static final long CKP_SLH_DSA_SHA2_256S  = 0x00000009;
    public static final long CKP_SLH_DSA_SHAKE_256S = 0x0000000a;
    public static final long CKP_SLH_DSA_SHA2_256F  = 0x0000000b;
    public static final long CKP_SLH_DSA_SHAKE_256F = 0x0000000c;

    /* ML-KEM values for CKA_PARAMETER_SETS */
    public static final long CKP_ML_KEM_512         = 0x00000001;
    public static final long CKP_ML_KEM_768         = 0x00000002;
    public static final long CKP_ML_KEM_1024        = 0x00000003;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CKP.class);
    /**
     * Convert long constant value to name.
     * @param ckp value
     * @return name
     */
    public static final String L2S(long ckp) { return C.l2s(L2S, CKP.class.getSimpleName(), ckp); }
}
 