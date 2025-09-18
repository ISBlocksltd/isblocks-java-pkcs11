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
package com.isblocks.pkcs11.jna;

import java.util.Arrays;
import java.util.List;

import com.isblocks.pkcs11.CK_GCM_PARAMS;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_GCM_PARAMS struct.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JNA_CK_GCM_PARAMS extends Structure {
    public Pointer pIv;
    public NativeLong ulIvLen;
    public NativeLong ulIvBits;
    public Pointer pAAD;
    public NativeLong ulAADLen;
    public NativeLong ulTagBits;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("pIv", "ulIvLen", "ulIvBits", "pAAD", "ulAADLen", "ulTagBits");
    }

    /**
     * Convert from CK_GCM_PARAMS to JNA_CK_GCM_PARAMS
     * @param params CK_GCM_PARAMS  
     * @return this JNA_CK_GCM_PARAMS instance
     */
    public JNA_CK_GCM_PARAMS readFrom(CK_GCM_PARAMS params) {
        pIv = params.pIv;
        ulIvLen = params.ulIvLen;
        ulIvBits = params.ulIvBits;
        pAAD = params.pAAD;
        ulAADLen = params.ulAADLen;
        ulTagBits = params.ulTagBits;
        return this;
    }

    /**
     * Convert from JNA_CK_GCM_PARAMS to CK_GCM_PARAMS
     * @param params CK_GCM_PARAMS  
     * @return params
     */
    public CK_GCM_PARAMS writeTo(CK_GCM_PARAMS params) {
        params.pIv = pIv;
        params.ulIvLen = ulIvLen;
        params.ulIvBits = ulIvBits;
        params.pAAD = pAAD;
        params.ulAADLen = ulAADLen;
        params.ulTagBits = ulTagBits;
        return params;
    }
}
