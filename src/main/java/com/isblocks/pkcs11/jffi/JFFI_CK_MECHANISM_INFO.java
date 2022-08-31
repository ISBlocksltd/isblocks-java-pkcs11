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

package com.isblocks.pkcs11.jffi;

import com.isblocks.pkcs11.CK_MECHANISM_INFO;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_MECHANSIM_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_MECHANISM_INFO extends Struct {
    public long ulMinKeySize;
    public long ulMaxKeySize;
    public long flags;

    public JFFI_CK_MECHANISM_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }
  /**
     * TO DO:
     * @param info CK_MECHANISM_INFO  
     * @return 
     */
    public JFFI_CK_MECHANISM_INFO readFrom(CK_MECHANISM_INFO info) {
        ulMinKeySize = info.ulMinKeySize;
        ulMaxKeySize = info.ulMaxKeySize;
        flags = info.flags;
        return this;
    }
/**
     * TO DO:
     * @param info CK_INFO  
     * @return info
     */
    public CK_MECHANISM_INFO writeTo(CK_MECHANISM_INFO info) {
        info.ulMinKeySize = ulMinKeySize;
        info.ulMaxKeySize = ulMaxKeySize;
        info.flags = flags;
        return info;
    }
}
