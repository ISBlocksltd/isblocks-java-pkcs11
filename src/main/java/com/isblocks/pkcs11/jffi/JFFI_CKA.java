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

import com.isblocks.pkcs11.CKA;

import jnr.ffi.Memory;
import jnr.ffi.Struct;

/**
 * JFFI CK_ATTRIBUTE wrapper.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CKA extends Struct {
    public long type;
    public jnr.ffi.Pointer pValue;
    public long ulValueLen;

    public JFFI_CKA() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }

    public JFFI_CKA readFrom(CKA cka) {
        type = cka.type;
        int len = cka.pValue != null ? cka.pValue.length : 0;
        if (len > 0) {
            pValue = Memory.allocate(jnr.ffi.Runtime.getSystemRuntime(), len);
            pValue.put(0, cka.pValue, 0, len);
        }
        ulValueLen = len;
        return this;
    }

    public CKA writeTo(CKA cka) {
        cka.type = (int) type;
        cka.ulValueLen = (int) ulValueLen;
        if (cka.ulValueLen > 0) {
            pValue.get(0, cka.pValue, 0, (int) cka.ulValueLen);
        }
        return cka;
    }
}
