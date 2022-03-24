/*/*************************************************************************
 *  Copyright 2021 IS Blocks, Ltd. and/or its affiliates 				 *
 *  and other contributors as indicated by the @author tags.	         *
 *																		 *
 *  All rights reserved													 *
 * 																		 *
 *  The use of this Proprietary Software are subject to specific         *
 *  commercial license terms											 *
 * 																		 *
 *  To purchase a licence agreement for any use of this code please 	 *
 *  contact info@isblocks.com 											 *
 *																		 *
 *  Unless required by applicable law or agreed to in writing, software  *
 *  distributed under the License is distributed on an "AS IS" BASIS,    *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      *
 *  implied.															 *
 *  See the License for the specific language governing permissions and  *
 *  limitations under the License.                                       *
 *                                                                       *
 *************************************************************************/
/*/*************************************************************************
 *  Copyright 2021 IS Blocks, Ltd. and/or its affiliates 				 *
 *  and other contributors as indicated by the @author tags.	         *
 *																		 *
 *  All rights reserved													 *
 * 																		 *
 *  The use of this Proprietary Software are subject to specific         *
 *  commercial license terms											 *
 * 																		 *
 *  To purchase a licence agreement for any use of this code please 	 *
 *  contact info@isblocks.com 											 *
 *																		 *
 *  Unless required by applicable law or agreed to in writing, software  *
 *  distributed under the License is distributed on an "AS IS" BASIS,    *
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or      *
 *  implied.															 *
 *  See the License for the specific language governing permissions and  *
 *  limitations under the License.                                       *
 *                                                                       *
 *************************************************************************/

package com.isblocks.pkcs11.jffi;

import jnr.ffi.Memory;
import jnr.ffi.Struct;

import com.isblocks.pkcs11.CKM;
import com.sun.jna.Native;

/**
 * JFFI CK_MECHANISM struct wrapper.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CKM extends Struct {
    public long mechanism;
    public jnr.ffi.Pointer pParameter;
    public long ulParameterLen;

    public JFFI_CKM() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }

    public JFFI_CKM readFrom(CKM ckm) {
        mechanism = ckm.mechanism;
        int len = ckm.bParameter != null ? ckm.bParameter.length : 0;
        if (len > 0) {
            pParameter = Memory.allocate(jnr.ffi.Runtime.getSystemRuntime(), len);
            pParameter.put(0, ckm.bParameter, 0, len);
        }
        ulParameterLen = len;
        return this;
    }

    public JFFI_CKM readFromPointer(CKM pMechanism) {
        mechanism = pMechanism.mechanism;
        int len = pMechanism.pParameter != null ? Native.POINTER_SIZE : 0;
        if (len > 0) {
            byte[] ckmParamBytes = pMechanism.pParameter.getByteArray(0, len);
            pParameter = Memory.allocate(jnr.ffi.Runtime.getSystemRuntime(), len);
            pParameter.put(0, ckmParamBytes, 0, len);
        }
        ulParameterLen = len;
        return this;
    }
}
