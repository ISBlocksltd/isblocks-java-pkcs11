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

import com.isblocks.pkcs11.CKM;
import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * JNA mapping of CK_MECHANISM. Keep allocated Memory referenced so GC
 * doesn't free the parameter buffer while native call runs.
 */
public class JNA_CKM extends com.sun.jna.Structure {
    public static class ByReference extends JNA_CKM implements com.sun.jna.Structure.ByReference {}
    public com.sun.jna.NativeLong mechanism;
    public com.sun.jna.Pointer pParameter;
    public com.sun.jna.NativeLong ulParameterLen;

    // keep Memory alive while native call runs
    private com.sun.jna.Memory paramMemory;

    public JNA_CKM readFrom(CKM ckm) {
        this.mechanism = new com.sun.jna.NativeLong(ckm.mechanism);
        byte[] param = ckm.getParameterBytes();
        if (param != null && param.length > 0) {
            this.paramMemory = new com.sun.jna.Memory(param.length);
            this.paramMemory.write(0, param, 0, param.length);
            this.pParameter = this.paramMemory;
            this.ulParameterLen = new com.sun.jna.NativeLong(param.length);
        } else {
            this.paramMemory = null;
            this.pParameter = null;
            this.ulParameterLen = new com.sun.jna.NativeLong(0);
        }
        this.write(); // sync Java -> native
        return this;
    }

    @Override
    protected java.util.List<String> getFieldOrder() {
        return java.util.Arrays.asList("mechanism","pParameter","ulParameterLen");
    }
}