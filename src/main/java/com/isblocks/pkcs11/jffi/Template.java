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
import jnr.ffi.Pointer;
import jnr.ffi.Runtime;

/**
 * JFFI Wrapper for CK_ATTRIBUTE[].
 *
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class Template {
/**
     * TO DO:
     * @param cka CKA  
     * @return 
     */
    public static Pointer templ(CKA[] cka) {
        if (cka == null) {
            return null;
        }
        Runtime runtime = Runtime.getSystemRuntime();
        Pointer result = Memory.allocate(runtime, cka.length * (runtime.longSize() + runtime.addressSize() + runtime.longSize()));

        int offset = 0;
        for (int i = 0; i < cka.length; i++) {
            // type
            result.putLong(offset, cka[i].type);
            offset += runtime.longSize();

            // pValue
            if (cka[i].pValue != null) {
                Pointer pValue = Memory.allocate(runtime, cka[i].pValue.length);
                pValue.put(0, cka[i].pValue, 0, cka[i].pValue.length);
            }
            offset += runtime.addressSize();

            // ulValueLen
            result.putLong(offset, cka[i].ulValueLen);
            offset += runtime.longSize();
        }

        return result;
    }
/**
     * TO DO:
	 * @param templ Pointer  
     * @param cka CKA  
     * @return 
     */
    public static void update(Pointer templ, CKA[] cka) {
        if (cka == null) {
            return;
        }
        Runtime runtime = Runtime.getSystemRuntime();
        int offset = 0;
        for (int i = 0; i < cka.length; i++) {
            // read ulValueLen (skip type, pValue)
            long ulValueLen = templ.getLong(offset + runtime.longSize() + runtime.addressSize());
            cka[i].ulValueLen = ulValueLen;

            // pValue
            Pointer pValue = templ.getPointer(offset + runtime.longSize());
            pValue.put(0, cka[i].pValue, 0, cka[i].pValue.length);

            // update offset (skip type, pValue, ulValueLen)
            offset += runtime.longSize() + runtime.addressSize() + runtime.longSize();
        }
    }
}
