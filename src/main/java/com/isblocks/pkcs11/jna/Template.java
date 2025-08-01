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

import java.util.ArrayList;
import java.util.List;

import com.isblocks.pkcs11.C;
import com.isblocks.pkcs11.CE;
import com.isblocks.pkcs11.CKA;
import com.isblocks.pkcs11.NativeProvider;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;

/**
 * Wrapper for CK_ATTRIBUTE[] (in this case it is CKA class that represents
 * PKCS#11 CK_ATTRIBUTE struct).  JNA direct memory mapping doesn't seem to
 * support struct arrays, so this class is required to map the
 * list of (type, pValue, ulValueLen) into a contiguous block of memory.
 *
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class Template extends PointerType {
    private CKA[] list;
    private List<Memory> pValues;
    private int listLen;

    /** Default no-arg constructor required by JNA. */
    public Template() {
        this(null);
    }

    /**
     * Allocates JNA Memory and writes CKA[] values.
     * @param list template
     */
    public Template(CKA[] list) {
        this.list = list;
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * (NativeLong.SIZE + Native.POINTER_SIZE + NativeLong.SIZE)));
        // Keep java references over the life time of this Template to avoid native memory being freed before use
        pValues = new ArrayList<>();
        int offset = 0;

        for (int i = 0; i < listLen; i++) {
            // type
            if (NativeLong.SIZE == 4) {
                getPointer().setInt(offset, (int) list[i].type);
            } else {
                getPointer().setLong(offset, list[i].type);
            }
            offset += NativeLong.SIZE;

            // pValue
            Memory pValue = null;
            if (list[i].ulValueLen > 0) {
                pValue = new Memory(list[i].ulValueLen);
                pValue.write(0, list[i].pValue, 0, (int) list[i].ulValueLen);
            }
            getPointer().setPointer(offset, pValue);
            // We saved a "long" pointer to the memory allocated by "new Memory" above, keep the java object 
            // reference as well to avoid it being garbage collected, which will free the native memory allocated when
            // Memory.finalize is called
            pValues.add(pValue);
            offset += Native.POINTER_SIZE;

            // ulValueLen
            if (NativeLong.SIZE == 4) {
                getPointer().setInt(offset, (int) list[i].ulValueLen);
            } else {
                getPointer().setLong(offset, list[i].ulValueLen);
            }
            offset += NativeLong.SIZE;
        }
    }

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link NativeProvider} 
     */
    public void update() {
        if (listLen == 0) {
            return;
        }
        int offset = 0;
        for (int i = 0; i < list.length; i++) {
            offset += NativeLong.SIZE; // skip type

            // read pValue
            Pointer ptr = getPointer().getPointer(offset);
            offset += Native.POINTER_SIZE;

            // read ulValueLen
            int ulValueLen = 0;
            if (NativeLong.SIZE == 4) {
                ulValueLen = getPointer().getInt(offset);
            } else {
                ulValueLen = (int) getPointer().getLong(offset);
            }
            offset += NativeLong.SIZE;

            // read contents into pValue if ptr != null && ulValueLen > 0
            if (ptr != null && ulValueLen > 0) {
                ptr.read(0, list[i].pValue, 0, ulValueLen);
            }
            list[i].ulValueLen = ulValueLen;
        }
    }
}
