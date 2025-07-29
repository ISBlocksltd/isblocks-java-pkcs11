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

import com.isblocks.pkcs11.C;
import com.isblocks.pkcs11.CE;
import com.isblocks.pkcs11.LongRef;
import com.isblocks.pkcs11.NativeProvider;
import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.PointerType;

/**
 * Implements a CK_ULONG[] type for JNA.  Allows simple conversion with java long[].
 * JNA direct memory mapping doesn't seem to support struct arrays,
 * so this class is required to map the ints into a contiguous block of memory.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class LongArray extends PointerType {
    private long[] list;
    private int listLen;

    /** Default no-arg constructor required by JNA. */
    public LongArray() {
        this(null);
    }

    /**
     * Allocates JNA Memory and writes long values.
     * @param list longs
     * @return
     * 
     */
    public LongArray(long[] list) {
        this.list = list;
        listLen = list == null ? 0 : list.length;
        if (listLen == 0) {
            return;
        }
        setPointer(new Memory(listLen * NativeLong.SIZE));
        if (NativeLong.SIZE == 8) {
            getPointer().write(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                getPointer().setInt(i, (int) list[i]);
            }
        }
    }

    /**
     * Reads (updated) JNA Memory and modifies values in list.
     * This must be called after native PKCS#11 calls in {@link NativeProvider} that modify
     * ULONG values such as {@link NativeProvider#C_FindObjects(NativeLong, LongArray, NativeLong, LongRef)}.
     * This is automatically done by the {@link C} and {@link CE} interfaces.
     *  * @return
     */
    public void update() {
        if (listLen == 0) {
            return;
        }
        if (NativeLong.SIZE == 8) {
            getPointer().read(0, list, 0, listLen);
        } else {
            for (int i = 0; i < listLen; i++) {
                list[i] = getPointer().getInt(i * NativeLong.SIZE);
            }
        }
    }
}
