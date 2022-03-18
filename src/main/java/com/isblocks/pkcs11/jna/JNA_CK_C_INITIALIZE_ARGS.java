/*
 * Copyright 2010-2011 Joel Hockey (joel.hockey@gmail.com). All rights reserved.

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
/*************************************************************************

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
package com.isblocks.pkcs11.jna;

import java.util.Arrays;
import java.util.List;

import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS;
import com.isblocks.pkcs11.NativePointer;
import com.isblocks.pkcs11.NativePointerByReference;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_CREATEMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_DESTROYMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_LOCKMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_UNLOCKMUTEX;
import com.sun.jna.Callback;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

/**
 * JNA wrapper for PKCS#11 CK_C_INITIALIZE_ARGS struct. Also includes JNA mutex interface wrappers.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_C_INITIALIZE_ARGS extends Structure {

    public JNA_CK_CREATEMUTEX createMutex;
    public JNA_CK_DESTROYMUTEX destroyMutex;
    public JNA_CK_LOCKMUTEX lockMutex;
    public JNA_CK_UNLOCKMUTEX unlockMutex;
    public NativeLong flags;
    public Pointer pReserved;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("createMutex", "destroyMutex", "lockMutex", "unlockMutex", "flags", "pReserved");
    }

    public JNA_CK_C_INITIALIZE_ARGS(final CK_C_INITIALIZE_ARGS args) {
        if (args.createMutex != null) {
            this.createMutex = new JNA_CK_CREATEMUTEX() {
                public long invoke(NativePointerByReference mutex) {
                    return args.createMutex.invoke(mutex);
                }
                public NativeLong invoke(PointerByReference mutex) {
                    return new NativeLong(invoke(new NativePointerByReference(
                        new NativePointer(Pointer.nativeValue(mutex.getPointer())))));
                }
            };
        }
        if (args.destroyMutex != null) {
            this.destroyMutex = new JNA_CK_DESTROYMUTEX() {
                public long invoke(NativePointer mutex) {
                    return args.destroyMutex.invoke(mutex);
                }
                public NativeLong invoke(Pointer mutex) {
                    return new NativeLong(invoke(new NativePointer(Pointer.nativeValue(mutex))));
                }
            };
        }
        if (args.lockMutex != null) {
            this.lockMutex = new JNA_CK_LOCKMUTEX() {
                public long invoke(NativePointer mutex) {
                    return args.lockMutex.invoke(mutex);
                }
                public NativeLong invoke(Pointer mutex) {
                    return new NativeLong(invoke(new NativePointer(Pointer.nativeValue(mutex))));
                }
            };
        }
        if (args.unlockMutex != null) {
            this.unlockMutex = new JNA_CK_UNLOCKMUTEX() {
                public long invoke(NativePointer mutex) {
                    return args.unlockMutex.invoke(mutex);
                }
                public NativeLong invoke(Pointer mutex) {
                    return new NativeLong(invoke(new NativePointer(Pointer.nativeValue(mutex))));
                }
            };
        }
        this.flags = new NativeLong(args.flags);
    }

    /**
     * JNA wrapper for PKCS#11 CK_CREATEMUTEX.
     * @author Joel Hockey
     */
    public interface JNA_CK_CREATEMUTEX extends CK_CREATEMUTEX, Callback {
        /**
         * Create Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(PointerByReference mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_DESTROYMUTEX.
     * @author Joel Hockey
     */
    public interface JNA_CK_DESTROYMUTEX extends CK_DESTROYMUTEX, Callback {
        /**
         * Destroy Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_LOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JNA_CK_LOCKMUTEX extends CK_LOCKMUTEX, Callback {
        /**
         * Lock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_UNLOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JNA_CK_UNLOCKMUTEX extends CK_UNLOCKMUTEX, Callback {
        /**
         * Unlock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        NativeLong invoke(Pointer mutex);
    }
}
