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

import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS;
import com.isblocks.pkcs11.NativePointer;
import com.isblocks.pkcs11.NativePointerByReference;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_CREATEMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_DESTROYMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_LOCKMUTEX;
import com.isblocks.pkcs11.CK_C_INITIALIZE_ARGS.CK_UNLOCKMUTEX;

import jnr.ffi.Struct;
import jnr.ffi.annotations.Delegate;
import jnr.ffi.byref.PointerByReference;

/**
 * JFFI wrapper for PKCS#11 CK_C_INITIALIZE_ARGS struct. Also includes JFFI mutex interface wrappers.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JFFI_CK_C_INITIALIZE_ARGS extends Struct {

    public JFFI_CK_CREATEMUTEX createMutex;
    public JFFI_CK_DESTROYMUTEX destroyMutex;
    public JFFI_CK_LOCKMUTEX lockMutex;
    public JFFI_CK_UNLOCKMUTEX unlockMutex;
    public long flags;
    public jnr.ffi.Pointer pReserved;
  /**
         * TO DO:
         * @param args CK_C_INITIALIZE_ARGS
         * @return 
         */
    public JFFI_CK_C_INITIALIZE_ARGS(final CK_C_INITIALIZE_ARGS args) {
        super(jnr.ffi.Runtime.getSystemRuntime());
        this.createMutex = new JFFI_CK_CREATEMUTEX() {
            public long invoke(NativePointerByReference mutex) {
                return args.createMutex.invoke(mutex);
            }
			  /**
         * TO DO:
         * @param mutex PointerByReference
         * @return 
         */
            public long invoke(PointerByReference mutex) {
                return invoke(new NativePointerByReference(
                    new NativePointer(mutex.getValue().address())));
            }
        };
        this.destroyMutex = new JFFI_CK_DESTROYMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.destroyMutex.invoke(mutex);
            }
				  /**
         * TO DO:
         * @param mutex PointerByReference
         * @return 
         */
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.lockMutex = new JFFI_CK_LOCKMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.lockMutex.invoke(mutex);
            }
				  /**
         * TO DO:
         * @param mutex PointerByReference
         * @return 
         */
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.unlockMutex = new JFFI_CK_UNLOCKMUTEX() {
            public long invoke(NativePointer mutex) {
                return args.unlockMutex.invoke(mutex);
            }
				  /**
         * TO DO:
         * @param mutex PointerByReference
         * @return 
         */
            public long invoke(jnr.ffi.Pointer mutex) {
                return invoke(new NativePointer(mutex.address()));
            }
        };
        this.flags = args.flags;
    }

    /**
     * JNA wrapper for PKCS#11 CK_CREATEMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_CREATEMUTEX extends CK_CREATEMUTEX {
        /**
         * Create Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(PointerByReference mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_DESTROYMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_DESTROYMUTEX extends CK_DESTROYMUTEX {
        /**
         * Destroy Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }

    /** 
     * JNA wrapper for PKCS#11 CK_LOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_LOCKMUTEX extends CK_LOCKMUTEX {
        /**
         * Lock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_UNLOCKMUTEX.
     * @author Joel Hockey
     */
    public interface JFFI_CK_UNLOCKMUTEX extends CK_UNLOCKMUTEX {
        /**
         * Unlock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        @Delegate
        long invoke(jnr.ffi.Pointer mutex);
    }
}
