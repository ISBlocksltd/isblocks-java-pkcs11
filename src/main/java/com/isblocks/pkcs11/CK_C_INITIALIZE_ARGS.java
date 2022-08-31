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

package com.isblocks.pkcs11;

import java.util.Map;

/**
 * PKCS#11 CK_C_INITIALIZE_ARGS struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class CK_C_INITIALIZE_ARGS {

    /**
     * True if application threads which are executing calls to the library may not use native operating system calls to
     * spawn new threads; false if they may.
     */
    public static final long CKF_LIBRARY_CANT_CREATE_OS_THREADS = 0x00000001;
    /** True if the library can use the native operation system threading model for locking; false otherwise. */
    public static final long CKF_OS_LOCKING_OK = 0x00000002;

    /** Maps from long value to String description (variable name). */
    private static final Map<Long, String> L2S = C.createL2SMap(CK_C_INITIALIZE_ARGS.class);
    /**
     * Convert long constant value to name.
     * @param ckf value
     * @return name
     */
    public static final String L2S(long ckf) { return C.l2s(L2S, "CKF", ckf); }
    /**
     * Convert flags to string.
     * @param flags flags
     * @return string format
     */
    public static String f2s(long flags) { return C.f2s(L2S, flags); }


    public CK_CREATEMUTEX createMutex;
    public CK_DESTROYMUTEX destroyMutex;
    public CK_LOCKMUTEX lockMutex;
    public CK_UNLOCKMUTEX unlockMutex;
    public long flags;
    public NativePointer pReserved;

    /**
     * Initialise struct with supplied values.
     * @param createMutex create mutex
     * @param destroyMutex destroy mutex
     * @param lockMutex lock mutex
     * @param unlockMutex unlock mutex
     * @param flags locking flags constant from CKF
     */
    public CK_C_INITIALIZE_ARGS(CK_CREATEMUTEX createMutex, CK_DESTROYMUTEX destroyMutex, CK_LOCKMUTEX lockMutex,
            CK_UNLOCKMUTEX unlockMutex, long flags) {

        this.createMutex = createMutex;
        this.destroyMutex = destroyMutex;
        this.lockMutex = lockMutex;
        this.unlockMutex = unlockMutex;
        this.flags = flags;
    }
    
    /** @return True, if the provided flag is set */
    public boolean isFlagSet(long CKF_FLAG) {
        return (flags & CKF_FLAG) != 0L;
    }

    /** @return string */
    public String toString() {
        return String.format("create=%s destroy=%s lock=%s unlock=%s flags=0x%08x{%s}",
                createMutex, destroyMutex, lockMutex, unlockMutex, flags, f2s(flags));
    }

    /**
     * JNA wrapper for PKCS#11 CK_CREATEMUTEX.
     * @author Joel Hockey
     */
    public interface CK_CREATEMUTEX {
        /**
         * Create Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        long invoke(NativePointerByReference mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_DESTROYMUTEX.
     * @author Joel Hockey
     */
    public interface CK_DESTROYMUTEX {
        /**
         * Destroy Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        long invoke(NativePointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_LOCKMUTEX.
     * @author Joel Hockey
     */
    public interface CK_LOCKMUTEX {
        /**
         * Lock Mutex.
         * @param mutex mutex 
         * @return {@link CKR} return code
         */
        long invoke(NativePointer mutex);
    }

    /**
     * JNA wrapper for PKCS#11 CK_UNLOCKMUTEX.
     * @author Joel Hockey
     */
    public interface CK_UNLOCKMUTEX {
        /**
         * Unlock Mutex.
         * @param mutex mutex
         * @return {@link CKR} return code
         */
        long invoke(NativePointer mutex);
    }
}
