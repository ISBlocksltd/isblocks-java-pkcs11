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

import com.isblocks.pkcs11.CKR;

import jnr.ffi.Pointer;
import jnr.ffi.annotations.Delegate;
import com.isblocks.pkcs11.CKR;;

/**
 * JFFI wrapper for PKCS#11 CK_NOTIFY.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public interface JFFI_CK_NOTIFY {

    /**
     * CK_NOTIFY is an application callback that processes events.
     * @param hSession the session's handle
     * @param event event
     * @param pApplication passed to C_OpenSession
     * @return {@link CKR} return code
     */
    @Delegate
    long invoke(long hSession, long event, Pointer pApplication);
}
 