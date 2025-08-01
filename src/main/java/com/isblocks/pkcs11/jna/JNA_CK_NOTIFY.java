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

import com.isblocks.pkcs11.CKR;
import com.sun.jna.Callback;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.isblocks.pkcs11.CKR;

/**
 * JNA wrapper for PKCS#11 CK_NOTIFY.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public interface JNA_CK_NOTIFY extends Callback {
    /**
     * CK_NOTIFY is an application callback that processes events.
     * @param hSession the session's handle
     * @param event event
     * @param pApplication passed to C_OpenSession
     * @return {@link CKR} return code
     */
    NativeLong invoke(NativeLong hSession, NativeLong event, Pointer pApplication);
}
 