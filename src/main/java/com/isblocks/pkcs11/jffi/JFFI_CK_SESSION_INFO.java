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

import com.isblocks.pkcs11.CK_SESSION_INFO;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_SESSION_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_SESSION_INFO extends Struct {
    public long slotID;
    public long state;
    public long flags;
    public long ulDeviceError;

    public JFFI_CK_SESSION_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }


    public JFFI_CK_SESSION_INFO readFrom(CK_SESSION_INFO info) {
        slotID = info.slotID;
        state = info.state;
        flags = info.flags;
        ulDeviceError = info.ulDeviceError;
        return this;
    }

    public CK_SESSION_INFO writeTo(CK_SESSION_INFO info) {
        info.slotID = slotID;
        info.state = state;
        info.flags = flags;
        info.ulDeviceError = ulDeviceError;
        return info;
    }
}
