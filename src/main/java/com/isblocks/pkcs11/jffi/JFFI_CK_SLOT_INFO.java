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

import com.isblocks.pkcs11.CK_SLOT_INFO;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_SLOT_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_SLOT_INFO extends Struct {
    public byte[] slotDescription;
    public byte[] manufacturerID;
    public long flags;
    public JFFI_CK_VERSION hardwareVersion;
    public JFFI_CK_VERSION firmwareVersion;

    public JFFI_CK_SLOT_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }


    public JFFI_CK_SLOT_INFO readFrom(CK_SLOT_INFO info) {
        slotDescription = info.slotDescription;
        manufacturerID = info.manufacturerID;
        flags = info.flags;
        hardwareVersion = new JFFI_CK_VERSION().readFrom(info.hardwareVersion);
        firmwareVersion = new JFFI_CK_VERSION().readFrom(info.firmwareVersion);
        return this;
    }

    public CK_SLOT_INFO writeTo(CK_SLOT_INFO info) {
        info.slotDescription = slotDescription;
        info.manufacturerID = manufacturerID;
        info.flags = flags;
        hardwareVersion.writeTo(info.hardwareVersion);
        firmwareVersion.writeTo(info.firmwareVersion);
        return info;
    }
}
