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

import java.util.Arrays;
import java.util.List;

import com.isblocks.pkcs11.CK_SLOT_INFO;
import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_SLOT_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_SLOT_INFO extends Structure {
    public byte[] slotDescription;
    public byte[] manufacturerID;
    public NativeLong flags;
    public JNA_CK_VERSION hardwareVersion;
    public JNA_CK_VERSION firmwareVersion;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("slotDescription", "manufacturerID", "flags", "hardwareVersion", "firmwareVersion");
    }

    public JNA_CK_SLOT_INFO readFrom(CK_SLOT_INFO info) {
        slotDescription = info.slotDescription;
        manufacturerID = info.manufacturerID;
        flags = new NativeLong(info.flags);
        hardwareVersion = new JNA_CK_VERSION().readFrom(info.hardwareVersion);
        firmwareVersion = new JNA_CK_VERSION().readFrom(info.firmwareVersion);
        return this;
    }

    public CK_SLOT_INFO writeTo(CK_SLOT_INFO info) {
        info.slotDescription = slotDescription;
        info.manufacturerID = manufacturerID;
        info.flags = flags.intValue();
        hardwareVersion.writeTo(info.hardwareVersion);
        firmwareVersion.writeTo(info.firmwareVersion);
        return info;
    }
}
