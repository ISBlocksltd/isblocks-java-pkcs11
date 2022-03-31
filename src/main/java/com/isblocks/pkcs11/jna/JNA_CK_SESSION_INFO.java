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

import com.isblocks.pkcs11.CK_SESSION_INFO;
import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_SESSION_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_SESSION_INFO extends Structure {
    public NativeLong slotID;
    public NativeLong state;
    public NativeLong flags;
    public NativeLong ulDeviceError;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("slotID", "state", "flags", "ulDeviceError");
    }

    public JNA_CK_SESSION_INFO readFrom(CK_SESSION_INFO info) {
        slotID = new NativeLong(info.slotID);
        state = new NativeLong(info.state);
        flags = new NativeLong(info.flags);
        ulDeviceError = new NativeLong(info.ulDeviceError);
        return this;
    }

    public CK_SESSION_INFO writeTo(CK_SESSION_INFO info) {
        info.slotID = slotID.intValue();
        info.state = state.intValue();
        info.flags = flags.intValue();
        info.ulDeviceError = ulDeviceError.intValue();
        return info;
    }
}
