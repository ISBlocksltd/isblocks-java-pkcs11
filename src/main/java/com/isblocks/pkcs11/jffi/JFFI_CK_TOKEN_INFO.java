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

import com.isblocks.pkcs11.CK_TOKEN_INFO;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_TOKEN_INFO struct.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JFFI_CK_TOKEN_INFO extends Struct {
    public byte[] label;
    public byte[] manufacturerID;
    public byte[] model;
    public byte[] serialNumber;
    public long flags;
    public long ulMaxSessionCount;
    public long ulSessionCount;
    public long ulMaxRwSessionCount;
    public long ulRwSessionCount;
    public long ulMaxPinLen;
    public long ulMinPinLen;
    public long ulTotalPublicMemory;
    public long ulFreePublicMemory;
    public long ulTotalPrivateMemory;
    public long ulFreePrivateMemory;
    public JFFI_CK_VERSION hardwareVersion;
    public JFFI_CK_VERSION firmwareVersion;
    public byte[] utcTime;

    public JFFI_CK_TOKEN_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }
    
    /**
     * TO DO:
     * @param info CK_TOKEN_INFO  
     * @return 
     */

    public JFFI_CK_TOKEN_INFO readFrom(CK_TOKEN_INFO info) {
        label = info.label;
        manufacturerID = info.manufacturerID;
        model = info.model;
        serialNumber = info.serialNumber;
        flags = info.flags;
        ulMaxSessionCount = info.ulMaxSessionCount;
        ulSessionCount = info.ulSessionCount;
        ulMaxRwSessionCount = info.ulMaxRwSessionCount;
        ulRwSessionCount = info.ulRwSessionCount;
        ulMaxPinLen = info.ulMaxPinLen;
        ulMinPinLen = info.ulMinPinLen;
        ulTotalPublicMemory = info.ulTotalPublicMemory;
        ulFreePublicMemory = info.ulFreePublicMemory;
        ulTotalPrivateMemory = info.ulTotalPrivateMemory;
        ulFreePrivateMemory = info.ulFreePrivateMemory;
        hardwareVersion = new JFFI_CK_VERSION().readFrom(info.hardwareVersion);
        firmwareVersion = new JFFI_CK_VERSION().readFrom(info.firmwareVersion);
        utcTime = info.utcTime;
        return this;
    }
  /**
     * TO DO:
     * @param info CK_TOKEN_INFO  
     * @return info
     */
    public CK_TOKEN_INFO writeTo(CK_TOKEN_INFO info) {
        info.label = label;
        info.manufacturerID = manufacturerID;
        info.model = model;
        info.serialNumber = serialNumber;
        info.flags = flags;
        info.ulMaxSessionCount = ulMaxSessionCount;
        info.ulSessionCount = ulSessionCount;
        info.ulMaxRwSessionCount = ulMaxRwSessionCount;
        info.ulRwSessionCount = ulRwSessionCount;
        info.ulMaxPinLen = ulMaxPinLen;
        info.ulMinPinLen = ulMinPinLen;
        info.ulTotalPublicMemory = ulTotalPublicMemory;
        info.ulFreePublicMemory = ulFreePublicMemory;
        info.ulTotalPrivateMemory = ulTotalPrivateMemory;
        info.ulFreePrivateMemory = ulFreePrivateMemory;
        hardwareVersion.writeTo(info.hardwareVersion);
        firmwareVersion.writeTo(info.firmwareVersion);
        info.utcTime = utcTime;
        return info;
    }
}
