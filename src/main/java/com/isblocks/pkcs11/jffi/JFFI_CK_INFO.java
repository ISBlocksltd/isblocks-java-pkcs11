/*/*************************************************************************
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

package com.isblocks.pkcs11.jffi;

import com.isblocks.pkcs11.CK_INFO;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_INFO struct.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JFFI_CK_INFO extends Struct {

    public JFFI_CK_VERSION cryptokiVersion;
    public byte[] manufacturerID;
    public long flags;
    public byte[] libraryDescription;
    public JFFI_CK_VERSION libraryVersion;

    /**
     * Default constructor.
     * need to set alignment to none since 'flags' is not
     * correctly aligned to a 4 byte boundary
     */
    public JFFI_CK_INFO() {
        super(jnr.ffi.Runtime.getSystemRuntime());
//        setAlignType();
    }

    public JFFI_CK_INFO readFrom(CK_INFO info) {
        cryptokiVersion = new JFFI_CK_VERSION().readFrom(info.cryptokiVersion);
        manufacturerID = info.manufacturerID;
        flags = info.flags;
        libraryDescription = info.libraryDescription;
        libraryVersion = new JFFI_CK_VERSION().readFrom(info.libraryVersion);
        return this;
    }

    public CK_INFO writeTo(CK_INFO info) {
        cryptokiVersion.writeTo(info.cryptokiVersion);
        info.manufacturerID = manufacturerID;
        info.flags = flags;
        info.libraryDescription = libraryDescription;
        libraryVersion.writeTo(info.libraryVersion);
        return info;
    }
}
