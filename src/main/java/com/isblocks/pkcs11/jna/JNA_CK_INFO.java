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

import com.isblocks.pkcs11.CK_INFO;
import com.sun.jna.NativeLong;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_INFO struct.  It sets align type to {@link Structure#ALIGN_NONE}
 * since the ULONGS (NativeLongs) don't line up on a 4 byte boundary.  You wouldn't care to know
 * how painful that learning experience was.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JNA_CK_INFO extends Structure {

    public JNA_CK_VERSION cryptokiVersion;
    public byte[] manufacturerID;
    public NativeLong flags;
    public byte[] libraryDescription;
    public JNA_CK_VERSION libraryVersion;

    /**
     * Default constructor.
     * need to set alignment to none since 'flags' is not
     * correctly aligned to a 4 byte boundary
     */
    public JNA_CK_INFO() {
        setAlignType(ALIGN_NONE);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("cryptokiVersion", "manufacturerID", "flags", "libraryDescription", "libraryVersion");
    }
 /**
     * TO DO:
     * @param info CK_INFO  
     * @return 
     */
    public JNA_CK_INFO readFrom(CK_INFO info) {
        cryptokiVersion = new JNA_CK_VERSION().readFrom(info.cryptokiVersion);
        manufacturerID = info.manufacturerID;
        flags = new NativeLong(info.flags);
        libraryDescription = info.libraryDescription;
        libraryVersion = new JNA_CK_VERSION().readFrom(info.libraryVersion);
        return this;
    }
  /**
     * TO DO:
     * @param info CK_INFO  
     * @return info
     */
    public CK_INFO writeTo(CK_INFO info) {
        cryptokiVersion.writeTo(info.cryptokiVersion);
        info.manufacturerID = manufacturerID;
        info.flags = flags.intValue();
        info.libraryDescription = libraryDescription;
        libraryVersion.writeTo(info.libraryVersion);
        return info;
    }
}
