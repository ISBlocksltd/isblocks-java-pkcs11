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

import com.isblocks.pkcs11.CK_VERSION;

import jnr.ffi.Struct;

/**
 * JFFI wrapper for PKCS#11 CK_VERSION.  It hardly seems worthwhile
 * wrapping 2 bytes, but we have.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JFFI_CK_VERSION extends Struct {
    public byte major;
    public byte minor;

    public JFFI_CK_VERSION() {
        super(jnr.ffi.Runtime.getSystemRuntime());
    }
/**
     * TO DO:
     * @param version CK_VERSION  
     * @return 
     */
    public JFFI_CK_VERSION readFrom(CK_VERSION version) {
        major = version.major;
        minor = version.minor;
        return this;
    }
	/**
     * TO DO:
     * @param version CK_VERSION  
     * @return version
     */
    public CK_VERSION writeTo(CK_VERSION version) {
        version.major = major;
        version.minor = minor;
        return version;
    }
}
