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
package com.isblocks.pkcs11.jna;

import java.util.Arrays;
import java.util.List;

import com.isblocks.pkcs11.CK_VERSION;
import com.sun.jna.Structure;

/**
 * JNA wrapper for PKCS#11 CK_VERSION.  It hardly seems worthwhile
 * wrapping 2 bytes, but we have.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class JNA_CK_VERSION extends Structure {
    public byte major;
    public byte minor;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("major", "minor");
    }
    
    public JNA_CK_VERSION readFrom(CK_VERSION version) {
        major = version.major;
        minor = version.minor;
        return this;
    }
    public CK_VERSION writeTo(CK_VERSION version) {
        version.major = major;
        version.minor = minor;
        return version;
    }
}
