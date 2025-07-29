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

import com.isblocks.pkcs11.CKM;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;


/**
 * CKM_? constants and CK_MECHANISM struct wrapper.
  * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class JNA_CKM extends Structure {
    public NativeLong mechanism;
    public Pointer pParameter;
    public NativeLong ulParameterLen;

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("mechanism", "pParameter", "ulParameterLen");
    }
/**
     * TO DO:
     * @param ckm CKM  
     * @return 
     */
    public JNA_CKM readFrom(CKM ckm) {
        mechanism = new NativeLong(ckm.mechanism);
        pParameter = ckm.pParameter;
        ulParameterLen = new NativeLong(ckm.ulParameterLen);
        return this;
    }
}
