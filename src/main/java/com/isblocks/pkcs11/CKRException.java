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

package com.isblocks.pkcs11;

/**
 * Exception for CKR values that are non-zero (CKR.OK).
 * Used in {@link CE} interface as alternative to returning
 * CKR for every function.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class CKRException extends RuntimeException {
    private static final long serialVersionUID = 0x2841de9d258bab8bL;
    private long ckr;

    /**
     * Constructor with CKR value.
     * @param ckr CKR value.
    
     */ 
    public CKRException(long ckr) {
        super(String.format("0x%08x: %s", ckr, CKR.L2S(ckr)));
        this.ckr = ckr;
    }

    /**
     * Constructor with message and CKR value.
     * @param msg message
     * @param ckr CKR value
     */
    public CKRException(String msg, long ckr) {
        super(String.format("0x%08x: %s : %s", ckr, CKR.L2S(ckr), msg));
        this.ckr = ckr;
    }

    /** @return CKR value */
    public long getCKR() { return ckr; }
}
