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
 * Java wrapper for Pointer to NativePointer
 *
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class NativePointerByReference {
    private NativePointer pointer;

    /**
     * Constructor with pointer
     * @param pointer pointer
     */
    public NativePointerByReference(NativePointer pointer) {
        this.pointer = pointer;
    }
    /** @param pointer pointer referenced */
    public void setPointer(NativePointer pointer) { this.pointer = pointer; }
    /** @return pointer */
    public NativePointer getPointer() { return pointer; }
}
 