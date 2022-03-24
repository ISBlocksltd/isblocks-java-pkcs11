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

package com.isblocks.pkcs11;

/**
 * Wrapper for native long that can be modified.
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class LongRef {
    public long value;
    /** Default constructor */
    public LongRef() { this(0); }
    /**
     * Constructor taking java long.
     * @param value value
     */
    public LongRef(long value) { this.value = value; }

    /** @return current value */
    public long value() { return value; }

    /** @return value as string */
    public String toString() { return Long.toString(value); }
}
 