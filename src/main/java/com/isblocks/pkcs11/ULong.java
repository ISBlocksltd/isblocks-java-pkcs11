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

import java.nio.ByteOrder;

/** 
 * Converts between Java long and 'unsigned long int' catering for size(long) and endianness.
 * @author Raoul da Costa (rdacosta@isblocks.com)
 */
public class ULong {
    public enum ULongSize { ULONG4(4), ULONG8(8);
        private int size;
        private ULongSize(int size) { this.size = size; }
        public int size() { return size;}
    };
    public static ULongSize ULONG_SIZE = ULongSize.ULONG4;

    /**
     * Convert list of Java long to byte array
     * of native long catering for endianness and sizeof(long)
     * @param la list of longs
     * @return native format
     */
    public static byte[] ulong2b(long... la) {
        if (la == null || la.length == 0) {
            return new byte[0];
        }

        if (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN) {
            if (ULONG_SIZE == ULongSize.ULONG4) {
                byte[] result = new byte[la.length * 4];
                // start at rhs and work back for big-endian
                int j = result.length - 1;
                for (int i = la.length - 1; i >= 0; i--) {
                    long val = la[i];
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                }
                return result;
            } else {
                byte[] result = new byte[la.length * 8];
                // start at rhs and work back for big-endian
                int j = result.length - 1;
                for (int i = la.length - 1; i >= 0; i--) {
                    long val = la[i];
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                    val >>= 8;
                    result[j--] = (byte) val;
                }
                return result;
            }
        } else {
            if (ULONG_SIZE == ULongSize.ULONG4) {
                byte[] result = new byte[la.length * 4];
                // start at lhs and work forward for little-endian
                int j = 0;
                for (int i = 0; i < la.length; i++) {
                    long val = la[i];
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                }
                return result;
            } else {
                byte[] result = new byte[la.length * 8];
                // start at lhs and work forward for little-endian
                int j = 0;
                for (int i = 0; i < la.length; i++) {
                    long val = la[i];
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                    val >>= 8;
                    result[j++] = (byte) val;
                }
                return result;
            }
        }
    }

    /**
     * Convert byte array of native long to java long
     * @param buf native long
     * @return java long
     */
    public static long b2ulong(byte[] buf) {
        if (ByteOrder.nativeOrder() == ByteOrder.BIG_ENDIAN) {
            if (ULONG_SIZE == ULongSize.ULONG4) {
                return ((buf[0] & 0xff) << 24) | ((buf[1] & 0xff) << 16) | ((buf[2] & 0xff) << 8) | (buf[3] & 0xff);
            } else {
                return ((buf[0] & 0xff) << 56) | ((buf[1] & 0xff) << 48) | ((buf[2] & 0xff) << 40) | ((buf[3] & 0xff) << 32) | ((buf[4] & 0xff) << 24) | ((buf[5] & 0xff) << 16) | ((buf[6] & 0xff) << 8) | (buf[7] & 0xff);
            }
        } else {
            if (ULONG_SIZE == ULongSize.ULONG4) {
                return ((buf[3] & 0xff) << 24) | ((buf[2] & 0xff) << 16) | ((buf[1] & 0xff) << 8) | (buf[0] & 0xff);
            } else {
                return ((buf[7] & 0xff) << 56) | ((buf[6] & 0xff) << 48) | ((buf[5] & 0xff) << 40) | ((buf[4] & 0xff) << 32) | ((buf[3] & 0xff) << 24) | ((buf[2] & 0xff) << 16) | ((buf[1] & 0xff) << 8) | (buf[0] & 0xff);
            }
        }
    }
}


