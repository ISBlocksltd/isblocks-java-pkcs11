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
 * Byte array utils.
 *
 * @author Joel Hockey (joel.hockey@gmail.com)
 */
public class Buf {
    /**
     * Maps how to convert byte to printable java string.
     *   -1 => non-printable (use '\\uxxxx'), 0 => printable as-is, else gives escape char.
     */
    public static final int[] LKP_ESCAPES = new int[256];

    static {
        // non-printable or escapable
        for  (int i = 0; i < 0x20; i++) {
            LKP_ESCAPES[i] = -1;
        }
        for (int i = 127; i < 256; i++) {
            LKP_ESCAPES[i] = -1;
        }
        // special escapes
        LKP_ESCAPES['\b'] = 'b';
        LKP_ESCAPES['\t'] = 't';
        LKP_ESCAPES['\n'] = 'n';
        LKP_ESCAPES['\r'] = 'r';
        LKP_ESCAPES['\f'] = 'f';
        LKP_ESCAPES['"'] = '"';
        LKP_ESCAPES['\''] = '\'';
        LKP_ESCAPES['\\'] = '\\';
    }
    /**
     * concatenate bufs.
     * @param bufs parts to concatenate
     * @return concatenated
     */
    public static byte[] cat(byte[]... bufs) {
        if (bufs == null) {
            return null;
        }
        int l = 0;
        for (int i = 0; i < bufs.length; i++) {
            l += bufs[i] == null ? 0 : bufs[i].length;
        }

        byte[] result = new byte[l];
        cat(result, 0, bufs);
        return result;
    }

    /**
     * cat into dest starting at start.
     * @param dest destination
     * @param start position to start writing
     * @param bufs parts to concatenate
     */
    public static void cat(byte[] dest, int start, byte[]... bufs) {
        if (bufs == null) {
            return;
        }
        for (int i = 0; i < bufs.length; i++) {
            if (bufs[i] != null) {
                System.arraycopy(bufs[i], 0, dest, start, bufs[i].length);
                start += bufs[i].length;
            }
        }
    }

    /**
     * Substring of buf.  Allows negative indexing as per python.
     * If range of substring outside range of buf, then result is zero-padded.
     * Result will be left justified if start is positive,
     * right-justified if start is negative.
     * @param src src to get sub buf
     * @param start index to start
     * @param len index to end
     * @return buf len (end - start) containing src
     */
    public static byte[] substring(byte[] src, int start, int len) {
        if (len < 0) {
            throw new IllegalArgumentException("len cannot be negative, got: " + len);
        }

        if (src == null) { src = new byte[0]; }
        if (src != null && start == 0 && len == src.length) {
            return src;
        }

        // result is src
        if (len == src.length && (start == 0 || start == -src.length)) {
            return src;
        }

        byte[] result = new byte[len];
        // left-justified
        if (start >= 0 && start < src.length) {
            int tocopy = Math.min(len, src.length - start);
            System.arraycopy(src, start, result, 0, tocopy);

        // right-justified
        } else if (start < 0 && start + src.length + len > 0) {
            start += src.length;
            int tocopy = start < 0 ?
                    Math.min(len + start, src.length)
                    : Math.min(len, src.length - start);
            System.arraycopy(src, Math.max(0, start), result, len - tocopy, tocopy);
        }

        return result;
    }

    /**
     * Return java-escaped string enclosed in double quotes.
     * @param buf buf
     * @return java-escaped string enclosed in double quotes
     */
    public static String escstr(byte[] buf) {
        if (buf == null) {
            return null;
        }
        // size for totally printable string - should help perf
        StringBuilder sb = new StringBuilder(buf.length + 2);
        sb.append('"');
        for (int i = 0; i < buf.length; i++) {
            int c = buf[i] & 0xff;
            int escape = LKP_ESCAPES[c];
            // printable without escape
            if (escape == 0) {
                sb.append((char) c);
            } else if (escape != -1) {
                sb.append('\\').append((char) escape);
            } else {
                sb.append("\\u00").append(Hex.HEX_B2S[buf[i] & 0xff]);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    /**
     * Convert char array to byte array using single byte encoding.
     * Each char is cast to byte.
     * @param c char array
     * @return byte array with each char cast to byte
     */
    public static byte[] c2b(char[] c) {
        if (c == null) return null;
        byte[] result = new byte[c.length];
        for (int i = 0; i < c.length; i++) {
            result[i] = (byte) c[i];
        }
        return result;
    }

    /**  
     * Convert string to byte array using single byte encoding.
     * Each char is cast to byte.
     * @param s string
     * @return byte array with each char cast to byte
     */
    public static byte[] c2b(String s) {
        if (s == null) return null;
        return c2b(s.toCharArray());
    }
}
