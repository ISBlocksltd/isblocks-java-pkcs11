/*
 * Copyright (c) 2018, JSC Aktiv-Soft. See the LICENSES/Aktiv-Soft file at the top-level directory of this distribution.
 * All Rights Reserved.
 */

/*
 * reserved comment block
 * DO NOT REMOVE OR ALTER!
 */
/* Copyright  (c) 2002 Graz University of Technology. All rights reserved.
 *
 * Redistribution and use in  source and binary forms, with or without
 * modification, are permitted  provided that the following conditions are met:
 *
 * 1. Redistributions of  source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in  binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The end-user documentation included with the redistribution, if any, must
 *    include the following acknowledgment:
 *
 *    "This product includes software developed by IAIK of Graz University of
 *     Technology."
 *
 *    Alternately, this acknowledgment may appear in the software itself, if
 *    and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Graz University of Technology" and "IAIK of Graz University of
 *     Technology" must not be used to endorse or promote products derived from
 *    this software without prior written permission.
 *
 * 5. Products derived from this software may not be called
 *    "IAIK PKCS Wrapper", nor may "IAIK" appear in their name, without prior
 *    written permission of Graz University of Technology.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESSED OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *  PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE LICENSOR BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *  OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 *  OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY  OF SUCH DAMAGE.
 */

package com.isblocks.pkcs11;

/*
 * @author Karl Scheibelhofer <Karl.Scheibelhofer@iaik.at>
 * @author Martin Schlaeffer <schlaeff@sbox.tugraz.at>
 * @author Aktiv Co. <hotline@rutoken.ru>
 */

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.Memory;
/**
 * CK_GCM_PARAMS provides the parameters for the CKM_AES_GCM mechanism.
 * 
 * <pre>
 * typedef struct CK_GCM_PARAMS {
 *     CK_BYTE_PTR       pIv;
 *     CK_ULONG          ulIvLen;
 *     CK_ULONG          ulIvBits;
 *     CK_BYTE_PTR       pAAD;
 *     CK_ULONG          ulAADLen;
 *     CK_ULONG          ulTagBits;
 * } CK_GCM_PARAMS;
 * </pre>
 */
@Structure.FieldOrder({"pIv", "ulIvLen", "ulIvBits", "pAAD", "ulAADLen", "ulTagBits"})
public class CK_GCM_PARAMS extends Pkcs11Structure {
    /** Pointer to the initialization vector */
    public Pointer pIv;
    /** Length of the initialization vector in bytes */
    public NativeLong ulIvLen;
    /** Length of the initialization vector in bits */
    public NativeLong ulIvBits;
    /** Pointer to the additional authenticated data */
    public Pointer pAAD;
    /** Length of the additional authenticated data in bytes */
    public NativeLong ulAADLen;
    /** Length of the authentication tag in bits */
    public NativeLong ulTagBits;

    public CK_GCM_PARAMS() {
    }

    public CK_GCM_PARAMS(Pointer pIv, long ulIvLen, long ulIvBits, 
                        Pointer pAAD, long ulAADLen, long ulTagBits) {
        this.pIv = pIv;
        this.ulIvLen = new NativeLong(ulIvLen);
        this.ulIvBits = new NativeLong(ulIvBits);
        this.pAAD = pAAD;
        this.ulAADLen = new NativeLong(ulAADLen);
        this.ulTagBits = new NativeLong(ulTagBits);
    }

    public CK_GCM_PARAMS(Pointer pIv, NativeLong ulIvLen, NativeLong ulIvBits, 
                        Pointer pAAD, NativeLong ulAADLen, NativeLong ulTagBits) {
        this.pIv = pIv;
        this.ulIvLen = ulIvLen;
        this.ulIvBits = ulIvBits;
        this.pAAD = pAAD;
        this.ulAADLen = ulAADLen;
        this.ulTagBits = ulTagBits;
    }

    public CK_GCM_PARAMS(byte iv[], byte aad[], long ulTagBits) {
        if (iv != null && iv.length > 0) {
            this.pIv = new Memory(iv.length);
            this.pIv.write(0, iv, 0, iv.length);
            this.ulIvLen = new NativeLong(iv.length);
            this.ulIvBits = new NativeLong(iv.length * 8);
        } else {
            this.pIv = null;
            this.ulIvLen = new NativeLong(0);
            this.ulIvBits = new NativeLong(0);
        }
        if (aad != null && aad.length > 0) {
            this.pAAD = new Memory(aad.length);
            this.pAAD.write(0, aad, 0, aad.length);
            this.ulAADLen = new NativeLong(aad.length);
        } else {
            this.pAAD = null;
            this.ulAADLen = new NativeLong(0);
        }
        this.ulTagBits = new NativeLong(ulTagBits);

  
    }
    public static class ByReference extends CK_GCM_PARAMS implements Structure.ByReference {}
    public static class ByValue extends CK_GCM_PARAMS implements Structure.ByValue {}
}
