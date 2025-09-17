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
 *    Technology" must not be used to endorse or promote products derived from
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

@Structure.FieldOrder({"mechanism", "pParameter", "ulParameterLen"})
public class CK_MECHANISM extends Pkcs11Structure {
    public NativeLong mechanism;
    public Pointer pParameter;
    public NativeLong ulParameterLen;

    public CK_MECHANISM() {
    }

    public CK_MECHANISM(long mech, Pointer pParam, long ulParamLen) {
        this(new NativeLong(mech), pParam, new NativeLong(ulParamLen));
    }

    public CK_MECHANISM(NativeLong mech, Pointer pParam, NativeLong ulParamLen) {
        mechanism = mech;
        pParameter = pParam;
        ulParameterLen = ulParamLen;
    }
    
    public static class ByReference extends CK_MECHANISM implements Structure.ByReference {}
    public static class ByValue extends CK_MECHANISM implements Structure.ByValue {}
}