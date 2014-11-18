/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.certificateauthority;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.wso2.carbon.identity.certificateauthority.utils.ConversionUtils;

import java.security.*;

public class CsrGenerator {
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;
    private KeyPairGenerator keyGen = null;

    public String getPrivateKey() throws CaException {
        return ConversionUtils.toEncodedPrivateKey(privateKey);
    }

    public String generateCSR(String alg, int keyLength, String cn, String ou, String o, String l,
                              String st, String c) throws Exception {
        keyGen = KeyPairGenerator.getInstance(alg);
        keyGen.initialize(keyLength, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        X500Name x500Name = buildX500Name(cn.trim(), ou.trim(), o.trim(), l.trim(), st.trim(),
                c.trim());
        PKCS10CertificationRequest csr = generatePKCS10(x500Name);
        return ConversionUtils.toEncodedCsr(csr);
    }

    private X500Name buildX500Name(String cn, String ou, String o, String l, String st, String c)
            throws CaException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        if (cn == null || "".equals(cn)) {
            throw new CaException("Common Name (CN) should have a non empty value");
        }
        x500NameBuilder.addRDN(BCStyle.CN,cn);
        if(ou !=null && !"".equals(ou)){
            x500NameBuilder.addRDN(BCStyle.OU,ou);
        }
        if(o !=null && !"".equals(o)){
            x500NameBuilder.addRDN(BCStyle.O,o);
        }
        if(l !=null && !"".equals(l)){
            x500NameBuilder.addRDN(BCStyle.L,l);
        }
        if(st !=null && !"".equals(st)){
            x500NameBuilder.addRDN(BCStyle.ST,st);
        }
        if(c !=null && !"".equals(c)){
            x500NameBuilder.addRDN(BCStyle.C,c);
        }
        return x500NameBuilder.build();
    }

    private PKCS10CertificationRequest generatePKCS10(X500Name x500Name) throws Exception {
        PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                x500Name, publicKey);
        JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(CaConstants.SHA256_WITH_RSA);
        ContentSigner signer = csBuilder.build(privateKey);
        return p10Builder.build(signer);
    }
}
