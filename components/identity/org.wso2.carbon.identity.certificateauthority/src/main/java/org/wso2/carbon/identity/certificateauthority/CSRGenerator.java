/*
 * Copyright (c) 2015 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * This contains the methods required to generate key pairs, and CSRs.
 */
@SuppressWarnings("UnusedDeclaration")
public class CSRGenerator {
    private PublicKey publicKey = null;
    private PrivateKey privateKey = null;

    public String getPrivateKey() throws CAException {
        try {
            return CAObjectUtils.toEncodedPrivateKey(privateKey);
        } catch (IOException e) {
            throw new CAException("Error when encoding the private key to PEM", e);
        }
    }

    /**
     * Generate a CSR from given attributes.
     *
     * @param alg       The signature algorithm
     * @param keyLength The key length to be used in key generation
     * @param cn        Common name
     * @param ou        Organization unit
     * @param o         Organization
     * @param l         City
     * @param st        State
     * @param c         Country
     * @return The generated PEM encoded CSR
     * @throws Exception
     */
    public String generateCSR(String alg, int keyLength, String cn, String ou, String o, String l, String st,
                              String c) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(alg);
        keyGen.initialize(keyLength, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        publicKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();
        X500Name x500Name = buildX500Name(cn.trim(), ou.trim(), o.trim(), l.trim(), st.trim(), c.trim());
        PKCS10CertificationRequest csr = generatePKCS10(x500Name);
        return CAObjectUtils.toEncodedCsr(csr);
    }

    /**
     * Builds X500 name with the provided values, any null values will be ignored except for CN
     * which is mandatory.
     *
     * @param cn Common name
     * @param ou Organization unit
     * @param o  Organization
     * @param l  City
     * @param st State
     * @param c  Country
     * @return The X500 name build from not-null values
     * @throws CAException
     */
    private X500Name buildX500Name(String cn, String ou, String o, String l, String st, String c)
            throws CAException {
        X500NameBuilder x500NameBuilder = new X500NameBuilder();
        //CN is mandatory
        if (StringUtils.isBlank(cn)) {
            throw new CAException("Common Name (CN) should have a non empty value");
        }
        x500NameBuilder.addRDN(BCStyle.CN, cn);
        //These fields are optional and will be included only if given
        if (StringUtils.isNotBlank(ou)) {
            x500NameBuilder.addRDN(BCStyle.OU, ou);
        }
        if (StringUtils.isNotBlank(o)) {
            x500NameBuilder.addRDN(BCStyle.O, o);
        }
        if (StringUtils.isNotBlank(l)) {
            x500NameBuilder.addRDN(BCStyle.L, l);
        }
        if (StringUtils.isNotBlank(st)) {
            x500NameBuilder.addRDN(BCStyle.ST, st);
        }
        if (StringUtils.isNotBlank(c)) {
            x500NameBuilder.addRDN(BCStyle.C, c);
        }
        return x500NameBuilder.build();
    }

    /**
     * Generate PKCS10CertificationRequest from given X500name.
     *
     * @param x500Name The X500Name for the resulting PKCS10CertificationRequest
     * @return PKCS10CertificationRequest for the public key
     * @throws CAException
     */
    private PKCS10CertificationRequest generatePKCS10(X500Name x500Name) throws CAException {
        try {
            PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(x500Name,
                    publicKey);
            JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(CAConstants.SHA256_WITH_RSA);
            ContentSigner signer = csBuilder.build(privateKey);
            return p10Builder.build(signer);
        } catch (OperatorCreationException e) {
            throw new CAException("Error when generating CSR for " + x500Name.toString(), e);
        }
    }
}
