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

package org.wso2.carbon.identity.certificateauthority.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;

import java.io.*;
import java.security.PrivateKey;
import java.security.cert.*;

/**
 * Contains the Util methods to encode/decode the certificates, CSRs, CRLs,..
 */
public class CaObjectUtils {
    private static final Log log = LogFactory.getLog(CaObjectUtils.class);

    private CaObjectUtils() {
    }

    /**
     * Decode base 64 encoded CRL to X509CRL
     * @param encodedCrl The crl in base 64 encoded format
     * @return
     * @throws CaException
     */
    public static X509CRL toX509Crl(String encodedCrl) throws CaException {
        try {
            byte[] b64DecodeBytes = Base64.decode(encodedCrl.getBytes(CaConstants.UTF_8_CHARSET));
            CertificateFactory certificateFactory =
                    CertificateFactory.getInstance(CaConstants.X509);
            return (X509CRL) certificateFactory
                    .generateCRL(new ByteArrayInputStream(b64DecodeBytes));
        } catch (CRLException e) {
            log.error("Can't decode CRL.", e);
            throw new CaException("Unable to decode given CRL", e);
        } catch (CertificateException e) {
            log.error("Couldn't create certificate factory", e);
            throw new CaException("Error creating X509CRL", e);
        } catch (UnsupportedEncodingException e) {
            log.error("Error with the charset used", e);
            throw new CaException("Error creating X509CRL", e);
        }
    }

    /**
     * PEM encode a given certificate
     * @param certificate The X509 certificate to be encoded
     * @return
     */
    public static String toPemEncodedCertificate(X509Certificate certificate) {
        try {
            StringWriter stringWriter = new StringWriter();
            PEMWriter writer = new PEMWriter(stringWriter);
            writer.writeObject(certificate);
            writer.close();
            return stringWriter.toString();
        } catch (IOException ignored) {
            return "";
        }
    }

    /**
     * Decode a base 64 encoded csr into a PKCS10CertificateRequest
     *
     * @param encodedCsr Base 64 encoded CSR
     * @return PKCS10CertificationRequest constructed from the encoded string
     */
    public static PKCS10CertificationRequest toPkcs10CertificationRequest(String encodedCsr)
            throws CaException {
        try {
            PEMParser pemParser = new PEMParser(new InputStreamReader(new ByteArrayInputStream
                    (encodedCsr.getBytes(CaConstants.UTF_8_CHARSET)),CaConstants.UTF_8_CHARSET));
            return (PKCS10CertificationRequest) pemParser.readObject();
        } catch (IOException e) {
            throw new CaException("Error parsing encoded request", e);
        }
    }

    /**
     * Encode a CSR to a PEM encoded String
     * @param request The CSR to be PEM encoded
     * @return The PEM encoded representation of the CSR
     * @throws CaException
     */
    public static String toEncodedCsr(PKCS10CertificationRequest request) throws CaException {
        try {
            StringWriter writer = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(writer);
            pemWriter.writeObject(request);
            writer.close();
            pemWriter.close();
            return writer.toString();
        } catch (IOException e) {
            throw new CaException("Error encoding the request", e);
        }
    }

    /**
     * PEM encode a private key
     * @param key The key to be PEM encoded
     * @return
     * @throws CaException
     */
    public static String toEncodedPrivateKey(PrivateKey key) throws CaException {
        try {
            StringWriter writer = new StringWriter();
            PEMWriter pemWriter = new PEMWriter(writer);
            pemWriter.writeObject(key);
            writer.close();
            pemWriter.close();
            return writer.toString();
        } catch (IOException e) {
            throw new CaException("Error encoding the private key", e);
        }
    }
}
