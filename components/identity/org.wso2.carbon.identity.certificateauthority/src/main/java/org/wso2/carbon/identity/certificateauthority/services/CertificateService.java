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

package org.wso2.carbon.identity.certificateauthority.services;

import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.bean.Certificate;
import org.wso2.carbon.identity.certificateauthority.bean.RevokedCertificate;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateService {
    /**
     * Signs the CSR with the given serial no, so that the resulting certificate will have the
     * given validity period from the time of signing
     *
     * @param serialNo The serial no of the CSR to be signed
     * @param validity The validity of the resulting certificate in days
     * @throws org.wso2.carbon.identity.certificateauthority.CAException If signing or storing the certificate fails
     */
    public void signCSR(String tenantDomain, String serialNo, int validity) throws CAException;

    /**
     * Revoke or update the revoke reason for the given certificate
     *
     * @param tenantDomain the tenant domain of the CA
     * @param serialNo     The serial no of the certificate to be revoked
     * @param reason       The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public void revokeCert(String tenantDomain, String serialNo, int reason) throws CAException;

    /**
     * Revokes all certificates issued by a tenant ID
     *
     * @param tenantDomain The tenant id of the CA
     * @param revokeReason The reason code for the revocation as specified in
     *                     {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public void revokeAllIssuedCertificates(String tenantDomain, int revokeReason) throws CAException;

    /**
     * Get the PEM encoded Certificate for the given serial no
     *
     * @param serialNo The serial no of the certificate
     * @return The certificate as a PEM encoded string
     * @throws CAException
     */
    public String getPemEncodedCertificate(String serialNo) throws CAException;

    /**
     * Get the certificate in X509 format for the given serial no
     *
     * @param serialNo The serial no of the certificate
     * @return The certificate in X509 format
     * @throws CAException
     */
    public X509Certificate getX509Certificate(String serialNo) throws CAException;

    /**
     * Get the certificate specified by the serial number.
     *
     * @param serialNo serial number of the certificate
     * @return Information about the certificate
     */
    public Certificate getCertificate(String serialNo, String tenantDomain) throws CAException;

    /**
     * Lists all certificates issued by a tenant's CA.
     *
     * @param tenantDomain domain of the tenant
     * @return Set of certificates with given status issued by the given CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<Certificate> listCertificates(String tenantDomain) throws CAException;

    /**
     * Lists all certificates issued by a tenant's CA with given status
     *
     * @param status       Status filter for the certificates
     * @param tenantDomain domain of the tenant
     * @return Set of certificates with given status issued by the given CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<Certificate> listCertificates(String status, String tenantDomain) throws CAException;

    /**
     * Get Revoked certificate details from serial number
     *
     * @param serialNo The SerialNo of the revoked certificate
     * @return The details of the revoked certificate
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CAException;

}
