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

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.identity.certificateauthority.CAException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * The service interface for SCEP services.
 */
public interface SCEPService {

    /**
     * Enrolls a CSR from SCEP protocol.
     *
     * @param certReq       The certificate request
     * @param transactionId The transcation id that is used to identify the SCEP transaction
     * @param tenantDomain  The tenant domain for which the request is made
     * @return The enrolled certificate
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate enroll(PKCS10CertificationRequest certReq, String transactionId, String tenantDomain)
            throws CAException;

    /**
     * Gets the certificate that is issued in the transaction identified by transactionId.
     *
     * @param tenantDomain  The tenant domain for which the request is made
     * @param transactionId The transcation id that is used to identify the SCEP transaction
     * @return The enrolled certificate for the transaction
     * @throws CAException
     */
    public X509Certificate getCertificate(String tenantDomain, String transactionId) throws CAException;

    /**
     * Gives the CA certificate for the given tenant.
     *
     * @param tenantDomain The tenant domain whose CA certificate is required
     * @return The CA certificate for the tenant
     * @throws CAException
     */
    public X509Certificate getCaCert(String tenantDomain) throws CAException;

    /**
     * Gets the CA's private key for the SCEP operations.
     *
     * @param tenantDomain The tenant domain whose CA key is required
     * @return The CA's private key
     * @throws CAException
     */
    public PrivateKey getCaKey(String tenantDomain) throws CAException;

    /**
     * Generate a SCEP token to be used for SCEP operations.
     *
     * @param userName        The user who is generating the token
     * @param tenantDomain    The tenant domain of the user
     * @param userStoreDomain The user store domain of the user
     * @return The generated SCEP token
     * @throws CAException
     */
    public String generateScepToken(String userName, String tenantDomain, String userStoreDomain) throws CAException;
}
