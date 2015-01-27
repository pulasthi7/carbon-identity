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
import org.wso2.carbon.registry.core.Registry;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

public interface CAConfigurationService {

    /**
     * Gives the CA certificate of the current tenant. Returns the default certificate if
     * certificate is not configured.
     *
     * @return The CA certificate of the current tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCACert() throws CAException;

    /**
     * Gives the CA certificate of the tenant given by the tenantId. Returns the default certificate
     * if certificate is not configured.
     *
     * @param tenantDomain The tenant domain of the tenant whose certificate should be returned
     * @return The CA certificate of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCACert(String tenantDomain) throws CAException;

    /**
     * Return the CA certificate of the tenant specified by the tenantDomain as a PEM encoded
     * string.
     *
     * @param tenantDomain The tenantDomain whose certificate is needed
     * @return The CA certificate as a PEM encoded string
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String getPemEncodedCACert(String tenantDomain) throws CAException;

    /**
     * Returns the private key of the current tenant which is used to sign CSRs,
     * CRL and OCSP requests
     *
     * @return The private key of the current tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PrivateKey getConfiguredPrivateKey() throws CAException;

    /**
     * Returns the private key of the given tenant, which is used to sign CSRs,
     * CRL and OCSP requests
     *
     * @return The private key of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PrivateKey getConfiguredPrivateKey(String tenantDomain) throws CAException;

    /**
     * Lists all the keys available for the current tenant. Tenant admin can configure one of
     * them as the key to sign the CSRs, CRLs and OCSP requests
     *
     * @param registry The registry where the keystores are
     * @return List of keystores and key aliases in the format "keystore/alias"
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<String> listAllKeys(Registry registry) throws CAException;

    /**
     * Update the key that the tenant will be using for CA operations.<br/>
     * <b>Note: </b> Updating the key will revoke all the certificates that were signed using the
     * key
     *
     * @param tenantDomain The tenant domain of the tenant whose key should be updated
     * @param keyStore     The new keystore where the key is
     * @param alias        The alias for the key
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void updateKey(String tenantDomain, String keyStore, String alias) throws CAException;

    /**
     * Get the validity of a generated SCEP token
     *
     * @return
     */
    public int getTokenValidity();

    /**
     * Get the length of the SCEP token.
     *
     * @return
     */
    public int getTokenLength();

    /**
     * Get the validity of the certificates that are issued from a SCEP operation
     *
     * @return
     */
    public int getSCEPIssuedCertificateValidity();
}
