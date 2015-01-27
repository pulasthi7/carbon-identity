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

import java.security.cert.X509CRL;

/**
 * The service interface for CRL services.
 */
public interface CRLService {
    /**
     * Create and stores a new CRL.
     *
     * @throws CAException
     */
    public void addCRL() throws CAException;

    /**
     * Create and stores a new delta CRL.
     *
     * @throws CAException
     */
    public void addDeltaCrl() throws CAException;

    /**
     * Gets the latest CRL in binary format.
     *
     * @param tenantDomain The tenant domain of the CA
     * @return The CRL in binary format
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public byte[] getLatestCrl(String tenantDomain) throws CAException;

    /**
     * Gets the latest delta CRL in binary format.
     *
     * @param tenantDomain The tenant domain of the CA
     * @return The deltaCRL in binary format
     * @throws CAException
     */
    public byte[] getLatestDeltaCrl(String tenantDomain) throws CAException;

    /**
     * Update the CRL.
     *
     * @throws CAException
     */
    public void updateCrl() throws CAException;

    /**
     * Get the latest CRL for the tenant CA.
     *
     * @param tenantDomain The tenant domain of the CA
     * @return CRL of CA in X509 format
     * @throws CAException
     */
    public X509CRL getLatestX509Crl(String tenantDomain) throws CAException;

    /**
     * Create full CRL for the given tenant.
     *
     * @param tenantDomain The tenant domain
     * @return Full CRL of the tenant
     * @throws CAException
     */
    public X509CRL createFullCrl(String tenantDomain) throws CAException;

    /**
     * Create delta CRL for the given tenant.
     *
     * @param tenantDomain The tenant domain of the CA
     * @return The delta CRL of the tenant CA
     * @throws CAException
     */
    public X509CRL createDeltaCrl(String tenantDomain) throws CAException;

    /**
     * Creates and store a CRL in db for the given tenant.
     *
     * @param tenantDomain The tenant domain of the CA
     * @throws CAException
     */
    public void createAndStoreCrl(String tenantDomain) throws CAException;

    /**
     * Create and store a delta CRL in database.
     *
     * @param tenantDomain The tenant id of the CA
     * @throws CAException
     */
    public void createAndStoreDeltaCrl(String tenantDomain) throws CAException;
}
