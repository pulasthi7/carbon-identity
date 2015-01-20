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

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.dao.CSRDAO;
import org.wso2.carbon.identity.certificateauthority.model.CSR;

import java.util.List;

public class CSRService {

    private static CSRService instance = new CSRService();
    private CSRDAO csrDAO = new CSRDAO();

    private CSRService() {
    }

    public static CSRService getInstance() {
        return instance;
    }

    /**
     * Adds a new CSR to the DB
     *
     * @param csrContent      The CSR as an encoded string
     * @param userName        The user who requested the CSR to sign
     * @param tenantDomain    The domain of the tenant where the user belongs
     * @param userStoreDomain The user store where the user is
     * @return The serial no of the newly added CSR, which can be used in later queries
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String addCSR(String csrContent, String userName, String tenantDomain, String userStoreDomain)
            throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(csrContent)){
            throw new IllegalArgumentException("CSR content cannot be empty");
        }
        if(StringUtils.isEmpty(userName)){
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if(StringUtils.isEmpty(userStoreDomain)){
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.addCSR(csrContent, userName, tenantDomain, userStoreDomain);
    }

    /**
     * Retrieve the CSR details for the given serial no
     *
     * @param serialNo     The serial no of the CSR to be retrieved
     * @param tenantDomain The id of the tenant CA
     * @return The CSR details
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public CSR getCSR(String serialNo, String userStoreDomain, String userName, String tenantDomain)
            throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(serialNo)){
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        if(StringUtils.isEmpty(userName)){
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if(StringUtils.isEmpty(userStoreDomain)){
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.getCSR(serialNo, userStoreDomain, userName, tenantDomain);
    }

    /**
     * Retrieve the CSR for the given serial no
     *
     * @param serialNo     The serial no of the CSR to be retrieved
     * @param tenantDomain The id of the tenant CA
     * @return The CSR details
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public CSR getCSR(String serialNo, String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(serialNo)){
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return csrDAO.getCSR(serialNo, tenantDomain);
    }

    /**
     * Mark the CSR as a rejected one
     *
     * @param serialNo     The serial no of the CSR to be marked as rejected
     * @param tenantDomain The domain of the tenant CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void rejectCSR(String serialNo, String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(serialNo)){
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        csrDAO.rejectCSR(serialNo, tenantDomain);
    }

    /**
     * Lists CSRs that are for the given tenant
     *
     * @param tenantDomain The domain of the tenant whose CSRs need to be listed
     * @return The list of CSRs for the tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRs(String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        return csrDAO.listCSRs(tenantDomain);
    }

    /**
     * Lists CSRs requested by a user
     *
     * @param userName        The username of the user whose CSRs need to be listed
     * @param userStoreDomain The user store where the user is
     * @param tenantDomain    The domain of the tenant where the user belongs
     * @return List of CSRs from the user
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRs(String userName, String userStoreDomain, String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(userName)){
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if(StringUtils.isEmpty(userStoreDomain)){
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.listCSRs(userName, userStoreDomain, tenantDomain);
    }

    /**
     * Lists CSRs by status for a given tenant CA
     *
     * @param tenantDomain The domain of the tenant whose CSRs need to be listed
     * @param status       The filter for the status
     * @return List of CSRs with the given status
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRsByStatus(String tenantDomain, String status) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(status)){
            throw new IllegalArgumentException("Certificate status cannot be empty");
        }
        return csrDAO.listCSRsByStatus(tenantDomain, status);
    }

    /**
     * Delete the CSR with given serial number
     *
     * @param serialNo     The serial no of the CSR to be deleted
     * @param tenantDomain The domain of the tenant CA
     * @throws CAException
     */
    public void deleteCSR(String serialNo, String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if(StringUtils.isEmpty(serialNo)){
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        csrDAO.deleteCSR(serialNo, tenantDomain);
    }

    /**
     * Retrieves the CSR by serial number
     *
     * @param serialNo The serial no of the CSR to be retrieved
     * @return The CSR as a PKCS10CertificationRequest
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PKCS10CertificationRequest getPKCS10CertificationRequest(String serialNo) throws CAException {
        if(StringUtils.isEmpty(serialNo)){
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return csrDAO.getPKCS10CertificationRequest(serialNo);
    }
}
