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
import org.wso2.carbon.identity.certificateauthority.bean.CSR;
import org.wso2.carbon.identity.certificateauthority.dao.CSRDAO;

import java.util.List;

/**
 * The implementation for CSRService.
 */
public class CSRServiceImpl implements CSRService {

    private static CSRService instance = new CSRServiceImpl();
    private CSRDAO csrDAO = new CSRDAO();

    private CSRServiceImpl() {
    }

    public static CSRService getInstance() {
        return instance;
    }

    @Override
    public String addCSR(String csrContent, String userName, String tenantDomain, String userStoreDomain)
            throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(csrContent)) {
            throw new IllegalArgumentException("CSR content cannot be empty");
        }
        if (StringUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if (StringUtils.isEmpty(userStoreDomain)) {
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.addCSR(csrContent, userName, tenantDomain, userStoreDomain);
    }

    @Override
    public CSR getCSR(String serialNo, String userStoreDomain, String userName, String tenantDomain)
            throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        if (StringUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if (StringUtils.isEmpty(userStoreDomain)) {
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.getCSR(serialNo, userStoreDomain, userName, tenantDomain);
    }

    @Override
    public CSR getCSR(String serialNo, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return csrDAO.getCSR(serialNo, tenantDomain);
    }

    @Override
    public void rejectCSR(String serialNo, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        csrDAO.rejectCSR(serialNo, tenantDomain);
    }

    @Override
    public List<CSR> listCSRs(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        return csrDAO.listCSRs(tenantDomain);
    }

    @Override
    public List<CSR> listCSRs(String userName, String userStoreDomain, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if (StringUtils.isEmpty(userStoreDomain)) {
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        return csrDAO.listCSRs(userName, userStoreDomain, tenantDomain);
    }

    @Override
    public List<CSR> listCSRsByStatus(String tenantDomain, String status) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(status)) {
            throw new IllegalArgumentException("Certificate status cannot be empty");
        }
        return csrDAO.listCSRsByStatus(tenantDomain, status);
    }

    @Override
    public void deleteCSR(String serialNo, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        csrDAO.deleteCSR(serialNo, tenantDomain);
    }

    @Override
    public PKCS10CertificationRequest getPKCS10CertificationRequest(String serialNo) throws CAException {
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return csrDAO.getPKCS10CertificationRequest(serialNo);
    }
}
