/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.certificateauthority;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CsrDAO;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.data.CsrInfo;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.List;

/**
 * This class contains the services that will be used by the CA users
 */
public class CaUserService {
    private static final Log log = LogFactory.getLog(CaUserService.class);

    private CsrDAO csrDAO = new CsrDAO();
    private CertificateDAO certificateDAO = new CertificateDAO();

    /**
     * Sends a CSR to the CA to be signed
     * @param csr PEM encoded CSR
     * @return The serial no of the CSR that was stored at CA
     * @throws CaException
     */
    public String addCsr(String csr) throws CaException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return csrDAO.addCsr(csr, username, tenantId, userStoreDomain);
    }

    /**
     * Gets the CSR specified by the given serial no
     * @param serial The serial no
     * @return The CSR
     * @throws CaException
     */
    public CsrInfo getCsr(String serial) throws CaException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return csrDAO.getCSR(serial, userStoreDomain, username, tenantID);
    }

    /**
     * Gets the CSR list requested by the current user
     * @return List of CSRs by the current user
     * @throws CaException
     */
    public CsrInfo[] getCsrList() throws CaException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        List<CsrInfo> csrList = csrDAO.listCsrs(username, userStoreDomain, tenantID);
        return csrList.toArray(new CsrInfo[csrList.size()]);
    }

    /**
     * Gets the certificate given by the serial no
     * @param serialNo The serial no of the certificate
     * @return The certificate with the given serial no
     * @throws CaException
     */
    public CertificateInfo getCertificate(String serialNo) throws CaException {
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return certificateDAO.getCertificateInfo(serialNo, tenantID);
    }
}