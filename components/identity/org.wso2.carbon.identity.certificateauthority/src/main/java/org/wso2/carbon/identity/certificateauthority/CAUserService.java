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

import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.dao.CSRDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.model.CSR;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.List;

/**
 * This class contains the services that will be used by the CA users
 */
@SuppressWarnings("UnusedDeclaration")
public class CAUserService {
    private static final Log log = LogFactory.getLog(CAUserService.class);

    private CSRDAO csrDAO = new CSRDAO();
    private CertificateDAO certificateDAO = new CertificateDAO();

    /**
     * Sends a CSR to the CA to be signed
     *
     * @param encodedCSR PEM encoded CSR
     * @return The serial number of the CSR that was stored at CA
     * @throws AxisFault
     */
    public String addCSR(String encodedCSR) throws AxisFault {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            return csrDAO.addCsr(encodedCSR, username, tenantDomain, userStoreDomain);
        } catch (CAException e) {
            log.error("Could not add CSR for user " + userStoreDomain + "\\" + username + "@" + tenantDomain, e);
            throw new AxisFault("Could not store the CSR");
        }
    }

    /**
     * Gets the CSR specified by the given serial number
     *
     * @param serialNo The serial number
     * @return The CSR
     * @throws AxisFault
     */
    public CSR getCSR(String serialNo) throws AxisFault {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        try {
            return csrDAO.getCSR(serialNo, userStoreDomain, username, tenantDomain);
        } catch (CAException e) {
            log.error("Error when retrieving the CSR, serial no:" + serialNo + ", user:" + userStoreDomain + "\\" +
                    username + "@" + tenantDomain, e);
            throw new AxisFault("Could not retrieve the CSR");
        }
    }

    /**
     * Gets the CSR list requested by the current user
     *
     * @return List of CSRs by the current user
     * @throws AxisFault
     */
    public CSR[] listCSRs() throws AxisFault {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            List<CSR> csrList = csrDAO.listCSRs(username, userStoreDomain, tenantDomain);
            return csrList.toArray(new CSR[csrList.size()]);
        } catch (CAException e) {
            log.error("Error when retrieving the CSR list for user:" + userStoreDomain + "\\" + username + "@" +
                    tenantDomain, e);
            throw new AxisFault("Error when listing CSRs");
        }
    }

    /**
     * Gets the certificate given by the serial number
     *
     * @param serialNo The serial number of the certificate
     * @return The certificate with the given serial number
     * @throws AxisFault
     */
    public Certificate getCertificate(String serialNo) throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            return certificateDAO.getCertificateInfo(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error when retrieving the certificate. Serial no:" + serialNo + ", tenant:" + tenantDomain, e);
            throw new AxisFault("Error when retrieving the certificate");
        }
    }
}
