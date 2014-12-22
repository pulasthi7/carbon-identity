/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CSRDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.model.CSR;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.List;

public class CAAdminService extends AbstractAdmin {

    private CSRDAO csrDAO;
    private CertificateDAO certificateDAO;
    private RevocationDAO revokeDAO;

    public CAAdminService() {
        csrDAO = new CSRDAO();
        certificateDAO = new CertificateDAO();
        revokeDAO = new RevocationDAO();
    }

    /**
     * Get the list of CSR assigned to the current tenant
     *
     * @return list of CSR assigned to the current tenant
     */
    public CSR[] getCsrList() throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CSR> csrList = csrDAO.listCsrs(tenantId);
        return csrList.toArray(new CSR[csrList.size()]);
    }

    /**
     * Revokes certificate with given serial no, specifying the given revoke reason
     *
     * @param serial The serial no of the certificate to be revoked
     * @param reason The reason code for the revocation
     * @throws Exception
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void revokeCert(String serial, int reason) throws Exception {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CertificateManager.getInstance().revokeCert(tenantId, serial, reason);
        CRLManager.getInstance().createAndStoreDeltaCrl(tenantId);

    }

    /**
     * Lists keys available for the tenant admin. The current configured key is the first of the
     * list
     *
     * @return A list of keys available for tenant admin
     * @throws CAException
     */
    public String[] listKeyAliases() throws CAException {
        List<String> keyList = CAConfiguration.getInstance().listAllKeys
                (getGovernanceSystemRegistry());
        return keyList.toArray(new String[keyList.size()]);
    }

    /**
     * Get the certificate attributes for the certificate with given serial number
     *
     * @param serialNo The serial no of the certificate
     * @return The certificate
     * @throws CAException
     */
    public Certificate getCertificate(String serialNo) throws CAException {
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return certificateDAO.getCertificateInfo(serialNo, tenantID);
    }

    /**
     * Lists all the certificate issued by the tenant CA
     *
     * @return
     * @throws CAException
     */
    public Certificate[] getTenantIssuedCertificates() throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<Certificate> certificateInfoList = certificateDAO.listCertificates(tenantId);
        return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
    }

    /**
     * Lists all the certificates issued by the tenant CA filtered by the given status
     *
     * @param status The status filter
     * @return
     * @throws CAException
     * @see org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
     */
    public Certificate[] listCertificatesWithStatus(String status) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<Certificate> certificateInfoList = certificateDAO.listCertificates(status,
                tenantId);
        return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
    }

    /**
     * Reject CSR without signing
     *
     * @param serial The serial no of the CSR to be rejected
     * @throws CAException
     */
    public void rejectCSR(String serial) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        csrDAO.rejectCSR(serial, tenantId);
    }

    /**
     * Get the CSR specified by the given serial no
     *
     * @param serial The serial no of the CSR
     * @return
     * @throws CAException
     */
    public CSR getCsr(String serial) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return csrDAO.getCSR(serial, tenantId);
    }

    /**
     * Update the key that is used for CA operations such as signing certificates,
     * CRLs. <br/>
     * <b>Note:</b> Changing the key will revoke all the certificates issued using the previous key.
     *
     * @param keyStore
     * @param alias
     * @throws CAException
     */
    public void updateSigningKey(String keyStore, String alias) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CAConfiguration.getInstance().updateKey(tenantId, keyStore, alias);
    }

    /**
     * Gets the revoke reason of the certificate given by the serial no
     *
     * @param serial The serial no of the certificate
     * @return The reason code for the revocation
     * @throws CAException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public int getRevokedReason(String serial) throws CAException {
        return revokeDAO.getRevokedCertificate(serial).getReason();
    }

    /**
     * Gets the CSRs for the tenant CA having the given status
     *
     * @param status The status filter
     * @return
     * @throws CAException
     */
    public CSR[] getCsrListWithStatus(String status) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CSR> csrList = csrDAO.listCsrsByStatus(tenantId, status);
        return csrList.toArray(new CSR[csrList.size()]);
    }

    /**
     * Generate and store a token for a SCEP enrollment. This token will be used to authorize the
     * scep enrollment requests that comes to the non-protected scep endpoint
     *
     * @return The generated scep token
     * @throws CAException
     */
    public String generateScepToken() throws CAException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return SCEPManager.getInstance().generateScepToken(username, tenantId, userStoreDomain);
    }
}
