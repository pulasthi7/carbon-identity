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
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CsrDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.data.CsrInfo;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.List;

public class CaAdminService extends AbstractAdmin {

    private static final Log log = LogFactory.getLog(CaAdminService.class);
    private CsrDAO csrDAO;
    private CertificateDAO certificateDAO;
    private RevocationDAO revokeDAO;

    public CaAdminService() {
        csrDAO = new CsrDAO();
        certificateDAO = new CertificateDAO();
        revokeDAO = new RevocationDAO();
    }

    /**
     * Signs the CSR with the given serial no
     * @param serialNo The serial no of the CSR to be signed
     * @param validity The validity period of the certificate in days
     * @throws CaException
     */
    public void signCSR(String serialNo, int validity) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CertificateManager.getInstance().signCSR(tenantId,serialNo,validity);
    }

    /**
     * Get the list of CSR assigned to the current tenant
     *
     * @return list of CSR assigned to the current tenant
     */
    public CsrInfo[] getCsrList() throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CsrInfo> csrList = csrDAO.listCsrs(tenantId);
        return csrList.toArray(new CsrInfo[csrList.size()]);
    }

    /**
     * Revokes certificate with given serial no, specifying the given revoke reason
     * @param serial The serial no of the certificate to be revoked
     * @param reason The reason code for the revocation
     * @throws Exception
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void revokeCert(String serial, int reason) throws Exception {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CertificateManager.getInstance().revokeCert(tenantId,serial, reason);
        CrlManager.getInstance().createAndStoreDeltaCrl(tenantId);

    }

    /**
     * Lists keys available for the tenant admin. The current configured key is the first of the
     * list
     * @return A list of keys available for tenant admin
     * @throws CaException
     */
    public String[] listKeyAliases() throws CaException {
        List<String> keyList = CaConfiguration.getInstance().listAllKeys
                (getGovernanceSystemRegistry());
        return keyList.toArray(new String[keyList.size()]);
    }

    /**
     * Get the certificate attributes for the certificate with given serial number
     * @param serialNo The serial no of the certificate
     * @return
     * @throws CaException
     */
    public CertificateInfo getCertificate(String serialNo) throws CaException {
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return certificateDAO.getCertificateInfo(serialNo, tenantID);
    }

    /**
     * Lists all the certificate issued by the tenant CA
     * @return
     * @throws CaException
     */
    public CertificateInfo[] getTenantIssuedCertificates() throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CertificateInfo> certificateInfoList = certificateDAO.listCertificates(tenantId);
        return certificateInfoList.toArray(new CertificateInfo[certificateInfoList.size()]);
    }

    /**
     * Lists all the certificates issued by the tenant CA filtered by the given status
     * @param status The status filter
     * @return
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
     */
    public CertificateInfo[] listCertificatesWithStatus(String status) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CertificateInfo> certificateInfoList = certificateDAO.listCertificates(status,
                tenantId);
        return certificateInfoList.toArray(new CertificateInfo[certificateInfoList.size()]);
    }

    /**
     * Reject CSR without signing
     * @param serial The serial no of the CSR to be rejected
     * @throws CaException
     */
    public void rejectCSR(String serial) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        csrDAO.rejectCSR(serial,tenantId);
    }

    /**
     * Get the CSR specified by the given serial no
     * @param serial The serial no of the CSR
     * @return
     * @throws CaException
     */
    public CsrInfo getCsr(String serial) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return csrDAO.getCSR(serial, tenantId);
    }

    /**
     * Update the key that is used for CA operations such as signing certificates,
     * CRLs. <br/>
     * <b>Note:</b> Changing the key will revoke all the certificates issued using the previous key.
     * @param keyStore
     * @param alias
     * @throws CaException
     */
    public void updateSigningKey(String keyStore,String alias) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CaConfiguration.getInstance().updateKey(tenantId,keyStore,alias);
    }

    /**
     * Gets the revoke reason of the certificate given by the serial no
     * @param serial The serial no of the certificate
     * @return The reason code for the revocation
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public int getRevokedReason(String serial) throws CaException {
        return revokeDAO.getRevokedCertificate(serial).getReason();
    }

    /**
     * Gets the CSRs for the tenant CA having the given status
     * @param status The status filter
     * @return
     * @throws CaException
     */
    public CsrInfo[] getCsrListWithStatus(String status) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CsrInfo> csrList = csrDAO.listCsrsByStatus(tenantId, status);
        return csrList.toArray(new CsrInfo[csrList.size()]);
    }

    /**
     * Generate and store a token for a SCEP enrollment. This token will be used to authorize the
     * scep enrollment requests that comes to the non-protected scep endpoint
     * @return The generated scep token
     * @throws CaException
     */
    public String generateScepToken() throws CaException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return ScepManager.getInstance().generateScepToken(username,tenantId,userStoreDomain);
    }
}
