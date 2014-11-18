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
import org.wso2.carbon.identity.certificateauthority.common.CsrStatus;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.ConfigurationDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CsrDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.CaConfig;
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

    public void signCSR(String serialNo, int validity) throws CaException {
        CertificateManager.getInstance().signCSR(serialNo,validity);
    }

    /**
     * to get a list of CS request assigned to a tenant
     *
     * @return list of CSR files assigned to a tenant
     */
    public CsrInfo[] getCsrList() throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CsrInfo> csrList = csrDAO.listCsrs(tenantId);
        return csrList.toArray(new CsrInfo[csrList.size()]);
    }

    public void revokeCert(String serial, int reason) throws Exception {
        CertificateManager.getInstance().revokeCert(serial, reason);

    }

    public String[] listKeyAliases() throws CaException {
        List<String> keyList = CaConfiguration.getInstance().listAllKeys
                (getGovernanceSystemRegistry());
        return keyList.toArray(new String[keyList.size()]);    }

    /**
     * delete csr
     *
     * @param serial serial number of the csr
     * @return 1 if the deletion is successful,0 else
     */

    public void deleteCsr(String serial) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        csrDAO.deleteCSR(serial, tenantId);
    }

    public CertificateInfo getCertificate(String serialNo) throws CaException {
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return certificateDAO.getCertificateInfo(serialNo, tenantID);
    }

    public CertificateInfo[] getTenantIssuedCertificates() throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CertificateInfo> certificateInfoList = certificateDAO.listCertificates(tenantId);
        return certificateInfoList.toArray(new CertificateInfo[certificateInfoList.size()]);
    }

    public CertificateInfo[] listCertificatesWithStatus(String status) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CertificateInfo> certificateInfoList = certificateDAO.listCertificates(status,
                tenantId);
        return certificateInfoList.toArray(new CertificateInfo[certificateInfoList.size()]);
    }

    public void rejectCSR(String serial) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        csrDAO.updateStatus(serial, CsrStatus.REJECTED, tenantId);
    }

    public CsrInfo getCsr(String serial) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return csrDAO.getCSR(serial, tenantId);
    }

    public void updateSigningKey(String keyStore,String alias) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CaConfiguration.getInstance().updateKey(tenantId,keyStore,alias);
    }

    public int getRevokedReason(String serial) throws CaException {
        return revokeDAO.getRevokedCertificate(serial).getReason();
    }

    public CsrInfo[] getCsrListWithStatus(String status) throws CaException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CsrInfo> csrList = csrDAO.listCsrsByStatus(tenantId, status);
        return csrList.toArray(new CsrInfo[csrList.size()]);
    }

    public String generateScepToken() throws CaException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return ScepManager.getInstance().generateScepToken(username,tenantId,userStoreDomain);
    }
}
