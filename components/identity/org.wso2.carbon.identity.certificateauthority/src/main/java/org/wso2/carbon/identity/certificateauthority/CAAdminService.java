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

/**
 * The Service class for the administrative operations of CA
 */
@SuppressWarnings("UnusedDeclaration")
public class CAAdminService extends AbstractAdmin {
    /**
     * DAO for CSR related operations
     */
    private CSRDAO csrDAO;
    /**
     * DAO for Certificate related operations
     */
    private CertificateDAO certificateDAO;
    /**
     * DAO for revocation related operations
     */
    private RevocationDAO revokeDAO;

    /**
     * The manager class for certificate related operations
     */
    private CertificateManager certificateManager;

    /**
     * The manager class for the SCEP operations
     */
    private SCEPManager scepManager;

    /**
     * The manager class for the CRL operations
     */
    private CRLManager crlManager;

    /**
     * Initialize the Service class
     */
    public CAAdminService() {
        csrDAO = new CSRDAO();
        certificateDAO = new CertificateDAO();
        revokeDAO = new RevocationDAO();
        certificateManager = new CertificateManager();
        crlManager = new CRLManager();
    }

    /**
     * Get the list of CSR assigned to the current tenant
     *
     * @return list of CSR assigned to the current tenant
     */
    public CSR[] listCSRs() throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CSR> csrList = csrDAO.listCsrs(tenantId);
        return csrList.toArray(new CSR[csrList.size()]);
    }

    /**
     * Gets the CSRs for the tenant CA having the given status
     *
     * @param status The status filter
     * @return CSRs of the tenant CA which has the given status
     * @throws CAException
     */
    public CSR[] listCSRsByStatus(String status) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<CSR> csrList = csrDAO.listCsrsByStatus(tenantId, status);
        return csrList.toArray(new CSR[csrList.size()]);
    }

    /**
     * Get the CSR specified by the given serial number
     *
     * @param serialNo The serial number of the CSR
     * @return CSR with the given serial number
     * @throws CAException
     */
    public CSR getCSR(String serialNo) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return csrDAO.getCSR(serialNo, tenantId);
    }

    /**
     * Reject CSR without signing
     *
     * @param serialNo The serial number of the CSR to be rejected
     * @throws CAException
     */
    public void rejectCSR(String serialNo) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        csrDAO.rejectCSR(serialNo, tenantId);
    }

    /**
     * Signs the CSR and stores the resulting certificate
     *
     * @param serialNo The serial number of the CSR to be signed
     * @param validity The number of days that the resulting certificate should be valid before expiration
     * @throws CAException
     */
    public void signCSR(String serialNo, int validity) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        certificateManager.signCSR(tenantId, serialNo, validity);
    }

    /**
     * Lists all the certificate issued by the tenant CA
     *
     * @return List of all tenant CA issued certificates
     * @throws CAException
     */
    public Certificate[] listCertificates() throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        List<Certificate> certificateInfoList = certificateDAO.listCertificates(tenantId);
        return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
    }

    /**
     * Lists all the certificates issued by the tenant CA filtered by the given status
     *
     * @param status The status filter
     * @return List of certificates with given status issued by tenant CA
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
     * Get the details of the certificate identified by the given serial number
     *
     * @param serialNo The serial number of the certificate
     * @return The certificate
     * @throws CAException
     */
    public Certificate getCertificate(String serialNo) throws CAException {
        int tenantID = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        return certificateDAO.getCertificateInfo(serialNo, tenantID);
    }

    /**
     * Revokes certificate with given serial number, specifying the given revoke reason
     *
     * @param serialNo The serial number of the certificate to be revoked
     * @param reason   The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws Exception
     */
    public void revokeCertificate(String serialNo, int reason) throws Exception {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        certificateManager.revokeCert(tenantId, serialNo, reason);
        crlManager.createAndStoreDeltaCrl(tenantId);

    }

    /**
     * Gets the revoke reason of the certificate given by the serial number
     *
     * @param serialNo The serial number of the certificate
     * @return The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public int getRevokedReason(String serialNo) throws CAException {
        return revokeDAO.getRevokedCertificate(serialNo).getReason();
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
     * Update the key that is used for CA operations such as signing certificates,
     * CRLs. <br/>
     * <b>Note:</b> Changing the key will revoke all the certificates issued using the previous key.
     *
     * @param keyStore The key store containing the new key
     * @param alias    The alias of the new key
     * @throws CAException
     */
    public void updateSigningKey(String keyStore, String alias) throws CAException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        CAConfiguration.getInstance().updateKey(tenantId, keyStore, alias);
    }

    /**
     * Generate and store a token for a SCEP enrollment. This token will be used to authorize the
     * SCEP enrollment requests that comes to the non-protected scep endpoint
     *
     * @return The generated SCEP token
     * @throws CAException
     */
    public String generateSCEPToken() throws CAException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        return scepManager.generateScepToken(username, tenantId, userStoreDomain);
    }
}
