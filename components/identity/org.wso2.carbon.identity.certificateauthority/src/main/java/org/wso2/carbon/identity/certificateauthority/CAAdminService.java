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
    private static final Log log = LogFactory.getLog(CAAdminService.class);

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
    public CSR[] listCSRs() throws AxisFault {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            List<CSR> csrList = csrDAO.listCSRs(tenantDomain);
            return csrList.toArray(new CSR[csrList.size()]);
        } catch (CAException e) {
            log.error("Error listing the CSRs", e);
            throw new AxisFault("Error listing the CSRs");
        }
    }

    /**
     * Gets the CSRs for the tenant CA having the given status
     *
     * @param status The status filter
     * @return CSRs of the tenant CA which has the given status
     * @throws AxisFault
     */
    public CSR[] listCSRsByStatus(String status) throws AxisFault {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            List<CSR> csrList = csrDAO.listCSRsByStatus(tenantDomain, status);
            return csrList.toArray(new CSR[csrList.size()]);
        } catch (CAException e) {
            log.error("Error when listing CSRs with status " + status, e);
            throw new AxisFault("Error when listing CSRs");
        }
    }

    /**
     * Get the CSR specified by the given serial number
     *
     * @param serialNo The serial number of the CSR
     * @return CSR with the given serial number
     * @throws AxisFault
     */
    public CSR getCSR(String serialNo) throws AxisFault {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            return csrDAO.getCSR(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error retrieving the CSR with serial no:" + serialNo, e);
            throw new AxisFault("Error when retrieving the CSR");
        }
    }

    /**
     * Reject CSR without signing
     *
     * @param serialNo The serial number of the CSR to be rejected
     * @throws AxisFault
     */
    public void rejectCSR(String serialNo) throws AxisFault {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            csrDAO.rejectCSR(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error when rejecting the CSR with serial no:" + serialNo, e);
            throw new AxisFault("Error when rejecting the CSR");
        }
    }

    /**
     * Signs the CSR and stores the resulting certificate
     *
     * @param serialNo The serial number of the CSR to be signed
     * @param validity The number of days that the resulting certificate should be valid before expiration
     * @throws AxisFault
     */
    public void signCSR(String serialNo, int validity) throws AxisFault {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            certificateManager.signCSR(tenantDomain, serialNo, validity);
        } catch (CAException e) {
            log.error("Error signing the CSR with serial no:" + serialNo + " , for " + validity + " days", e);
            throw new AxisFault("Certificate could not be signed");
        }
    }

    /**
     * Lists all the certificate issued by the tenant CA
     *
     * @return List of all tenant CA issued certificates
     * @throws AxisFault
     */
    public Certificate[] listCertificates() throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            List<Certificate> certificateInfoList = certificateDAO.listCertificates(tenantDomain);
            return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
        } catch (CAException e) {
            log.error("Error listing certificates for tenant:" + tenantDomain, e);
            throw new AxisFault("Error listing the certificates");
        }
    }

    /**
     * Lists all the certificates issued by the tenant CA filtered by the given status
     *
     * @param status The status filter
     * @return List of certificates with given status issued by tenant CA
     * @throws AxisFault
     * @see org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
     */
    public Certificate[] listCertificatesWithStatus(String status) throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            List<Certificate> certificateInfoList = certificateDAO.listCertificates(status, tenantDomain);
            return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
        } catch (CAException e) {
            log.error("Error listing certificates with status " + status + " for tenant:" + tenantDomain, e);
            throw new AxisFault("Error listing \"" + status + "\" certificates");
        }
    }

    /**
     * Get the details of the certificate identified by the given serial number
     *
     * @param serialNo The serial number of the certificate
     * @return The certificate
     * @throws AxisFault
     */
    public Certificate getCertificate(String serialNo) throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            return certificateDAO.getCertificateInfo(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error retrieving the certificate with serial no:" + serialNo + " from tenant:" + tenantDomain,
                    e);
            throw new AxisFault("Error when retrieving the certificate");
        }
    }

    /**
     * Revokes certificate with given serial number, specifying the given revoke reason
     *
     * @param serialNo The serial number of the certificate to be revoked
     * @param reason   The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws AxisFault
     */
    public void revokeCertificate(String serialNo, int reason) throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            certificateManager.revokeCert(tenantDomain, serialNo, reason);
            crlManager.createAndStoreDeltaCrl(tenantDomain);
        } catch (CAException e) {
            log.error("Error revoking the certificate, serial no:" + serialNo + ", revoke reason code" + reason, e);
            throw new AxisFault("Certificate could not be revoked");
        }

    }

    /**
     * Gets the revoke reason of the certificate given by the serial number
     *
     * @param serialNo The serial number of the certificate
     * @return The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws AxisFault
     */
    public int getRevokedReason(String serialNo) throws AxisFault {
        try {
            return revokeDAO.getRevokedCertificate(serialNo).getReason();
        } catch (CAException e) {
            log.error("Error when retrieving the revoke reason. Certificate serial no:" + serialNo, e);
            throw new AxisFault("Error when retrieving revoke reason for the certificate");
        }
    }

    /**
     * Lists keys available for the tenant admin. The current configured key is the first of the
     * list
     *
     * @return A list of keys available for tenant admin
     * @throws AxisFault
     */
    public String[] listKeyAliases() throws AxisFault {
        try {
            List<String> keyList = CAConfiguration.getInstance().listAllKeys(getGovernanceSystemRegistry());
            return keyList.toArray(new String[keyList.size()]);
        } catch (CAException e) {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            log.error("Error when listing the keys for tenant:" + tenantDomain, e);
            throw new AxisFault("Could not list the keys");
        }
    }

    /**
     * Update the key that is used for CA operations such as signing certificates,
     * CRLs. <br/>
     * <b>Note:</b> Changing the key will revoke all the certificates issued using the previous key.
     *
     * @param keyStore The key steore containing the new key
     * @param alias    The alias of the new key
     * @throws AxisFault
     */
    public void updateSigningKey(String keyStore, String alias) throws AxisFault {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            CAConfiguration.getInstance().updateKey(tenantDomain, keyStore, alias);
        } catch (CAException e) {
            log.error("Error when updating the key of tenant:" + tenantDomain + " to " + keyStore + "/" + alias, e);
            throw new AxisFault("Error when updating the key");
        }
    }

    /**
     * Generate and store a token for a SCEP enrollment. This token will be used to authorize the
     * SCEP enrollment requests that comes to the non-protected scep endpoint
     *
     * @return The generated SCEP token
     * @throws AxisFault
     */
    public String generateSCEPToken() throws AxisFault {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        try {
            return scepManager.generateScepToken(username, tenantDomain, userStoreDomain);
        } catch (CAException e) {
            log.error("Error when generating SCEP token for " + userStoreDomain + "\\" + username + "@" +
                    tenantDomain, e);
            throw new AxisFault("Could not generate a new token");
        }
    }
}
