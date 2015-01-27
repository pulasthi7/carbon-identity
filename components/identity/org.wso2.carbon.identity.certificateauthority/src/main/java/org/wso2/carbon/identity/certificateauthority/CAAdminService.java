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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.certificateauthority.bean.CSR;
import org.wso2.carbon.identity.certificateauthority.bean.Certificate;
import org.wso2.carbon.identity.certificateauthority.bean.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.services.CAConfigurationService;
import org.wso2.carbon.identity.certificateauthority.services.CRLService;
import org.wso2.carbon.identity.certificateauthority.services.CSRService;
import org.wso2.carbon.identity.certificateauthority.services.CertificateService;
import org.wso2.carbon.identity.certificateauthority.services.SCEPService;
import org.wso2.carbon.user.core.util.UserCoreUtil;

import java.util.List;

/**
 * The Service class for the administrative operations of CA.
 */
@SuppressWarnings("UnusedDeclaration")
public class CAAdminService extends AbstractAdmin {
    private static final Log log = LogFactory.getLog(CAAdminService.class);

    /**
     * DAO for CSR related operations.
     */
    private CSRService csrService = CAServiceComponent.getCsrService();
    private CertificateService certificateService = CAServiceComponent.getCertificateService();
    private SCEPService scepService = CAServiceComponent.getScepService();
    private CRLService crlService = CAServiceComponent.getCrlService();
    private CAConfigurationService configurationService = CAServiceComponent.getCaConfigurationService();

    /**
     * Get the list of CSR assigned to the current tenant.
     *
     * @return list of CSR assigned to the current tenant
     */
    public CSR[] listCSRs() throws CAException {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            List<CSR> csrList = csrService.listCSRs(tenantDomain);
            return csrList.toArray(new CSR[csrList.size()]);
        } catch (CAException e) {
            log.error("Error listing the CSRs", e);
            throw new CAException("Error listing the CSRs");
        }
    }

    /**
     * Gets the CSRs for the tenant CA having the given status.
     *
     * @param status The status filter
     * @return CSRs of the tenant CA which has the given status
     * @throws CAException
     */
    public CSR[] listCSRsByStatus(String status) throws CAException {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            List<CSR> csrList = csrService.listCSRsByStatus(tenantDomain, status);
            return csrList.toArray(new CSR[csrList.size()]);
        } catch (CAException e) {
            log.error("Error when listing CSRs with status " + status, e);
            throw new CAException("Error when listing CSRs");
        }
    }

    /**
     * Get the CSR specified by the given serial number.
     *
     * @param serialNo The serial number of the CSR
     * @return CSR with the given serial number
     * @throws CAException
     */
    public CSR getCSR(String serialNo) throws CAException {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            return csrService.getCSR(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error retrieving the CSR with serial no:" + serialNo, e);
            throw new CAException("Error when retrieving the CSR");
        }
    }

    /**
     * Reject CSR without signing.
     *
     * @param serialNo The serial number of the CSR to be rejected
     * @throws CAException
     */
    public void rejectCSR(String serialNo) throws CAException {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            csrService.rejectCSR(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error when rejecting the CSR with serial no:" + serialNo, e);
            throw new CAException("Error when rejecting the CSR");
        }
    }

    /**
     * Signs the CSR and stores the resulting certificate.
     *
     * @param serialNo The serial number of the CSR to be signed
     * @param validity The number of days that the resulting certificate should be valid before expiration
     * @throws CAException
     */
    public void signCSR(String serialNo, int validity) throws CAException {
        try {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            certificateService.signCSR(tenantDomain, serialNo, validity);
        } catch (CAException e) {
            log.error("Error signing the CSR with serial no:" + serialNo + " , for " + validity + " days", e);
            throw new CAException("Certificate could not be signed");
        }
    }

    /**
     * Lists all the certificate issued by the tenant CA.
     *
     * @return List of all tenant CA issued certificates
     * @throws CAException
     */
    public Certificate[] listCertificates() throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            List<Certificate> certificateInfoList = certificateService.listCertificates(tenantDomain);
            return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
        } catch (CAException e) {
            log.error("Error listing certificates for tenant:" + tenantDomain, e);
            throw new CAException("Error listing the certificates");
        }
    }

    /**
     * Lists all the certificates issued by the tenant CA filtered by the given status.
     *
     * @param status The status filter
     * @return List of certificates with given status issued by tenant CA
     * @throws CAException
     * @see org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
     */
    public Certificate[] listCertificatesWithStatus(String status) throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            List<Certificate> certificateInfoList = certificateService.listCertificates(status, tenantDomain);
            return certificateInfoList.toArray(new Certificate[certificateInfoList.size()]);
        } catch (CAException e) {
            log.error("Error listing certificates with status " + status + " for tenant:" + tenantDomain, e);
            throw new CAException("Error listing \"" + status + "\" certificates");
        }
    }

    /**
     * Get the details of the certificate identified by the given serial number.
     *
     * @param serialNo The serial number of the certificate
     * @return The certificate
     * @throws CAException
     */
    public Certificate getCertificate(String serialNo) throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            return certificateService.getCertificate(serialNo, tenantDomain);
        } catch (CAException e) {
            log.error("Error retrieving the certificate with serial no:" + serialNo + " from tenant:" + tenantDomain,
                    e);
            throw new CAException("Error when retrieving the certificate");
        }
    }

    /**
     * Revokes certificate with given serial number, specifying the given revoke reason.
     *
     * @param serialNo The serial number of the certificate to be revoked
     * @param reason   The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public void revokeCertificate(String serialNo, int reason) throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            certificateService.revokeCert(tenantDomain, serialNo, reason);
            crlService.createAndStoreDeltaCrl(tenantDomain);
        } catch (CAException e) {
            log.error("Error revoking the certificate, serial no:" + serialNo + ", revoke reason code" + reason, e);
            throw new CAException("Certificate could not be revoked");
        }

    }

    /**
     * Gets the revoke reason of the certificate given by the serial number.
     *
     * @param serialNo The serial number of the certificate
     * @return The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public int getRevokedReason(String serialNo) throws CAException {
        try {
            RevokedCertificate revokedCertificate = certificateService.getRevokedCertificate(serialNo);
            if (revokedCertificate != null) {
                return revokedCertificate.getReason();
            } else {
                log.error("No revoked certificate with serial number: " + serialNo);
                throw new CAException("No revoked certificate with given serial number");
            }
        } catch (CAException e) {
            log.error("Error when retrieving the revoke reason. Certificate serial no:" + serialNo, e);
            throw new CAException("Error when retrieving revoke reason for the certificate");
        }
    }

    /**
     * Lists keys available for the tenant admin. The current configured key is the first of the list.
     *
     * @return A list of keys available for tenant admin
     * @throws CAException
     */
    public String[] listKeyAliases() throws CAException {
        try {
            List<String> keyList = configurationService.listAllKeys(getGovernanceSystemRegistry());
            return keyList.toArray(new String[keyList.size()]);
        } catch (CAException e) {
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            log.error("Error when listing the keys for tenant:" + tenantDomain, e);
            throw new CAException("Could not list the keys");
        }
    }

    /**
     * Update the key that is used for CA operations such as signing certificates,
     * CRLs. <br/>
     * <b>Note:</b> Changing the key will revoke all the certificates issued using the previous key.
     *
     * @param keyStore The key steore containing the new key
     * @param alias    The alias of the new key
     * @throws CAException
     */
    public void updateSigningKey(String keyStore, String alias) throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            configurationService.updateKey(tenantDomain, keyStore, alias);
        } catch (CAException e) {
            log.error("Error when updating the key of tenant:" + tenantDomain + " to " + keyStore + "/" + alias, e);
            throw new CAException("Error when updating the key");
        }
    }

    /**
     * Generate and store a token for a SCEP enrollment. This token will be used to authorize the
     * SCEP enrollment requests that comes to the non-protected scep endpoint.
     *
     * @return The generated SCEP token
     * @throws CAException
     */
    public String generateSCEPToken() throws CAException {
        String username = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        try {
            return scepService.generateScepToken(username, tenantDomain, userStoreDomain);
        } catch (CAException e) {
            log.error("Error when generating SCEP token for " + userStoreDomain + "\\" + username + "@" +
                    tenantDomain, e);
            throw new CAException("Could not generate a new token");
        }
    }
}
