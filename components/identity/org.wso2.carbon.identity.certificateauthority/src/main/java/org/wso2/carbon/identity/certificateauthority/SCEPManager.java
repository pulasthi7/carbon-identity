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

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.SCEPDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SCEPManager {

    private static final Log log = LogFactory.getLog(CAUserService.class);
    private SCEPDAO scepDAO = new SCEPDAO();

    /**
     * Enrolls a CSR from SCEP protocol
     *
     * @param certReq       The certificate request
     * @param transactionId The transcation id that is used to identify the SCEP transaction
     * @param tenantDomain  The tenant domain for which the request is made
     * @return The enrolled certificate
     * @throws CAException
     */
    public X509Certificate enroll(PKCS10CertificationRequest certReq, String transactionId,
                                  String tenantDomain)
            throws CAException {
        int tenantId = 0;
        try {
            tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            String token = "";
            Attribute[] attributes =
                    certReq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (attributes != null && attributes.length > 0) {
                ASN1Set attributeValues = attributes[0].getAttrValues();
                if (attributeValues.size() > 0) {
                    token = attributeValues.getObjectAt(0).toString();
                }
            }
            String serialNo = scepDAO.addScepCsr(certReq, transactionId, token, tenantDomain);
            //To sign the certificate as admin, start a tenant flow (This is executed from an
            // unauthenticated endpoint, so need to set the tenant info before proceed to signing
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
            CertificateManager certificateManager = new CertificateManager();
            certificateManager.signCSR(tenantDomain, serialNo, CAConfiguration.getInstance()
                    .getScepIssuedCertificateValidity());
            return certificateManager.getX509Certificate(serialNo);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    /**
     * Gets the certificate that is issued in the transaction identified by transactionId
     *
     * @param tenantDomain  The tenant domain for which the request is made
     * @param transactionId The transcation id that is used to identify the SCEP transaction
     * @return The enrolled certificate for the transaction
     * @throws CAException
     */
    public X509Certificate getCertificate(String tenantDomain, String transactionId)
            throws CAException {
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            return scepDAO.getCertificate(transactionId, tenantDomain);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain);
        }
    }

    /**
     * Gives the CA certificate for the given tenant
     *
     * @param tenantDomain The tenant domain whose CA certificate is required
     * @return The CA certificate for the tenant
     * @throws CAException
     */
    public X509Certificate getCaCert(String tenantDomain) throws CAException {
        return CAConfiguration.getInstance().getConfiguredCACert(tenantDomain);
    }

    /**
     * Gets the CA's private key for the SCEP operations
     *
     * @param tenantDomain The tenant domain whose CA key is required
     * @return The CA's private key
     * @throws CAException
     */
    public PrivateKey getCaKey(String tenantDomain) throws CAException {
        return CAConfiguration.getInstance().getConfiguredPrivateKey(tenantDomain);
    }

    /**
     * Generate a SCEP token to be used for SCEP operations
     *
     * @param username        The user who is generating the token
     * @param tenantDomain        The tenant domain of the user
     * @param userStoreDomain The user store domain of the user
     * @return The generated SCEP token
     * @throws CAException
     */
    public String generateScepToken(String username, String tenantDomain, String userStoreDomain)
            throws CAException {
        CAConfiguration caConfiguration = CAConfiguration.getInstance();
        int tokenLength = caConfiguration.getTokenLength();
        String token = "";
        boolean added = false;
        int retries = 0;
        //If the generated token exists in the db (used/available/expired) try with another
        while (!added) {
            token = RandomStringUtils.randomAlphanumeric(tokenLength);
            added = scepDAO.addSCEPToken(token, username, userStoreDomain, tenantDomain);
            retries++;
            if (retries >= CAConstants.MAX_SCEP_TOKEN_RETRIES) {
                throw new CAException("Token creation failed, All tried keys exists in db. Try updating token length.");
            }
        }
        return token;
    }
}
