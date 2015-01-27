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

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CAUserService;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.SCEPDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class SCEPServiceImpl implements SCEPService {

    private static final Log log = LogFactory.getLog(CAUserService.class);
    private static SCEPService instance = new SCEPServiceImpl();
    private SCEPDAO scepDAO = new SCEPDAO();

    private SCEPServiceImpl() {
    }

    public static SCEPService getInstance() {
        return instance;
    }

    @Override
    public X509Certificate enroll(PKCS10CertificationRequest certReq, String transactionId, String tenantDomain)
            throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(transactionId)) {
            throw new IllegalArgumentException("Transaction ID cannot be empty");
        }
        if (certReq == null) {
            throw new IllegalArgumentException("Certificate request cannot be null");
        }
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            String token = "";
            Attribute[] attributes = certReq.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_challengePassword);
            if (attributes != null && attributes.length > 0) {
                ASN1Set attributeValues = attributes[0].getAttrValues();
                if (attributeValues.size() > 0) {
                    token = attributeValues.getObjectAt(0).toString();
                }
            }
            CAConfigurationService configurationService = CAConfigurationServiceImpl.getInstance();
            String serialNo = scepDAO.addScepCsr(certReq, transactionId, token, tenantDomain,
                    configurationService.getTokenValidity());
            //To sign the certificate as admin, start a tenant flow (This is executed from an
            // unauthenticated endpoint, so need to set the tenant info before proceed to signing
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
            PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
            CertificateService certificateService = CertificateServiceImpl.getInstance();
            certificateService.signCSR(tenantDomain, serialNo, CAConfiguration.getInstance()
                    .getScepIssuedCertificateValidity());
            return certificateService.getX509Certificate(serialNo);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    @Override
    public X509Certificate getCertificate(String tenantDomain, String transactionId) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(transactionId)) {
            throw new IllegalArgumentException("Transaction ID cannot be empty");
        }
        return scepDAO.getCertificate(transactionId, tenantDomain);
    }

    @Override
    public X509Certificate getCaCert(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        return CAConfigurationServiceImpl.getInstance().getConfiguredCACert(tenantDomain);
    }

    @Override
    public PrivateKey getCaKey(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        return CAConfigurationServiceImpl.getInstance().getConfiguredPrivateKey(tenantDomain);
    }

    @Override
    public String generateScepToken(String userName, String tenantDomain, String userStoreDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("User name cannot be empty");
        }
        if (StringUtils.isEmpty(userStoreDomain)) {
            throw new IllegalArgumentException("User store domain cannot be empty");
        }
        CAConfigurationService configurationService = CAConfigurationServiceImpl.getInstance();
        int tokenLength = configurationService.getTokenLength();
        String token = "";
        boolean added = false;
        int retries = 0;
        //If the generated token exists in the db (used/available/expired) try with another
        while (!added) {
            token = RandomStringUtils.randomAlphanumeric(tokenLength);
            added = scepDAO.addSCEPToken(token, userName, userStoreDomain, tenantDomain);
            retries++;
            if (retries >= CAConstants.MAX_SCEP_TOKEN_RETRIES) {
                throw new CAException("Token creation failed, All tried keys exists in db. Try updating token length.");
            }
        }
        return token;
    }
}
