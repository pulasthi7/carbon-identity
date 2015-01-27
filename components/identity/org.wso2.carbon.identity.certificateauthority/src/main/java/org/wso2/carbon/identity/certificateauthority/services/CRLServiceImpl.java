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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.bean.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.dao.CRLDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.scheduledTask.CRLUpdater;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Service implementation for CRLService
 */
public class CRLServiceImpl implements CRLService {

    private static final Log log = LogFactory.getLog(CRLServiceImpl.class);
    private static CRLService instance = new CRLServiceImpl();
    private CRLDAO crlDAO = new CRLDAO();

    private CRLServiceImpl() {
    }

    public static CRLService getInstance() {
        return instance;
    }

    @Override
    public void addCRL() throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        createAndStoreCrl(tenantDomain);
    }

    @Override
    public void addDeltaCrl() throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        createAndStoreDeltaCrl(tenantDomain);
    }

    @Override
    public byte[] getLatestCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        try {
            return crlDAO.getLatestCRL(tenantDomain, false).getBase64Crl().getBytes(
                    CAConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported encoding used", e);
        }
    }

    @Override
    public byte[] getLatestDeltaCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        try {
            return crlDAO.getLatestCRL(tenantDomain, true).getBase64Crl()
                    .getBytes(CAConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported encoding used", e);
        }
    }

    @Override
    public void updateCrl() throws CAException {
        CRLUpdater updater = new CRLUpdater();
        updater.buildFullCrl();
    }

    @Override
    public X509CRL getLatestX509Crl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        try {
            return CAObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantDomain, false).getBase64Crl());
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported CRL encoding used", e);
        } catch (CertificateException e) {
            throw new CAException("Error with keystore factory", e);
        } catch (CRLException e) {
            throw new CAException("Error when generating the CRL", e);
        }
    }

    /**
     * Creates X509 CRL.
     *
     * @param caCertificate       The CA Certificate
     * @param caPrivateKey        The CA private key
     * @param revokedCertificates List of revoked certificates
     * @param crlNumber           Unique number of the crl
     * @param baseCrlNumber       Base CRL number
     * @param isDeltaCrl          Whether the crl is a delta crl or a full CRL
     * @return The X509 CRL
     * @throws CAException
     */
    private X509CRL createCRL(X509Certificate caCertificate, PrivateKey caPrivateKey,
                              List<RevokedCertificate> revokedCertificates, int crlNumber, int baseCrlNumber,
                              boolean isDeltaCrl) throws CAException {
        try {
            Date now = new Date();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder(caCertificate)
                    .getSubject(), now);
            long crlUpdateTimeMillis = CAConstants.CRL_UPDATE_INTERVAL * 1000;
            crlBuilder.setNextUpdate(new Date(now.getTime() + crlUpdateTimeMillis));
            ContentSigner signer = new JcaContentSignerBuilder(CAConstants.SHA1_WITH_RSA).setProvider(CAConstants
                    .BC_PROVIDER).build(caPrivateKey);
            for (RevokedCertificate revokedCertificate : revokedCertificates) {
                BigInteger serialNo = new BigInteger(revokedCertificate.getSerialNo());
                crlBuilder.addCRLEntry(serialNo, revokedCertificate.getRevokedDate(), revokedCertificate.getReason());
            }
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(X509Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(caCertificate));
            crlBuilder.addExtension(X509Extension.cRLNumber, false, new CRLNumber(BigInteger.valueOf(crlNumber)));
            if (isDeltaCrl) {
                crlBuilder.addExtension(X509Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.valueOf
                        (baseCrlNumber)));
            }
            return new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        } catch (CertificateEncodingException e) {
            throw new CAException("Error when creating CRL. Error in certificate encoding.", e);
        } catch (OperatorCreationException e) {
            throw new CAException("Error with security provider when creating CRL.", e);
        } catch (CertIOException e) {
            throw new CAException("Error adding extensions to CRL.", e);
        } catch (NoSuchAlgorithmException e) {
            throw new CAException("Error with signature algorithm when creating CRL", e);
        } catch (CRLException e) {
            throw new CAException("Error when creating CRL.", e);
        }
    }

    @Override
    public X509CRL createFullCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        RevocationDAO revocationDAO = new RevocationDAO();
        CRLDAO crlDAO = new CRLDAO();
        List<RevokedCertificate> revokedCertificates = revocationDAO.listRevokedCertificates(tenantDomain);
        CAConfigurationService configurationService = CAServiceComponent.getCaConfigurationService();
        PrivateKey caKey = configurationService.getConfiguredPrivateKey();
        X509Certificate caCert = configurationService.getConfiguredCACert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + CAConstants
                .CRL_NUMBER_INCREMENT;
        return createCRL(caCert, caKey, revokedCertificates, nextCrlNumber, CAConstants.CRL_INDICATOR, false);

    }

    @Override
    public X509CRL createDeltaCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        RevocationDAO revocationDAO = new RevocationDAO();
        X509CRL latestCrl;
        try {
            latestCrl = CAObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantDomain, false).getBase64Crl());
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported CRL encoding used", e);
        } catch (CertificateException e) {
            throw new CAException("Error with keystore factory", e);
        } catch (CRLException e) {
            throw new CAException("Error when generating the CRL", e);
        }
        List<RevokedCertificate> revokedCertificates = revocationDAO.getRevokedCertificatesAfter(tenantDomain,
                latestCrl.getThisUpdate());
        CAConfigurationService configurationService = CAServiceComponent.getCaConfigurationService();
        PrivateKey privateKey = configurationService.getConfiguredPrivateKey();
        X509Certificate caCert = configurationService.getConfiguredCACert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + CAConstants
                .CRL_NUMBER_INCREMENT;
        return createCRL(caCert, privateKey, revokedCertificates, nextCrlNumber, fullCrlNumber, false);
    }

    @Override
    public void createAndStoreCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        X509CRL crl = createFullCrl(tenantDomain);
        RevocationDAO revocationDAO = new RevocationDAO();
        revocationDAO.removeReactivatedCertificates();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber;
        if (fullCrlNumber > deltaCrlNumber) {
            nextCrlNumber = fullCrlNumber + CAConstants.CRL_NUMBER_INCREMENT;
        } else {
            nextCrlNumber = deltaCrlNumber + CAConstants.CRL_NUMBER_INCREMENT;
        }
        crlDAO.addCRL(crl, tenantDomain, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber,
                CAConstants.CRL_INDICATOR);

    }

    @Override
    public void createAndStoreDeltaCrl(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        X509CRL crl = createDeltaCrl(tenantDomain);
        if (crl != null) {
            CRLDAO crlDAO = new CRLDAO();
            int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantDomain, false);
            int deltaCRLNumber = crlDAO.getHighestCrlNumber(tenantDomain, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1
            // (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber;
            if (fullCrlNumber > deltaCRLNumber) {
                nextCrlNumber = fullCrlNumber + CAConstants.CRL_NUMBER_INCREMENT;
            } else {
                nextCrlNumber = deltaCRLNumber + CAConstants.CRL_NUMBER_INCREMENT;
            }
            crlDAO.addCRL(crl, tenantDomain, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber,
                    CAConstants.DELTA_CRL_INDICATOR);
        }
    }
}
