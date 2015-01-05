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
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CRLDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.model.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.scheduledTask.CRLUpdater;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Manages the CRL related operations
 */
public class CRLManager {
    private static final Log log = LogFactory.getLog(CRLManager.class);

    private CRLDAO crlDAO = new CRLDAO();

    /**
     * Create and stores a new CRL
     *
     * @throws Exception
     */
    public void addCRL() throws Exception {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        createAndStoreCrl(tenantId);
    }

    /**
     * Create and stores a new delta CRL
     *
     * @throws Exception
     */
    public void addDeltaCrl() throws Exception {
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        createAndStoreDeltaCrl(tenantID);
    }

    /**
     * Gets the latest CRL in binary format
     *
     * @param tenantDomain The tenant domain of the CA
     * @return The CRL in binary format
     * @throws CAException
     */
    public byte[] getLatestCrl(String tenantDomain)
            throws CAException {
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, false).getBase64Crl().getBytes(
                    CAConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain", e);
        }
    }

    /**
     * Gets the latest delta CRL in binary format
     *
     * @param tenantDomain The tenant domain of the CA
     * @return The deltaCRL in binary format
     * @throws CAException
     */
    public byte[] getLatestDeltaCrl(String tenantDomain)
            throws CAException {
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, true).getBase64Crl()
                    .getBytes(CAConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CAException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain", e);
        }
    }

    /**
     * Update the CRL
     *
     * @throws Exception
     */
    public void updateCrl() throws Exception {
        CRLUpdater updater = new CRLUpdater();
        updater.buildFullCrl();
    }

    /**
     * Get the latest CRL for the tenant CA
     *
     * @param tenantId The tenant id of the CA
     * @return CRL of CA in X509 format
     * @throws CAException
     */
    public X509CRL getLatestX509Crl(int tenantId) throws CAException {
        return CAObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantId, false).getBase64Crl());
    }

    /**
     * Same as {@link #getLatestX509Crl(int)} Takes the tenant domain as parameter
     *
     * @param tenantDomain The tenant domain of the CA
     * @return CRL of CA in X509 format
     * @throws CAException
     */
    public X509CRL getLatestX509Crl(String tenantDomain) throws CAException {
        int tenantId;
        try {
            tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return getLatestX509Crl(tenantId);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain", e);
        }
    }

    /**
     * Creates X509 CRL
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
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder
                    (caCertificate).getSubject(), now);
            long crlUpdateTimeMillis = CAConstants.CRL_UPDATE_INTERVAL * 1000;
            crlBuilder.setNextUpdate(new Date(now.getTime() + crlUpdateTimeMillis));
            ContentSigner signer =
                    new JcaContentSignerBuilder(CAConstants.SHA1_WITH_RSA).setProvider
                            (CAConstants.BC_PROVIDER).build(caPrivateKey);
            for (RevokedCertificate revokedCertificate : revokedCertificates) {
                BigInteger serialNo = new BigInteger(revokedCertificate.getSerialNo());
                crlBuilder.addCRLEntry(serialNo, revokedCertificate.getRevokedDate(),
                        revokedCertificate.getReason());
            }
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(X509Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(caCertificate));
            crlBuilder.addExtension(X509Extension.cRLNumber, false,
                    new CRLNumber(BigInteger.valueOf(crlNumber)));
            if (isDeltaCrl) {
                crlBuilder.addExtension(X509Extension.deltaCRLIndicator, true,
                        new CRLNumber(BigInteger.valueOf(baseCrlNumber)));
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

    /**
     * Create full CRL for the given tenant
     *
     * @param tenantId The tenant Id
     * @return Full CRL of the tenant
     * @throws CAException
     */

    public X509CRL createFullCrl(int tenantId) throws CAException {
        RevocationDAO revocationDAO = new RevocationDAO();
        CRLDAO crlDAO = new CRLDAO();
        List<RevokedCertificate> revokedCertificates = revocationDAO.listRevokedCertificates
                (tenantId);
        PrivateKey caKey = CAConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate caCert = CAConfiguration.getInstance().getConfiguredCACert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + 1;
        return createCRL(caCert, caKey, revokedCertificates, nextCrlNumber, -1, false);

    }

    /**
     * Create delta CRL for the given tenant
     *
     * @param tenantId The tenant id of the CA
     * @return The delta CRL of the tenant CA
     * @throws CAException
     */
    public X509CRL createDeltaCrl(int tenantId) throws CAException {
        RevocationDAO revocationDAO = new RevocationDAO();
        X509CRL latestCrl;
        latestCrl = CAObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantId,
                false).getBase64Crl());
        List<RevokedCertificate> revokedCertificates = revocationDAO.getRevokedCertificatesAfter
                (tenantId, latestCrl.getThisUpdate());
        PrivateKey privateKey = CAConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate caCert = CAConfiguration.getInstance().getConfiguredCACert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + 1;
        return createCRL(caCert, privateKey, revokedCertificates, nextCrlNumber, fullCrlNumber,
                false);
    }

    /**
     * Creates and store a CRL in db for the given tenant
     *
     * @param tenantId The tenant id of the CA
     * @throws CAException
     */
    public void createAndStoreCrl(int tenantId) throws CAException {
        X509CRL crl = createFullCrl(tenantId);
        RevocationDAO revocationDAO = new RevocationDAO();
        revocationDAO.removeReactivatedCertificates();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + 1;

        crlDAO.addCRL(crl, tenantId, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber, -1);

    }

    /**
     * Create and store a delta CRL in database
     *
     * @param tenantId The tenant id of the CA
     * @throws CAException
     */
    public void createAndStoreDeltaCrl(int tenantId) throws CAException {
        X509CRL crl = createDeltaCrl(tenantId);
        if (crl != null) {
            CRLDAO crlDAO = new CRLDAO();
            int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
            int deltaNumber = crlDAO.getHighestCrlNumber(tenantId, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1
            // (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ((fullCrlNumber > deltaNumber) ? fullCrlNumber : deltaNumber) + 1;
            crlDAO.addCRL(crl, tenantId, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber,
                    1);
        }
    }
}
