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
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CrlDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.identity.certificateauthority.scheduledTask.CrlUpdater;
import org.wso2.carbon.identity.certificateauthority.utils.CaObjectUtils;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.List;

/**
 * Manages the CRL related operations
 */
public class CrlManager {
    private static final Log log = LogFactory.getLog(CrlManager.class);
    private static CrlManager instance = new CrlManager();

    private CrlDAO crlDAO = new CrlDAO();

    public static CrlManager getInstance() {
        return instance;
    }

    private CrlManager(){
    }

    /**
     * Create and stores a new CRL
     * @throws Exception
     */
    public void addCRL() throws Exception {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        createAndStoreCrl(tenantId);
    }

    /**
     * Create and stores a new delta CRL
     * @throws Exception
     */
    public void addDeltaCrl() throws Exception {
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        createAndStoreDeltaCrl(tenantID);
    }

    /**
     * Gets the latest CRL in binary format
     * @param tenantDomain
     * @return
     * @throws CaException
     */
    public byte[] getLatestCrl(String tenantDomain)
            throws CaException {
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, false).getBase64Crl().getBytes(
                    CaConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CaException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }

    /**
     * Gets the latest delta CRL in binary format
     * @param tenantDomain
     * @return
     * @throws CaException
     */
    public byte[] getLatestDeltaCrl(String tenantDomain)
            throws CaException {
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, true).getBase64Crl()
                    .getBytes(CaConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CaException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }

    /**
     * Update the CRL
     * @throws Exception
     */
    public void updateCrl() throws Exception {
        CrlUpdater updater = new CrlUpdater();
        updater.buildFullCrl();
    }

    /**
     * Get the latest CRL for the tenant CA
     * @param tenantId The tenant id of the CA
     * @return CRL of CA in X509 format
     * @throws CaException
     */
    public X509CRL getLatestX509Crl(int tenantId) throws CaException {
        return CaObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantId, false).getBase64Crl());
    }

    /**
     * Same as {@link #getLatestX509Crl(int)} Takes the tenant domain as parameter
     * @param tenantDomain The tenant domain of the CA
     * @return CRL of CA in X509 format
     * @throws CaException
     */
    public X509CRL getLatestX509Crl(String tenantDomain) throws CaException {
        int tenantId = 0;
        try {
            tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return getLatestX509Crl(tenantId);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }

    /**
     * Create CRL
     * @param caCertificate       The CA Certificate
     * @param caPrivateKey        The CA private key
     * @param revokedCertificates List of revoked certificates
     * @param crlNumber           Unique number of the crl
     * @param baseCrlNumber       Base CRL number
     * @param isDeltaCrl          Whether the crl is a delta crl or a full CRL
     * @return The X509 CRL
     * @throws Exception
     */
    private X509CRL createCRL(X509Certificate caCertificate, PrivateKey caPrivateKey,
                              List<RevokedCertificate> revokedCertificates, int crlNumber,
                              int baseCrlNumber, boolean isDeltaCrl) throws CaException {

        try {
            Date now = new Date();
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(new JcaX509CertificateHolder
                    (caCertificate).getSubject(),now);
            long crlUpdateTimeMillis = CaConstants.CRL_UPDATE_INTERVAL * 1000;
            crlBuilder.setNextUpdate(new Date(now.getTime()+crlUpdateTimeMillis));
            ContentSigner signer =
                    new JcaContentSignerBuilder(CaConstants.SHA1_WITH_RSA).setProvider
                            (CaConstants.BC_PROVIDER).build(caPrivateKey);
            for (RevokedCertificate revokedCertificate : revokedCertificates) {
                BigInteger serialNo = new BigInteger(revokedCertificate.getSerialNo());
                crlBuilder.addCRLEntry(serialNo, revokedCertificate.getRevokedDate(),
                        revokedCertificate.getReason());
            }
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(X509Extension.authorityKeyIdentifier,false,
                    extUtils.createAuthorityKeyIdentifier(caCertificate));
            crlBuilder.addExtension(X509Extension.cRLNumber,false,
                    new CRLNumber(BigInteger.valueOf(baseCrlNumber)));
            if (isDeltaCrl) {
                crlBuilder.addExtension(X509Extension.deltaCRLIndicator,true,
                        new CRLNumber(BigInteger.valueOf(baseCrlNumber)));
            }
            return new JcaX509CRLConverter().getCRL(crlBuilder.build(signer));
        } catch (CertificateEncodingException e) {
            log.error("Error when creating CRL. Error in certificate encoding.",e);
            throw new CaException("Error when creating CRL",e);
        } catch (OperatorCreationException e) {
            log.error("Error with security provider when creating CRL.",e);
            throw new CaException("Error when creating CRL",e);
        } catch (CertIOException e) {
            log.error("Error adding extensions to CRL.",e);
            throw new CaException("Error when creating CRL",e);
        } catch (NoSuchAlgorithmException e) {
            log.error("Error with signature algorithm when creating CRL",e);
            throw new CaException("Error when creating CRL",e);
        } catch (CRLException e) {
            log.error("Error when creating CRL.",e);
            throw new CaException("Error when creating CRL",e);
        }
    }

    /**
     * Create full CRL for the given tenant
     * @param tenantId The tenant Id
     * @return Full CRL of the tenant
     * @throws Exception
     */

    public X509CRL createFullCrl(int tenantId) throws CaException {
        RevocationDAO revocationDAO = new RevocationDAO();
        CrlDAO crlDAO = new CrlDAO();
        List<RevokedCertificate> revokedCertificates = revocationDAO.listRevokedCertificates
                (tenantId);
        PrivateKey caKey = CaConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate caCert = CaConfiguration.getInstance().getConfiguredCaCert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + 1;
        return createCRL(caCert, caKey, revokedCertificates, nextCrlNumber, -1, false);

    }

    /**
     * Create delta CRL for the given tenant
     * @param tenantId The tenant id of the CA
     * @return The delta CRL of the tenant CA
     * @throws Exception
     */
    public X509CRL createDeltaCrl(int tenantId) throws CaException {
        RevocationDAO revocationDAO = new RevocationDAO();
        CrlDAO crlDAO = new CrlDAO();
        X509CRL latestCrl;
        latestCrl = CaObjectUtils.toX509Crl(crlDAO.getLatestCRL(tenantId,
                false).getBase64Crl());
        List<RevokedCertificate> revokedCertificates = revocationDAO.getRevokedCertificatesAfter
                (tenantId, latestCrl.getThisUpdate());
        PrivateKey privateKey = CaConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate certb = CaConfiguration.getInstance().getConfiguredCaCert();
        int fullCrlNumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltaCrlNumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both
        // full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullCrlNumber > deltaCrlNumber) ? fullCrlNumber : deltaCrlNumber) + 1;
        return createCRL(certb, privateKey, revokedCertificates, nextCrlNumber, fullCrlNumber,
                false);
    }

    /**
     * Creates and store a CRL in db for the given tenant
     *
     * @param tenantId tenant id
     * @throws Exception
     */
    public void createAndStoreCrl(int tenantId) throws CaException {
        X509CRL crl = createFullCrl(tenantId);
        CrlDAO crlDAO = new CrlDAO();
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
     * Create and store a delta crl in database
     *
     * @param tenantId id of the tenant
     * @throws CaException
     */
    public void createAndStoreDeltaCrl(int tenantId) throws CaException {
        X509CRL crl = createDeltaCrl(tenantId);
        if (crl != null) {
            CrlDAO crlDAO = new CrlDAO();
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
