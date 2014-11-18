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

package org.wso2.carbon.identity.certificateauthority.crl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CrlDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.utils.ConversionUtils;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class CrlFactory {
    private static final Log log = LogFactory.getLog(CrlFactory.class);

    /**
     * @param caCertificate       Certoficate authority's certificate
     * @param caPrivateKey        CA private key
     * @param revokedCertificates list of revoked certificates
     * @param crlNumber           unique number of the crl
     * @param baseCrlNumber       base crl number
     * @param isDeltaCrl          whether the crl is a delta crl or a full crl
     * @return returns the X509 Crl
     * @throws Exception
     */
    private X509CRL createCRL(X509Certificate caCertificate, PrivateKey caPrivateKey,
                              List<RevokedCertificate> revokedCertificates, int crlNumber,
                              int baseCrlNumber, boolean isDeltaCrl) throws CaException {

        try {
            X509V2CRLGenerator crlGen = new X509V2CRLGenerator();
            Date now = new Date();
            crlGen.setIssuerDN(caCertificate.getSubjectX500Principal());
            crlGen.setThisUpdate(now);
            long crlUpdateTimeMillis = CaConstants.CRL_UPDATE_INTERVAL * 1000;
            crlGen.setNextUpdate(new Date(now.getTime() + crlUpdateTimeMillis));
            crlGen.setSignatureAlgorithm(CaConstants.SHA256_WITH_RSA_ENCRYPTION);
            for (RevokedCertificate revokedCertificate : revokedCertificates) {
                BigInteger serialNo = new BigInteger(revokedCertificate.getSerialNo());
                crlGen.addCRLEntry(serialNo, revokedCertificate.getRevokedDate(),
                        revokedCertificate.getReason());
            }
            crlGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                    new AuthorityKeyIdentifierStructure(caCertificate));
            crlGen.addExtension(X509Extensions.CRLNumber, false,
                    new CRLNumber(BigInteger.valueOf(crlNumber)));
            if (isDeltaCrl) {
                crlGen.addExtension(X509Extensions.DeltaCRLIndicator, true,
                        new CRLNumber(BigInteger.valueOf(baseCrlNumber)));
            }
            return crlGen.generateX509CRL(caPrivateKey, CaConstants.BC_PROVIDER);
        } catch (NoSuchProviderException e) {
            log.error("Bouncycastle Provider not added to the system", e);
        } catch (SignatureException e) {
            log.error("Signature algorithm not available", e);
        } catch (InvalidKeyException e) {
            log.error("Invalid key used", e);
        } catch (CertificateParsingException e) {
            log.error("Error parsing Certificate", e);
        }
        throw new CaException("Error when creating CRL");
    }

    /**
     * @param tenantId tenant Id
     * @return full crl of the tenant
     * @throws Exception
     */

    public X509CRL createFullCrl(int tenantId) throws CaException {
        RevocationDAO revocationDAO = new RevocationDAO();
        CrlDAO crlDAO = new CrlDAO();
        List<RevokedCertificate> revokedCertificates = revocationDAO.listRevokedCertificates
                (tenantId);
//        CRLDataHolder crlDataHolder = crlDataHolderDao.getLatestCRL(tenantId, false);
        PrivateKey privateKey = CaConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate certb = CaConfiguration.getInstance().getConfiguredCaCert();
        int fullnumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltanumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;
        return createCRL(certb, privateKey, revokedCertificates, nextCrlNumber, -1, false);

    }

    /**
     * @param tenantId id of the tenant creating delta crl
     * @return a delta crl which
     * @throws Exception
     */
    public X509CRL createDeltaCrl(int tenantId) throws CaException {
        RevocationDAO revocationDAO = new RevocationDAO();
        CrlDAO crlDAO = new CrlDAO();
        X509CRL latestCrl;
        latestCrl = ConversionUtils.toX509Crl(crlDAO.getLatestCRL(tenantId,
                false).getBase64Crl());
        List<RevokedCertificate> revokedCertificates = revocationDAO.getRevokedCertificatesAfter
                (tenantId, latestCrl.getThisUpdate());
        PrivateKey privateKey = CaConfiguration.getInstance().getConfiguredPrivateKey();
        X509Certificate certb = CaConfiguration.getInstance().getConfiguredCaCert();
        int fullnumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltanumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;
        return createCRL(certb, privateKey, revokedCertificates, nextCrlNumber, fullnumber,
                false);
    }

    /**
     * creates and store a crl in db for the given tenant
     *
     * @param tenantId tenant id
     * @throws Exception
     */
    public void createAndStoreCrl(int tenantId) throws CaException {
        X509CRL crl = createFullCrl(tenantId);
        CrlDAO crlDAO = new CrlDAO();
        RevocationDAO revocationDAO = new RevocationDAO();
        revocationDAO.removeReactivatedCertificates();
        int fullnumber = crlDAO.getHighestCrlNumber(tenantId, false);
        int deltanumber = crlDAO.getHighestCrlNumber(tenantId, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;

        crlDAO.addCRL(crl, tenantId, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber, -1);

    }

    /**
     * create and store a delta crl in database
     *
     * @param tenantId id of the tenant
     * @throws CaException
     */
    public void createAndStoreDeltaCrl(int tenantId) throws CaException {
        X509CRL crl = createDeltaCrl(tenantId);
        if (crl != null) {
            CrlDAO crlDAO = new CrlDAO();
            int fullNumber = crlDAO.getHighestCrlNumber(tenantId, false);
            int deltaNumber = crlDAO.getHighestCrlNumber(tenantId, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ((fullNumber > deltaNumber) ? fullNumber : deltaNumber) + 1;
            crlDAO.addCRL(crl, tenantId, crl.getThisUpdate(), crl.getNextUpdate(), nextCrlNumber,
                    1);
        }
    }

}
