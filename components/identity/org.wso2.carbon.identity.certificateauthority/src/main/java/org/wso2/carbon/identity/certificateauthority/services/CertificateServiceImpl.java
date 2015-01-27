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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.bean.CSR;
import org.wso2.carbon.identity.certificateauthority.bean.Certificate;
import org.wso2.carbon.identity.certificateauthority.bean.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.common.CSRStatus;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

/**
 * The service implementation of CertificateService
 */
public class CertificateServiceImpl implements CertificateService {

    private static final Log log = LogFactory.getLog(CertificateServiceImpl.class);
    private static CertificateService instance = new CertificateServiceImpl();
    private CertificateDAO certificateDAO = new CertificateDAO();
    private RevocationDAO revocationDAO = new RevocationDAO();

    private CertificateServiceImpl() {
    }

    public static CertificateService getInstance() {
        return instance;
    }

    @Override
    public void signCSR(String tenantDomain, String serialNo, int validity) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("CSR Serial number cannot be empty");
        }
        if (validity <= 0) {
            throw new IllegalArgumentException("Validity should have a positive value");
        }
        CSRService csrService = CAServiceComponent.getCsrService();
        CSR csr = csrService.getCSR(serialNo, tenantDomain);

        if (csr != null && !CSRStatus.PENDING.toString().equals(csr.getStatus())) {
            throw new CAException("CSR cannot be signed, It's either invalid, already signed, rejected or revoked");
        }
        CAConfigurationService caConfigurationService = CAServiceComponent.getCaConfigurationService();
        PKCS10CertificationRequest certificationRequest = csrService.getPKCS10CertificationRequest(serialNo);
        if (certificationRequest != null) {
            X509Certificate signedCert = getSignedCertificate(serialNo, certificationRequest, validity,
                    caConfigurationService.getConfiguredPrivateKey(), caConfigurationService.getConfiguredCACert());
            certificateDAO.addCertificate(serialNo, signedCert, tenantDomain, csr.getUserName(),
                    csr.getUserStoreDomain());
        }
    }

    @Override
    public void revokeCert(String tenantDomain, String serialNo, int reason) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        if (!isRevokeReasonValid(reason)) {
            throw new IllegalArgumentException("Reason code " + reason + " is not valid");
        }
        int currentRevokeReason = revocationDAO.getRevokeReason(serialNo);
        if (currentRevokeReason < 0) {
            // -1 is returned if there is no revoke information available for the certificate. So we need to add as new.
            revocationDAO.addRevokedCertificate(serialNo, tenantDomain, reason);
        } else {
            // certificate is already revoked, we are updating the reason
            revocationDAO.updateRevokedCertificate(serialNo, tenantDomain, reason);
        }
    }

    @Override
    public void revokeAllIssuedCertificates(String tenantDomain, int revokeReason) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (!isRevokeReasonValid(revokeReason)) {
            throw new IllegalArgumentException("Reason code " + revokeReason + " is not valid");
        }
        CertificateDAO certificateDAO = new CertificateDAO();
        List<Certificate> certificates =
                certificateDAO.listCertificates(CertificateStatus.ACTIVE.toString(), tenantDomain);
        for (Certificate certificate : certificates) {
            revokeCert(tenantDomain, certificate.getSerialNo(), revokeReason);
        }
    }

    @Override
    public String getPemEncodedCertificate(String serialNo) throws CAException {
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        X509Certificate x509Certificate = certificateDAO.getCertificate(serialNo);
        try {
            if (x509Certificate != null) {
                return CAObjectUtils.toPemEncodedCertificate(x509Certificate);
            }
        } catch (IOException e) {
            throw new CAException("Error when encoding the certificate to PEM", e);
        }
        return null;
    }

    @Override
    public X509Certificate getX509Certificate(String serialNo) throws CAException {
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return certificateDAO.getCertificate(serialNo);
    }

    /**
     * Signs the CSR and return the certificate in x509 format.
     *
     * @param serialNo   The serial no of the CSR
     * @param request    The PKCS10CertificationRequest to be signed
     * @param validity   The validity of the resulting certificate
     * @param privateKey The CA's private key
     * @param caCert     The CA's certificate
     * @return Signed x509 certificate
     * @throws CAException
     */
    private X509Certificate getSignedCertificate(String serialNo, PKCS10CertificationRequest request, int validity,
                                                 PrivateKey privateKey, X509Certificate caCert) throws CAException {
        try {
            Date issuedDate = new Date();
            Calendar expiryDate = Calendar.getInstance();
            expiryDate.add(Calendar.DAY_OF_YEAR, validity);
            JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);
            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCert,
                    new BigInteger(serialNo), issuedDate, expiryDate.getTime(), jcaRequest.getSubject(),
                    jcaRequest.getPublicKey());
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

            //Adds certificate extensions which include authority/subject key identifiers, key usages,
            // extended key usages
            certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(caCert))
                    .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier
                            (jcaRequest.getPublicKey()))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
                    .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage
                            .keyEncipherment))
                    .addExtension(Extension.extendedKeyUsage, false,
                            new ExtendedKeyUsage(new KeyPurposeId[]{KeyPurposeId.id_kp_clientAuth,
                                    KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_emailProtection})
                    );
            ContentSigner signer = new JcaContentSignerBuilder(CAConstants.SHA1_WITH_RSA).setProvider(CAConstants
                    .BC_PROVIDER).build(privateKey);
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            //Adds CRL and OCSP endpoints
            DistributionPointName crlEp =
                    new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                            CAConstants.HTTP_SERVER_URL + CAConstants.CRL_ENDPOINT + tenantDomain
                    )));
            DistributionPoint disPoint = new DistributionPoint(crlEp, null, null);
            certificateBuilder.addExtension(Extension.cRLDistributionPoints, false,
                    new CRLDistPoint(new DistributionPoint[]{disPoint}));
            AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, CAConstants.HTTP_SERVER_URL + CAConstants
                            .OCSP_ENDPOINT + tenantDomain)
            );
            ASN1EncodableVector authInfoAccessASN = new ASN1EncodableVector();
            authInfoAccessASN.add(ocsp);
            certificateBuilder.addExtension(Extension.authorityInfoAccess, false, new DERSequence(authInfoAccessASN));
            return new JcaX509CertificateConverter().setProvider(CAConstants.BC_PROVIDER).getCertificate
                    (certificateBuilder.build(signer));
        } catch (OperatorCreationException e) {
            throw new CAException("Error creating certificate signer", e);
        } catch (CertIOException e) {
            throw new CAException("Error adding extensions to the certificate", e);
        } catch (NoSuchAlgorithmException e) {
            //very unlikely to occur
            throw new CAException("Error with JCA algorithm", e);
        } catch (CertificateEncodingException e) {
            throw new CAException(
                    "Error with CA certificate encoding of " + caCert.getSubjectX500Principal().getName(), e);
        } catch (CertificateException e) {
            throw new CAException("Error when signing the certificate", e);
        } catch (InvalidKeyException e) {
            throw new CAException("Invalid public key in CSR", e);
        }
    }

    @Override
    public Certificate getCertificate(String serialNo, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return certificateDAO.getCertificate(serialNo, tenantDomain);
    }

    @Override
    public List<Certificate> listCertificates(String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        return certificateDAO.listCertificates(tenantDomain);
    }

    @Override
    public List<Certificate> listCertificates(String status, String tenantDomain) throws CAException {
        if (StringUtils.isEmpty(tenantDomain)) {
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        if (StringUtils.isEmpty(status)) {
            throw new IllegalArgumentException("Status cannot be empty");
        }
        return certificateDAO.listCertificates(status, tenantDomain);
    }

    @Override
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CAException {
        if (StringUtils.isEmpty(serialNo)) {
            throw new IllegalArgumentException("Certificate Serial number cannot be empty");
        }
        return revocationDAO.getRevokedCertificate(serialNo);
    }

    /**
     * Check whether the given reason code is valid.
     *
     * @param reasonCode The reason code to be validated
     * @return <code>true</code> if reason code is valid, <code>false</code> otherwise
     */
    private boolean isRevokeReasonValid(int reasonCode) {
        //reason code should have a value in range [0,10], see CRLReason class for exact values.
        return reasonCode >= 0 && reasonCode <= 10;
    }
}
