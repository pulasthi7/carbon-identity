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
import org.wso2.carbon.identity.certificateauthority.common.CSRStatus;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.dao.CSRDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.model.CSR;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.identity.certificateauthority.model.RevokedCertificate;
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

public class CertificateService {
    private static final Log log = LogFactory.getLog(CertificateService.class);
    private CSRDAO csrDAO = new CSRDAO();
    private CertificateDAO certificateDAO = new CertificateDAO();
    private RevocationDAO revocationDAO = new RevocationDAO();

    /**
     * Signs the CSR with the given serial no, so that the resulting certificate will have the
     * given validity period from the time of signing
     *
     * @param serialNo The serial no of the CSR to be signed
     * @param validity The validity of the resulting certificate in days
     * @throws org.wso2.carbon.identity.certificateauthority.CAException If signing or storing the certificate fails
     */
    public void signCSR(String tenantDomain, String serialNo, int validity) throws CAException {

        CSR csr = csrDAO.getCSR(serialNo, tenantDomain);

        if (!CSRStatus.PENDING.toString().equals(csr.getStatus())) {
            throw new CAException("Certificate already signed, rejected or revoked");
        }
        CAConfigurationService caConfigurationService = new CAConfigurationService();
        PKCS10CertificationRequest certificationRequest = csrDAO.getPKCS10CertificationRequest(serialNo);
        if (certificationRequest != null) {
            X509Certificate signedCert = getSignedCertificate(serialNo, certificationRequest, validity,
                    caConfigurationService.getConfiguredPrivateKey(), caConfigurationService.getConfiguredCACert());
            certificateDAO.addCertificate(serialNo, signedCert, tenantDomain, csr.getUserName(),
                    csr.getUserStoreDomain());
        }
    }

    /**
     * Revoke or update the revoke reason for the given certificate
     *
     * @param tenantDomain the tenant domain of the CA
     * @param serialNo     The serial no of the certificate to be revoked
     * @param reason       The reason code for the revocation as specified in {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public void revokeCert(String tenantDomain, String serialNo, int reason) throws CAException {
        int currentRevokeReason = revocationDAO.getRevokeReason(serialNo);
        if (currentRevokeReason < 0) {
            revocationDAO.addRevokedCertificate(serialNo, tenantDomain, reason);
        } else {
            revocationDAO.updateRevokedCertificate(serialNo, tenantDomain, reason);
        }
    }

    /**
     * Revokes all certificates issued by a tenant ID
     *
     * @param tenantDomain The tenant id of the CA
     * @param revokeReason The reason code for the revocation as specified in
     *                     {@link org.bouncycastle.asn1.x509.CRLReason}
     * @throws CAException
     */
    public void revokeAllIssuedCertificates(String tenantDomain, int revokeReason) throws CAException {
        CertificateDAO certificateDAO = new CertificateDAO();
        List<Certificate> certificates =
                certificateDAO.listCertificates(CertificateStatus.ACTIVE.toString(), tenantDomain);
        for (Certificate certificate : certificates) {
            revokeCert(tenantDomain, certificate.getSerialNo(), revokeReason);
        }
    }

    /**
     * Get the PEM encoded Certificate for the given serial no
     *
     * @param serialNo The serial no of the certificate
     * @return The certificate as a PEM encoded string
     * @throws CAException
     */
    public String getPemEncodedCertificate(String serialNo) throws CAException {
        X509Certificate x509Certificate = certificateDAO.getCertificate(serialNo);
        try {
            return CAObjectUtils.toPemEncodedCertificate(x509Certificate);
        } catch (IOException e) {
            throw new CAException("Error when encoding the certificate to PEM", e);
        }
    }

    /**
     * Get the certificate in X509 format for the given serial no
     *
     * @param serialNo The serial no of the certificate
     * @return The certificate in X509 format
     * @throws CAException
     */
    public X509Certificate getX509Certificate(String serialNo) throws CAException {
        return certificateDAO.getCertificate(serialNo);
    }

    /**
     * Signs the CSR and return the certificate in x509 format
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
                    "Error with CA certificate encoding of " + caCert.getSubjectX500Principal().getName());
        } catch (CertificateException e) {
            throw new CAException("Error when signing the certificate", e);
        } catch (InvalidKeyException e) {
            throw new CAException("Invalid public key in CSR", e);
        }
    }

    /**
     * Get the certificate specified by the serial number.
     *
     * @param serialNo serial number of the certificate
     * @return Information about the certificate
     */
    public Certificate getCertificate(String serialNo, String tenantDomain) throws CAException {
        return certificateDAO.getCertificate(serialNo, tenantDomain);
    }

    /**
     * Lists all certificates issued by a tenant's CA.
     *
     * @param tenantDomain domain of the tenant
     * @return Set of certificates with given status issued by the given CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<Certificate> listCertificates(String tenantDomain) throws CAException {
        return certificateDAO.listCertificates(tenantDomain);
    }

    /**
     * Lists all certificates issued by a tenant's CA with given status
     *
     * @param status       Status filter for the certificates
     * @param tenantDomain domain of the tenant
     * @return Set of certificates with given status issued by the given CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<Certificate> listCertificates(String status, String tenantDomain) throws CAException {
        return certificateDAO.listCertificates(status, tenantDomain);
    }

    /**
     * Get Revoked certificate details from serial number
     *
     * @param serialNo The SerialNo of the revoked certificate
     * @return The details of the revoked certificate
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public RevokedCertificate getRevokedCertificate(String serialNo) throws CAException {
        return revocationDAO.getRevokedCertificate(serialNo);
    }
}
