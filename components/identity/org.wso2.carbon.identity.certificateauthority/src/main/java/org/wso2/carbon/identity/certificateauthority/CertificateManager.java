/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.common.CsrStatus;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.CsrDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.data.CsrInfo;
import org.wso2.carbon.identity.certificateauthority.utils.CaObjectUtils;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

public class CertificateManager {
    private static CertificateManager instance = new CertificateManager();
    private static final Log log = LogFactory.getLog(CertificateManager.class);

    private CsrDAO csrDAO = new CsrDAO();
    private CertificateDAO certificateDAO = new CertificateDAO();
    private RevocationDAO revocationDAO = new RevocationDAO();

    public static CertificateManager getInstance() {
        return instance;
    }

    private CertificateManager() {
    }

    /**
     * Signs the CSR with the given serial no, so that the resulting certificate will have the
     * given validity period from the time of signing
     * @param serialNo The serial no of the CSR to be signed
     * @param validity The validity of the resulting certificate in days
     * @throws CaException If signing or storing the certificate fails
     */
    public void signCSR(int tenantId, String serialNo, int validity) throws CaException {

        CsrInfo csr = csrDAO.getCSR(serialNo, tenantId);

        if (!CsrStatus.PENDING.toString().equals(csr.getStatus())) {
            throw new CaException("Certificate already signed, rejected or revoked");
        }
        CaConfiguration configurationManager = CaConfiguration.getInstance();
        X509Certificate signedCert = getSignedCertificate(serialNo,
                csrDAO.getPKCS10CertificationRequest
                        (serialNo), validity, configurationManager.getConfiguredPrivateKey(),
                configurationManager.getConfiguredCaCert()
        );
        certificateDAO.addCertificate(serialNo, signedCert, tenantId,
                csr.getUserName(), csr.getUserStoreDomain());
    }

    /**
     * Revoke or update the revoke reason for the given certificate
     * @param tenantId the tenant Id of the CA
     * @param serial The serial no of the certificate to be revoked
     * @param reason The reason code for the revocation
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void revokeCert(int tenantId, String serial, int reason) throws CaException {
        int currentRevokeReason = revocationDAO.getRevokeReason(serial);
        if(currentRevokeReason < 0){
            revocationDAO.addRevokedCertificate(serial,tenantId,reason);
        } else {
            revocationDAO.updateRevokedCertificate(serial,tenantId,reason);
        }
    }

    /**
     * Revokes all certificates issued by a tenant ID
     * @param tenantId The tenant id of the CA
     * @param revokeReason The reason code for the revocation
     * @throws CaException
     * @see org.wso2.carbon.identity.certificateauthority.common.RevokeReason
     */
    public void revokeAllIssuedCertificates(int tenantId, int revokeReason) throws CaException {
        CertificateDAO certificateDAO = new CertificateDAO();
        List<CertificateInfo> certificates =
                certificateDAO.listCertificates(CertificateStatus.ACTIVE.toString(), tenantId);
        for (CertificateInfo certificate : certificates) {
            revokeCert(tenantId, certificate.getSerialNo(),revokeReason);
        }
    }

    /**
     * Get the PEM encoded Certificate for the given serial no
     * @param serial The serial no of the certificate
     * @return The certificate as a PEM encoded string
     * @throws CaException
     */
    public String getPemEncodedCertificate(String serial) throws CaException {
        X509Certificate x509Certificate = certificateDAO.getCertificate(serial);
        return CaObjectUtils.toPemEncodedCertificate(x509Certificate);
    }

    /**
     * Get the certificate in X509 format for the given serial no
     * @param serial The serial no of the certificate
     * @return The certificate in X509 format
     * @throws CaException
     */
    public X509Certificate getX509Certificate(String serial) throws CaException{
        return certificateDAO.getCertificate(serial);
    }

    /**
     * Signs the CSR and return the certificate in x509 format
     * @param serialNo The serial no of the CSR
     * @param request The PKCS10CertificationRequest to be signed
     * @param validity The validity of the resulting certificate
     * @param privateKey The CA's private key
     * @param caCert The CA's certificate
     * @return Signed x509 certificate
     * @throws CaException
     */
    private X509Certificate getSignedCertificate(String serialNo, PKCS10CertificationRequest
            request, int validity, PrivateKey privateKey, X509Certificate caCert) throws
            CaException {
        try {

            Date issuedDate = new Date();
            Calendar expiryDate =Calendar.getInstance();
            expiryDate.add(Calendar.DAY_OF_YEAR,validity);

            JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(request);
            X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(caCert,
                    new BigInteger(serialNo), issuedDate, expiryDate.getTime(),
                    jcaRequest.getSubject(), jcaRequest.getPublicKey());
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            certificateBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(caCert))
                    .addExtension(Extension.subjectKeyIdentifier, false,
                            extUtils.createSubjectKeyIdentifier(jcaRequest
                                    .getPublicKey()))
                    .addExtension(Extension.basicConstraints, true, new BasicConstraints(0))
                    .addExtension(Extension.keyUsage, true,
                            new KeyUsage(KeyUsage.digitalSignature | KeyUsage
                                    .keyEncipherment))
                    .addExtension(Extension.extendedKeyUsage, true,
                            new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            ContentSigner signer =
                    new JcaContentSignerBuilder(CaConstants.SHA1_WITH_RSA).setProvider
                            (CaConstants.BC_PROVIDER).build(privateKey);
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            DistributionPointName crlEp =
                    new DistributionPointName(new GeneralNames(new GeneralName(GeneralName
                            .uniformResourceIdentifier,
                            CaConstants.HTTP_SERVER_URL + CaConstants.CRL_ENDPOINT + tenantDomain)));
            DistributionPoint disPoint = new DistributionPoint(crlEp, null, null);
            certificateBuilder.addExtension(Extension.cRLDistributionPoints, false,
                    new CRLDistPoint(new DistributionPoint[]{disPoint}));
            AccessDescription ocsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier,
                            CaConstants.HTTP_SERVER_URL + CaConstants.OCSP_ENDPOINT + tenantDomain)
            );
            ASN1EncodableVector authInfoAccessASN = new ASN1EncodableVector();
            authInfoAccessASN.add(ocsp);
            certificateBuilder.addExtension(Extension.authorityInfoAccess, false,
                    new DERSequence(authInfoAccessASN));
            return new JcaX509CertificateConverter().setProvider(CaConstants.BC_PROVIDER)
                    .getCertificate(certificateBuilder.build(signer));
        } catch (Exception e) {
            throw new CaException("Error in signing the certificate", e);
        }
    }
}
