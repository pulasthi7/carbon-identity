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
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.identity.certificateauthority.model.RevokedCertificate;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class OCSPService {

    private CertificateDAO certificateDAO = new CertificateDAO();
    private RevocationDAO revocationDAO = new RevocationDAO();
    private CAConfigurationService configurationService = new CAConfigurationService();

    private Log log = LogFactory.getLog(OCSPService.class);

    /**
     * handles the OCSP requests
     *
     * @param req          The OCSP request
     * @param tenantDomain The tenant domain of the CA for whom the request is made
     * @return The OCSP response
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public OCSPResp handleOCSPRequest(OCSPReq req, String tenantDomain)
            throws CAException {
        OCSPRespBuilder respGenerator = new OCSPRespBuilder();
        try {
            if (req == null || req.getRequestList().length <= 0) {
                return respGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null);
            }
            //sign with tenant's configured key
            Req[] requests = req.getRequestList();
            CertificateID certificateId;
            Certificate certificate;
            X509Certificate caCert = configurationService.getConfiguredCACert(tenantDomain);
            PrivateKey privateKey = configurationService.getConfiguredPrivateKey(tenantDomain);
            SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey().getEncoded());
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(CAConstants.BC_PROVIDER).build().get(CertificateID.HASH_SHA1);
            BasicOCSPRespBuilder basicRespGen = new BasicOCSPRespBuilder(keyInfo, digestCalculator);
            Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (ext != null) {
                // Put the nonce back in the response
                basicRespGen.setResponseExtensions(new Extensions(new Extension[]{ext}));
            }
            for (Req request : requests) {
                certificateId = request.getCertID();
                certificate = certificateDAO.getCertificate(certificateId.getSerialNumber().toString(), tenantDomain);
                if (certificate == null || tenantDomain.equals(certificate.getTenantDomain())) {
                    basicRespGen.addResponse(certificateId, new UnknownStatus());
                } else {
                    org.wso2.carbon.identity.certificateauthority.common.CertificateStatus certificateStatus = org
                            .wso2.carbon.identity.certificateauthority.common.CertificateStatus.valueOf
                                    (certificate.getStatus());
                    switch (certificateStatus) {
                        case REVOKED:
                            RevokedCertificate revokedCertificate = revocationDAO
                                    .getRevokedCertificate(certificate.getSerialNo());
                            basicRespGen.addResponse(certificateId,
                                    new RevokedStatus(revokedCertificate.getRevokedDate(),
                                            revokedCertificate.getReason())
                            );
                            break;
                        case ACTIVE:
                            basicRespGen.addResponse(certificateId, CertificateStatus.GOOD);
                            break;
                        default:
                            basicRespGen.addResponse(certificateId, new UnknownStatus());
                    }
                }
            }
            //Signs the OCSP response
            ContentSigner contentSigner = new JcaContentSignerBuilder(CAConstants.SHA1_WITH_RSA)
                    .setProvider(CAConstants.BC_PROVIDER).build(privateKey);
            BasicOCSPResp basicOCSPResp = basicRespGen.build(contentSigner,
                    new X509CertificateHolder[]{new X509CertificateHolder(caCert.getEncoded())}, new Date());

            return respGenerator.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

            //OCSP requests are generated from an unauthenticated endpoint,
            // so the errors are logged at debug level to prevent logs being created unnecessarily
        } catch (OperatorCreationException e) {
            throw new CAException("Error when signing OCSP response for tenant:" + tenantDomain, e);
        } catch (CertificateEncodingException e) {
            throw new CAException("Error in certificate encoding for CA Certificate of tenant:" + tenantDomain, e);
        } catch (IOException e) {
            throw new CAException("Error when building certificate holder for CA certificate of tenant: " +
                    tenantDomain, e);
        } catch (OCSPException e) {
            //building OCSP response fails at BC
            throw new CAException("Error building the OCSP response", e);
        }
    }
}
