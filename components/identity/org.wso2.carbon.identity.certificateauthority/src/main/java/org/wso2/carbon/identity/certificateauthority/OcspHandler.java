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
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.RevocationDAO;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.data.RevokedCertificate;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class OcspHandler {

    private CertificateDAO certificateDAO;
    private RevocationDAO revocationDAO;

    private Log log = LogFactory.getLog(OcspHandler.class);

    public OcspHandler() {
        this.certificateDAO = new CertificateDAO();
        this.revocationDAO = new RevocationDAO();
    }

    public OCSPResp handleOCSPRequest(OCSPReq req, String tenantDomain) throws CaException,
            OCSPException {
        OCSPRespBuilder respGenerator = new OCSPRespBuilder();
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            if (req == null || req.getRequestList().length <= 0) {
                return respGenerator.build(OCSPRespBuilder.MALFORMED_REQUEST, null);
            }
            //sign with tenant's configured key
            Req[] requests = req.getRequestList();
            CertificateID certID;
            CertificateInfo certificateInfo;
            CaConfiguration configurationManager = CaConfiguration.getInstance();
            X509Certificate caCert = configurationManager.getConfiguredCaCert(tenantId);
            PrivateKey privateKey = configurationManager.getConfiguredPrivateKey(tenantId);
            SubjectPublicKeyInfo keyinfo = SubjectPublicKeyInfo.getInstance(caCert.getPublicKey()
                    .getEncoded());
            DigestCalculator digestCalculator = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(CaConstants.BC_PROVIDER).build().get(CertificateID.HASH_SHA1);
            BasicOCSPRespBuilder basicRespGen = new BasicOCSPRespBuilder(keyinfo, digestCalculator);
            Extension ext = req.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (ext != null) {
                basicRespGen.setResponseExtensions(new Extensions(new Extension[] { ext })); // Put the
                // nonce back in the response
            }
            for (Req request : requests) {
                certID = request.getCertID();
                certificateInfo = certificateDAO.getCertificateInfo(certID.getSerialNumber()
                        .toString(), tenantId);
                if (certificateInfo == null || tenantId != certificateInfo.getTenantID()) {
                    basicRespGen.addResponse(certID, new UnknownStatus());
                } else {
                    org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
                            certificateStatus = org.wso2
                            .carbon.identity.certificateauthority.common.CertificateStatus
                            .valueOf(certificateInfo.getStatus());
                    switch (certificateStatus) {
                        case REVOKED:
                            RevokedCertificate revokedCertificate = revocationDAO
                                    .getRevokedCertificate(certificateInfo.getSerialNo());
                            basicRespGen.addResponse(certID,
                                    new RevokedStatus(revokedCertificate.getRevokedDate(),
                                            revokedCertificate.getReason()));
                            break;
                        case ACTIVE:
                            basicRespGen.addResponse(certID, CertificateStatus.GOOD);
                            break;
                        default:
                            basicRespGen.addResponse(certID, new UnknownStatus());
                    }
                }
            }
            ContentSigner contentSigner =  new JcaContentSignerBuilder(CaConstants.SHA1_WITH_RSA)
                    .setProvider(CaConstants.BC_PROVIDER).build(privateKey);
            BasicOCSPResp basicOCSPResp = basicRespGen.build(contentSigner,
                    new X509CertificateHolder[]{new X509CertificateHolder(caCert.getEncoded())},
                    new Date());

            return respGenerator.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);
        } catch (OperatorCreationException e) {
            log.debug("Error when processing request", e);
        } catch (CertificateEncodingException e) {
            log.debug("Error in certificate encoding", e);
        } catch (IOException e) {
            log.debug("IO Error reading CA certificate", e);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain",e);
        }
        return respGenerator.build(OCSPRespBuilder.INTERNAL_ERROR, null);
    }
}
