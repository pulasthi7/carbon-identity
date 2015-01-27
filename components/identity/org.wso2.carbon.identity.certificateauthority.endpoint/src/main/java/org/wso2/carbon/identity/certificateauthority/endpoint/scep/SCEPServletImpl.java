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

package org.wso2.carbon.identity.certificateauthority.endpoint.scep;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.server.ScepServlet;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CAServerException;
import org.wso2.carbon.identity.certificateauthority.endpoint.CAEndpointConstants;
import org.wso2.carbon.identity.certificateauthority.endpoint.util.CAEndpointUtils;
import org.wso2.carbon.identity.certificateauthority.services.CRLService;
import org.wso2.carbon.identity.certificateauthority.services.CertificateService;
import org.wso2.carbon.identity.certificateauthority.services.SCEPService;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Implements the abstract methods from ScepServlet class from jscep.
 */
public class SCEPServletImpl extends ScepServlet {

    private static Log log = LogFactory.getLog(SCEPServletImpl.class);
    private String tenantDomain;

    /**
     * Instantiate SCEPServletImpl with the CA's tenant domain.
     *
     * @param tenantDomain The tenant domain of the CA whose SCEP operations should be handled.
     */
    public SCEPServletImpl(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    @Override
    protected Set<Capability> doCapabilities(String s) throws Exception {
        return CAEndpointConstants.SCEP_CAPABILITIES;
    }

    @Override
    protected List<X509Certificate> doGetCaCertificate(String s) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>(1);
        certificateList.add(getSigner());
        return certificateList;
    }

    @Override
    protected List<X509Certificate> getNextCaCertificate(String s) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>(1);
        certificateList.add(getSigner());
        return certificateList;
    }

    @Override
    protected List<X509Certificate> doGetCert(X500Name x500Name, BigInteger bigInteger) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        CertificateService certificateService = CAEndpointUtils.getCertificateService();
        X509Certificate x509Certificate = certificateService.getX509Certificate(bigInteger.toString());
        if (x509Certificate != null) {
            X500Name issuerX500Name = new X500Name(x509Certificate.getIssuerX500Principal().getName());
            if (issuerX500Name.equals(x500Name)) {
                certificateList.add(x509Certificate);
                //adds the CA certificate to the chain
                certificateList.addAll(doGetCaCertificate(null));
            }
        }
        return certificateList;
    }

    @Override
    protected List<X509Certificate> doGetCertInitial(X500Name issuer, X500Name subject,
                                                     TransactionId transactionId) throws Exception {
        SCEPService scepService = CAEndpointUtils.getSCEPService();
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        X509Certificate certificate = scepService.getCertificate(tenantDomain, transactionId.toString());
        if (certificate == null) {
            //A certificate with given params does not exists, logging as debug since the request is from an
            // unauthenticated endpoint
            if (log.isDebugEnabled()) {
                log.debug("No certificate with transaction id: " + transactionId.toString());
            }
            return certificateList;
        }
        X500Name certificateIssuer = new X500Name(certificate.getIssuerX500Principal().getName());
        X500Name certificateSubject = new X500Name(certificate.getSubjectX500Principal().getName());
        if (certificateIssuer.equals(issuer) && certificateSubject.equals(subject)) {
            certificateList.add(certificate);
            //adds the CA certificate to the chain
            certificateList.addAll(doGetCaCertificate(null));
        }
        return certificateList;
    }

    @Override
    protected X509CRL doGetCrl(X500Name x500Name, BigInteger bigInteger) throws Exception {
        CRLService crlService = CAEndpointUtils.getCRLService();
        return crlService.getLatestX509Crl(tenantDomain);
    }

    @Override
    protected List<X509Certificate> doEnrol(PKCS10CertificationRequest request,
                                            TransactionId transactionId) throws Exception {
        SCEPService scepService = CAEndpointUtils.getSCEPService();
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        X509Certificate certificate = scepService.enroll(request, transactionId.toString(), tenantDomain);
        if (certificate != null) {
            certificateList.add(certificate);
            certificateList.addAll(doGetCaCertificate(null));
        }
        return certificateList;
    }

    @Override
    protected PrivateKey getRecipientKey() {
        return getSignerKey();
    }

    @Override
    protected X509Certificate getRecipient() {
        return getSigner();
    }

    @Override
    protected PrivateKey getSignerKey() {
        try {
            SCEPService scepService = CAEndpointUtils.getSCEPService();
            return scepService.getCaKey(tenantDomain);
        } catch (CAServerException e) {
            log.error("Server error when getting signer key.", e);
            return null;
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Key not available for tenant domain: " + tenantDomain, e);
            }
            return null;
        }
    }

    @Override
    protected X509Certificate getSigner() {
        try {
            SCEPService scepService = CAEndpointUtils.getSCEPService();
            return scepService.getCaCert(tenantDomain);
        } catch (CAServerException e) {
            log.error("Server Error when getting signer.", e);
            return null;
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Certificate not available for tenant domain: " + tenantDomain, e);
            }
            return null;
        }
    }
}
