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

package org.wso2.carbon.identity.certificateauthority.endpoint.scep;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.jscep.server.ScepServlet;
import org.jscep.transaction.TransactionId;
import org.jscep.transport.response.Capability;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.CertificateManager;
import org.wso2.carbon.identity.certificateauthority.CrlManager;
import org.wso2.carbon.identity.certificateauthority.ScepManager;
import org.wso2.carbon.identity.certificateauthority.endpoint.CaEndpointConstants;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Implements the abstract methods from ScepServlet class from jscep.
 */
public class ScepServletImpl extends ScepServlet {

    private ScepManager scepManager = ScepManager.getInstance();
    private static Log log = LogFactory.getLog(ScepServletImpl.class);
    private String tenantDomain;

    public ScepServletImpl(String tenantDomain) {
        this.tenantDomain = tenantDomain;
    }

    @Override
    protected Set<Capability> doCapabilities(String s) throws Exception {
        return CaEndpointConstants.SCEP_CAPABILITIES;
    }

    @Override
    protected List<X509Certificate> doGetCaCertificate(String s) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>(1);
        certificateList.add(getSigner());
        return  certificateList;
    }

    @Override
    protected List<X509Certificate> getNextCaCertificate(String s) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>(1);
        certificateList.add(getSigner());
        return  certificateList;
    }

    @Override
    protected List<X509Certificate> doGetCert(X500Name x500Name, BigInteger bigInteger)
            throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        X509Certificate x509Certificate =
                CertificateManager.getInstance().getX509Certificate(bigInteger.toString());
        X500Name issuerX500Name = new X500Name(x509Certificate.getIssuerX500Principal().getName());
        if (issuerX500Name.equals(x500Name)){
            certificateList.add(x509Certificate);
            certificateList.addAll(doGetCaCertificate(null));
        }
        return certificateList;
    }

    @Override
    protected List<X509Certificate> doGetCertInitial(X500Name issuer, X500Name subject,
                                                     TransactionId transactionId) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        X509Certificate certificate =
                scepManager.getCertificate(tenantDomain, transactionId.toString());
        X500Name certificateIssuer = new X500Name(certificate.getIssuerX500Principal().getName());
        X500Name certificateSubject = new X500Name(certificate.getSubjectX500Principal().getName());
        if(certificateIssuer.equals(issuer) && certificateSubject.equals(subject)){
            certificateList.add(certificate);
            certificateList.addAll(doGetCaCertificate(null));
        }
        return certificateList;
    }

    @Override
    protected X509CRL doGetCrl(X500Name x500Name, BigInteger bigInteger) throws Exception {
        CrlManager crlManager = CrlManager.getInstance();
        return crlManager.getLatestX509Crl(tenantDomain);
    }

    @Override
    protected List<X509Certificate> doEnrol(PKCS10CertificationRequest request,
                                            TransactionId transactionId) throws Exception {
        List<X509Certificate> certificateList = new ArrayList<X509Certificate>();
        X509Certificate certificate =
                scepManager.enroll(request, transactionId.toString(), tenantDomain);
        if(certificate !=null){
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
            return scepManager.getCaKey(tenantDomain);
        } catch (CaException e) {
            if(log.isDebugEnabled()){
                log.debug("Key not available for tenant domain: "+tenantDomain,e);
            }
            return null;
        }
    }

    @Override
    protected X509Certificate getSigner() {
        try {
            return scepManager.getCaCert(tenantDomain);
        } catch (CaException e) {
            if(log.isDebugEnabled()){
                log.debug("Certificate not available for tenant domain: "+tenantDomain,e);
            }
            return null;
        }
    }
}