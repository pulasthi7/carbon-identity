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

package org.wso2.carbon.identity.certificateauthority.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.CRLReason;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CRLManager;
import org.wso2.carbon.identity.certificateauthority.CertificateManager;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.ConfigurationDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.security.keystore.service.KeyStoreData;
import org.wso2.carbon.user.api.UserStoreException;

import javax.xml.namespace.QName;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Reads and store the configuration needed for CA.
 * Configurations are read from identity.xml
 */
public class CAConfiguration {

    private static final String CA_ROOT_ELEMENT = "CertificateAuthority";
    private static final String SCEP_CONF_ELEMENT = "ScepConfiguration";
    private static final String SCEP_TOKEN_LENGTH_ELEM = "TokenLength";
    private static final String SCEP_TOKEN_VALIDITY_ELEM = "TokenValidity";
    private static final String SCEP_CERTIFICATE_VALIDITY_ELEM = "CertificateValidity";
    private static final Log log = LogFactory.getLog(CAConfiguration.class);
    private static CAConfiguration instance = new CAConfiguration();
    //initializing to default values in case of reading configs fails
    private int scepTokenLength = CAConstants.DEFAULT_SCEP_TOKEN_LENGTH;
    private int scepTokenValidity = CAConstants.DEFAULT_SCEP_TOKEN_VALIDITY;
    private int scepCertificateValidity = CAConstants.DEFAULT_SCEP_CERTIFICATE_VALIDITY;

    /**
     * Private constructor that initialize the configs from identity.xml
     */
    private CAConfiguration() {
//        buildCaConfiguration();
    }

    /**
     * Gets the instance of the CaConfiguration
     *
     * @return
     */
    public static CAConfiguration getInstance() {
        return instance;
    }

    /**
     * Reads the configuration from identity.xml and store them. If any of the configs are
     * missing they are initialized to the default values
     */
    private void buildCaConfiguration() {
        IdentityConfigParser configParser = null;
        try {
            configParser = IdentityConfigParser.getInstance();
            OMElement caRootElem = configParser.getConfigElement(CA_ROOT_ELEMENT);
            if (caRootElem == null) {
                log.warn("Certificate Authority configuration was not found in identity.xml, " +
                        "using the default configuration");
                return;
            }
            OMElement scepElement = caRootElem.getFirstChildWithName(new QName
                    (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE,
                            SCEP_CONF_ELEMENT));
            if (scepElement != null) {
                OMElement tokenLengthElem = scepElement.getFirstChildWithName(new QName
                        (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE, SCEP_TOKEN_LENGTH_ELEM));
                if (tokenLengthElem != null) {
                    scepTokenLength = Integer.parseInt(tokenLengthElem.getText().trim());
                } else {
                    scepTokenLength = CAConstants.DEFAULT_SCEP_TOKEN_LENGTH;
                }

                OMElement tokenValidityElem = scepElement.getFirstChildWithName(new QName
                        (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE, SCEP_TOKEN_VALIDITY_ELEM));
                if (tokenValidityElem != null) {
                    scepTokenValidity = Integer.parseInt(tokenValidityElem.getText().trim());
                } else {
                    scepTokenValidity = CAConstants.DEFAULT_SCEP_TOKEN_VALIDITY;
                }

                OMElement certificateValidityElem = scepElement.getFirstChildWithName(new QName
                        (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE,
                                SCEP_CERTIFICATE_VALIDITY_ELEM));
                if (certificateValidityElem != null) {
                    scepCertificateValidity = Integer.parseInt(certificateValidityElem.getText()
                            .trim());
                } else {
                    scepCertificateValidity = CAConstants.DEFAULT_SCEP_CERTIFICATE_VALIDITY;
                }
            }
        } catch (ServerConfigurationException e) {
            log.error("Error loading CA related configurations.", e);
        }
    }

    /**
     * Gives the CA certificate of the current tenant. Returns the default certificate if
     * certificate is not configured
     *
     * @return The CA certificate of the current tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCaCert() throws CAException {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        return getConfiguredCaCert(tenantId);
    }

    /**
     * Gives the CA certificate of the tenant given by the tenantId. Returns the default certificate
     * if certificate is not configured
     *
     * @param tenantId The tenant id of the tenant whose certificate should be returned
     * @return The CA certificate of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCaCert(int tenantId) throws CAException {
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String tenantDomain =
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantId);
        try {
            if (keyPath == null) {
                //Using the default key
                if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
                    return keyStoreManager.getDefaultPrimaryCertificate();
                } else {
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    return (X509Certificate) keyStoreManager.getKeyStore(jksName)
                            .getCertificate(tenantDomain);
                }
            }
            String[] storeAndAlias = keyPath.split("/");
            return (X509Certificate) keyStoreManager.getKeyStore(storeAndAlias[0]).getCertificate
                    (storeAndAlias[1]);
        } catch (Exception e) {
            throw new CAException("Error retrieving CA Certificate", e);
        }
    }

    /**
     * Return the CA certificate of the tenant specified by the tenantDomain as a PEM encoded
     * string
     *
     * @param tenantDomain The tenantDomain whose certificate is needed
     * @return The CA certificate as a PEM encoded string
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String getPemEncodedCaCert(String tenantDomain) throws CAException {
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return CAObjectUtils.toPemEncodedCertificate(getConfiguredCaCert(tenantId));
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain", e);
        }
    }

    /**
     * Returns the private key of the current tenant which is used to sign CSRs,
     * CRL and OCSP requests
     *
     * @return The private key of the current tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PrivateKey getConfiguredPrivateKey() throws CAException {
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        return getConfiguredPrivateKey(tenantID);
    }

    /**
     * Returns the private key of the given tenant, which is used to sign CSRs,
     * CRL and OCSP requests
     *
     * @return The private key of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PrivateKey getConfiguredPrivateKey(int tenantId) throws CAException {
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String tenantDomain =
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantId);

        try {
            if (keyPath == null) {
                if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
                    return keyStoreManager.getDefaultPrivateKey();
                } else {
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    return (PrivateKey) keyStoreManager.getPrivateKey(jksName, tenantDomain);
                }
            }
            String[] storeAndAlias = keyPath.split("/");
            Key privateKey = keyStoreManager.getPrivateKey(storeAndAlias[0], storeAndAlias[1]);
            return (PrivateKey) privateKey;
        } catch (Exception e) {
            throw new CAException("Error retrieving CA's private key", e);
        }
    }

    /**
     * Lists all the keys available for the current tenant. Tenant admin can configure one of
     * them as the key to sign the CSRs, CRLs and OCSP requests
     *
     * @param registry The registry where the keystores are
     * @return List of keystores and key aliases in the format "keystore/alias"
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<String> listAllKeys(Registry registry) throws CAException {
        List<String> keyList = new ArrayList<String>();


        try {
            int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            ConfigurationDAO configurationDAO = new ConfigurationDAO();
            String keyPath = configurationDAO.getConfiguredKey(tenantId);

            if (keyPath != null) {
                //The current configuration will be the first of the list
                keyList.add(keyPath);
            }

            KeyStoreAdmin admin = new KeyStoreAdmin(tenantId, registry);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            KeyStoreData[] keyStores =
                    admin.getKeyStores(tenantId == MultitenantConstants.SUPER_TENANT_ID);
            for (KeyStoreData keyStore : keyStores) {
                if (keyStore != null) {
                    String keyStoreName = keyStore.getKeyStoreName();
                    KeyStore keyStoreManagerKeyStore = keyStoreManager.getKeyStore(keyStoreName);
                    Enumeration<String> aliases = keyStoreManagerKeyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (keyStoreManagerKeyStore.isKeyEntry(alias)) {
                            keyList.add(keyStoreName + "/" + alias);
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error listing the keys", e);
            throw new CAException("Error listing the keys", e);
        }
        return keyList;
    }

    /**
     * Update the key that the tenant will be using for CA operations.<br/>
     * <b>Note: </b> Updating the key will revoke all the certificates that were signed using the
     * key
     *
     * @param tenantId The tenant id of the tenant whose key should be updated
     * @param keyStore The new keystore where the key is
     * @param alias    The alias for the key
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void updateKey(int tenantId, String keyStore, String alias) throws CAException {
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        CertificateDAO certificateDAO = new CertificateDAO();
        String currentKeyPath = configurationDAO.getConfiguredKey(tenantId);
        String newKeyPath = keyStore + "/" + alias;
        if (currentKeyPath != null && !currentKeyPath.equals(newKeyPath)) {
            //revoke the ca certificate itself
            X509Certificate caCert = getConfiguredCaCert();

            List<Certificate> certificates =
                    certificateDAO.listCertificates(CertificateStatus.ACTIVE.toString(), tenantId);
            configurationDAO.updateCaConfiguration(tenantId, keyStore, alias, caCert);

            //Revoke each issued certificates
            for (Certificate certificate : certificates) {
                try {
                    CertificateManager.getInstance().revokeCert(tenantId,
                            certificate.getSerialNo(), CRLReason.cACompromise);
                } catch (CAException e) {
                    //If any certificate revocation fails it should not affect the rest of the
                    // certificate revocations. So the error is not propagated to the callee
                    log.error(e);
                }
            }
            CRLManager crlManager = new CRLManager();
            crlManager.createAndStoreDeltaCrl(tenantId);
        }

    }

    /**
     * Get the validity of a generated SCEP token
     *
     * @return
     */
    public int getTokenValidity() {
        return scepTokenValidity;
    }

    /**
     * Get the length of the SCEP token.
     *
     * @return
     */
    public int getTokenLength() {
        return scepTokenLength;
    }

    /**
     * Get the validity of the certificates that are issued from a SCEP operation
     *
     * @return
     */
    public int getScepIssuedCertificateValidity() {
        return scepCertificateValidity;
    }

}
