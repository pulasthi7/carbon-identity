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
import org.bouncycastle.asn1.x509.CRLReason;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.dao.CertificateDAO;
import org.wso2.carbon.identity.certificateauthority.dao.ConfigurationDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.model.Certificate;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.security.keystore.service.KeyStoreData;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class CAConfigurationService {

    private static final Log log = LogFactory.getLog(CAConfigurationService.class);
    private static CAConfigurationService instance = new CAConfigurationService();
    private ConfigurationDAO configurationDAO = new ConfigurationDAO();
    private CAConfiguration configuration = CAConfiguration.getInstance();

    private CAConfigurationService() {
    }

    public static CAConfigurationService getInstance() {
        return instance;
    }

    /**
     * Gives the CA certificate of the current tenant. Returns the default certificate if
     * certificate is not configured.
     *
     * @return The CA certificate of the current tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCACert() throws CAException {
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        return getConfiguredCACert(tenantDomain);
    }

    /**
     * Gives the CA certificate of the tenant given by the tenantId. Returns the default certificate
     * if certificate is not configured.
     *
     * @param tenantDomain The tenant domain of the tenant whose certificate should be returned
     * @return The CA certificate of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public X509Certificate getConfiguredCACert(String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantDomain);
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            if (keyPath == null) {
                //Using the default key
                if (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equals(tenantDomain)) {
                    return keyStoreManager.getDefaultPrimaryCertificate();
                } else {
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    return (X509Certificate) keyStoreManager.getKeyStore(jksName).getCertificate(tenantDomain);
                }
            }
            //Any not null keypath will have the format <KeyStoreName>/<Alias>
            String[] storeAndAlias = keyPath.split("/");
            return (X509Certificate) keyStoreManager.getKeyStore(storeAndAlias[0]).getCertificate(storeAndAlias[1]);
        } catch (Exception e) {
            //KeystoreManager throws "Exception"
            throw new CAException("Error retrieving CA Certificate from " + keyPath, e);
        }
    }

    /**
     * Return the CA certificate of the tenant specified by the tenantDomain as a PEM encoded
     * string.
     *
     * @param tenantDomain The tenantDomain whose certificate is needed
     * @return The CA certificate as a PEM encoded string
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String getPemEncodedCACert(String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        try {
            return CAObjectUtils.toPemEncodedCertificate(getConfiguredCACert(tenantDomain));
        } catch (IOException e) {
            throw new CAException("Error when encoding the certificate to PEM", e);
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
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        return getConfiguredPrivateKey(tenantDomain);
    }

    /**
     * Returns the private key of the given tenant, which is used to sign CSRs,
     * CRL and OCSP requests
     *
     * @return The private key of the given tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PrivateKey getConfiguredPrivateKey(String tenantDomain) throws CAException {
        if(StringUtils.isEmpty(tenantDomain)){
            throw new IllegalArgumentException("Tenant domain cannot be empty");
        }
        String keyPath = configurationDAO.getConfiguredKey(tenantDomain);
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
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
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (Exception e) {
            // thrown from keyStoreManager.getDefaultPrivateKey()
            throw new CAException("Error retrieving CA's private key for tenant:" + tenantDomain, e);
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
        if(registry == null){
            throw new IllegalArgumentException("Registry cannot be null");
        }
        List<String> keyList = new ArrayList<String>();

        //tenantId is required for KeyStoreAdmin
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantDomain);

        if (keyPath != null) {
            //The current configuration will be the first of the list
            keyList.add(keyPath);
        }

        KeyStoreAdmin keyStoreAdmin = new KeyStoreAdmin(tenantId, registry);
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        KeyStoreData[] keyStores;
        try {
            keyStores = keyStoreAdmin.getKeyStores(tenantId == MultitenantConstants.SUPER_TENANT_ID);
        } catch (SecurityConfigException e) {
            throw new CAException("Error when retrieving keystore for tenant: " + tenantDomain, e);
        }
        for (KeyStoreData keyStore : keyStores) {
            if (keyStore != null) {
                String keyStoreName = keyStore.getKeyStoreName();
                KeyStore keyStoreManagerKeyStore = null;
                try {
                    keyStoreManagerKeyStore = keyStoreManager.getKeyStore(keyStoreName);
                    Enumeration<String> aliases = keyStoreManagerKeyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = aliases.nextElement();
                        if (keyStoreManagerKeyStore.isKeyEntry(alias)) {
                            keyList.add(keyStoreName + "/" + alias);
                        }
                    }
                } catch (KeyStoreException e) {
                    throw new CAException("Error when listing aliases for keystore: " + keyStoreName, e);
                } catch (Exception e) {
                    throw new CAException("Error when accessing the keystore: " + keyStoreName, e);
                }
            }
        }
        return keyList;
    }

    /**
     * Update the key that the tenant will be using for CA operations.<br/>
     * <b>Note: </b> Updating the key will revoke all the certificates that were signed using the
     * key
     *
     * @param tenantDomain The tenant domain of the tenant whose key should be updated
     * @param keyStore     The new keystore where the key is
     * @param alias        The alias for the key
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void updateKey(String tenantDomain, String keyStore, String alias) throws CAException {
        if (StringUtils.isBlank(keyStore) || StringUtils.isBlank(alias)) {
            throw new IllegalArgumentException("Keystore and alias cannot be null or empty");
        }
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        CertificateDAO certificateDAO = new CertificateDAO();
        String currentKeyPath = configurationDAO.getConfiguredKey(tenantDomain);
        String newKeyPath = keyStore + "/" + alias;
        if (currentKeyPath != null && !currentKeyPath.equals(newKeyPath)) {
            //revoke the ca certificate itself
            X509Certificate caCert = getConfiguredCACert();
            List<Certificate> certificates =
                    certificateDAO.listCertificates(CertificateStatus.ACTIVE.toString(), tenantDomain);
            configurationDAO.updateCAConfiguration(tenantDomain, keyStore, alias, caCert);

            //Revoke each issued certificates
            for (Certificate certificate : certificates) {
                try {
                    CertificateService certificateService = CertificateService.getInstance();
                    certificateService.revokeCert(tenantDomain, certificate.getSerialNo(), CRLReason.cACompromise);
                } catch (CAException e) {
                    //If any certificate revocation fails it should not affect the rest of the
                    // certificate revocations. So the error is not propagated to the callee
                    log.error("Revocation failed for certificate with serial number:" + certificate.getSerialNo(), e);
                }
            }
            CRLService crlService = CRLService.getInstance();
            crlService.createAndStoreDeltaCrl(tenantDomain);
        }
    }

    /**
     * Get the validity of a generated SCEP token
     *
     * @return
     */
    public int getTokenValidity() {
        return configuration.getTokenValidity();
    }

    /**
     * Get the length of the SCEP token.
     *
     * @return
     */
    public int getTokenLength() {
        return configuration.getTokenLength();
    }

    /**
     * Get the validity of the certificates that are issued from a SCEP operation
     *
     * @return
     */
    public int getScepIssuedCertificateValidity() {
        return configuration.getScepIssuedCertificateValidity();
    }
}
