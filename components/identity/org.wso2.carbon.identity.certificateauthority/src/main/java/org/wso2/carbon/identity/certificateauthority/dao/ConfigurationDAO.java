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

package org.wso2.carbon.identity.certificateauthority.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x509.CRLReason;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Performs DAO operations related to the CA configurations.
 */
public class ConfigurationDAO {

    private static Log log = LogFactory.getLog(ConfigurationDAO.class);

    /**
     * Retrieve the key that is configured to use for the CA operations for the given tenant.
     *
     * @param tenantDomain The domain of the tenant whose key need to be retrieved
     * @return The key path for the configured key in the format of "{keyStoreName}/{keyAlias}",
     * <code>null</code> if no configured key exists(The default key is used in that case)
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String getConfiguredKey(String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.GET_CA_CONFIGURATION_QUERY;

        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                String keyStore = resultSet.getString(SQLConstants.KEY_STORE_COLUMN);
                String alias = resultSet.getString(SQLConstants.ALIAS_COLUMN);
                return keyStore + "/" + alias;
            }
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        return null;
    }

    /**
     * Update the key of the tenant CA.
     *
     * @param tenantDomain   The domain of the tenant whose key need to be updated
     * @param keyStore       The new key store where the key is
     * @param alias          The alias that identify the key
     * @param oldCertificate The previously used certificate of the CA,
     *                       which will be revoked with the update
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void updateCAConfiguration(String tenantDomain, String keyStore, String alias,
                                      X509Certificate oldCertificate) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SQLConstants.GET_CA_CONFIGURATION_QUERY;

        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                sql = SQLConstants.UPDATE_CA_CONFIGURATION_QUERY;
                prepStmt = connection.prepareStatement(sql);
                prepStmt.setString(1, keyStore);
                prepStmt.setString(2, alias);
                prepStmt.setInt(6, tenantId);
                prepStmt.executeUpdate();
            } else {
                sql = SQLConstants.ADD_CA_CONFIGURATION_QUERY;
                prepStmt = connection.prepareStatement(sql);
                prepStmt.setInt(1, tenantId);
                prepStmt.setString(2, keyStore);
                prepStmt.setString(3, alias);
                prepStmt.executeUpdate();
            }
            if (oldCertificate != null) {
                RevocationDAO revocationDAO = new RevocationDAO();
                revocationDAO.addRevokedCertificate(oldCertificate.getSerialNumber().toString(), tenantDomain,
                        CRLReason.keyCompromise);
            }
            connection.commit();
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the update of signing key", e1);
            }
            throw new CAException("Error when executing the SQL : " + sql, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}
