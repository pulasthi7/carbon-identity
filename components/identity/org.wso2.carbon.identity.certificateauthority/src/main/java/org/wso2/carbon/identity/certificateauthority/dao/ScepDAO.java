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

package org.wso2.carbon.identity.certificateauthority.dao;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.Date;

/**
 * Performs DAO operations related to SCEP enrollments
 */
public class ScepDAO {
    private static Log log = LogFactory.getLog(ScepDAO.class);

    /**
     * Adds an generated scep token to the db. This token can be later used by the user in
     * certificate enrollment process to authenticate user.
     * @param token The token to be stored
     * @param userName The user for whom the token in generated
     * @param userStoreDomain The user store of the domain
     * @param tenantId The user's tenant id
     * @return <code>true</code> if token is added successfully, <code>false</code> otherwise
     * @throws CaException
     */
    public boolean addScepToken(String token, String userName,
                             String userStoreDomain, int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.ADD_SCEP_TOKEN;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, token);
            prepStmt.setTimestamp(2,new Timestamp(new Date().getTime()));
            prepStmt.setString(3, userName);
            prepStmt.setInt(4, tenantId);
            prepStmt.setString(5, userStoreDomain);
            prepStmt.executeUpdate();
            connection.commit();
            return true;
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when adding the token", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Adds a CSR from SCEP PKI operation to the DB
     * @param certReq The CSR to be added
     * @param transId The transaction ID which can be used to identify the CSR
     * @param token The token associated with the operation
     * @param tenantId The tenant id of CA
     * @return The serial no of the CSR that was added.
     * @throws CaException
     */
    public String addScepCsr(PKCS10CertificationRequest certReq, String transId,
                             String token, int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.GET_SCEP_TOKEN;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, token);
            prepStmt.setInt(2,tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()){
                //token exists
                CaConfiguration caConfiguration = CaConfiguration.getInstance();
                String serialNo = resultSet.getString(SqlConstants.SERIAL_NO_COLUMN);
                if( serialNo != null){
                    throw new CaException("The token is already used");
                }
                Date date = resultSet.getTimestamp(SqlConstants.CREATED_TIME_COLUMN);
                if (date.getTime() + caConfiguration.getTokenValidity() < new java.util
                        .Date().getTime()){
                    throw new CaException("The token is expired, create a new token");
                }
                String userName = resultSet.getString(SqlConstants.USERNAME_COLUMN);
                String userStoreDomain = resultSet.getString(SqlConstants.USERSTORE_DOMAIN_COLUMN);

                //Adds to the CSR table
                CsrDAO csrDAO = new CsrDAO();
                serialNo = csrDAO.addCsr(certReq, userName, tenantId, userStoreDomain);
                sql = SqlConstants.UPDATE_SCEP_TOKEN;
                prepStmt = connection.prepareStatement(sql);
                prepStmt.setString(1,serialNo);
                prepStmt.setString(2,transId);
                prepStmt.setString(3,token);
                prepStmt.executeUpdate();
                connection.commit();
                return serialNo;
            } else {
                throw new CaException("Invalid token given");
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when adding the request", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Gets the certificate that was enrolled for the given transaction id
     * @param transactionId The id that is used to identify the PKI operation
     * @param tenantId The tenant id of CA
     * @return The certificate that was enrolled from the PKI operation
     * @throws CaException
     */
    public X509Certificate getCertificate(String transactionId, int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.GET_ENROLLED_CERTIFICATE_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, transactionId);
            prepStmt.setInt(2,tenantId);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()){
                Blob certificateBlob = resultSet.getBlob(SqlConstants.CERTIFICATE_COLUMN);
                CertificateFactory certificateFactory = CertificateFactory.getInstance
                        (CaConstants.X509);
                X509Certificate certificate = (X509Certificate) certificateFactory
                        .generateCertificate(certificateBlob.getBinaryStream());
                if (certificate != null) {
                    return certificate;
                }
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when retrieving certificate", e);
        } catch (CertificateException e) {
            log.error("Error occured with certificate factory",e);
            throw new CaException("Error when retrieving certificate",e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        //Reaches below when certificate does not exist
        if(log.isDebugEnabled()){
            log.debug("Transaction id : "+ transactionId+" is valid, " +
                    "but the certificate is not found in database for its serial no");
        }
        throw new CaException("Requested certificate is not available");
    }
}
