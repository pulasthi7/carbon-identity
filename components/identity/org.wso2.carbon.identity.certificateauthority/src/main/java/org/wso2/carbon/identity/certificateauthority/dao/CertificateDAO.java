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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.common.CsrStatus;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.core.persistence.JDBCPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Performs DAO operations related to the certificates.
 */
public class CertificateDAO {
    private static final Log log = LogFactory.getLog(CertificateDAO.class);

    /**
     * Stores certificate in the database, and update the relevant CSR status
     * @param serialNo The serial number of the certificate
     * @param tenantId ID of the tenant tenant who issued the certificate
     * @return
     */
    public void addCertificate(String serialNo, X509Certificate certificate, int tenantId,
                               String username, String userStoreDomain) throws CaException {
        Connection connection = null;
        Date requestDate = new Date();
        String sql = SqlConstants.ADD_CERTIFICATE_QUERY;
        PreparedStatement prepStatement = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            Date expiryDate = certificate.getNotAfter();
            prepStatement = connection.prepareStatement(sql);
            prepStatement.setString(1, serialNo);
            prepStatement.setBlob(2, new ByteArrayInputStream(certificate.getEncoded()));
            prepStatement.setString(3, CertificateStatus.ACTIVE.toString());
            prepStatement.setTimestamp(4, new Timestamp(requestDate.getTime()));
            prepStatement.setTimestamp(5, new Timestamp(expiryDate.getTime()));
            prepStatement.setInt(6, tenantId);
            prepStatement.setString(7, username);
            prepStatement.setString(8, userStoreDomain);
            prepStatement.executeUpdate();
            CsrDAO csrDAO = new CsrDAO();
            csrDAO.updateStatus(connection, serialNo, CsrStatus.SIGNED, tenantId);
            connection.commit();
        } catch (IdentityException e) {
            log.error("Error when getting an Identity Persistence Store instance.", e);
            throw new CaException("Error Signing certificate", e);
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back the transaction to sign CSR", e1);
            }
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error while adding the certificate", e);
        } catch (CertificateEncodingException e) {
            log.error("Error while encoding certificate", e);
            throw new CaException("Error while adding the certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStatement);
        }
    }

    /**
     * Update certificate status to the given value. Status is updated as a part of some other
     * operations, so this method require the same DB connection as used in those operations to
     * make sure that the operation and the status update is done in single db commit.
     * @param connection The DB connection
     * @param serialNo The serial number of the certificate
     * @param status The new status
     * @throws SQLException If update operation fails
     */
    public void updateCertificateStatus(Connection connection, String serialNo,
                                        String status) throws SQLException {
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.UPDATE_CERTIFICATE_QUERY;
        try {
            if(log.isDebugEnabled()){
                log.debug("updating certificate with serial number :" + serialNo+" as "+status);
            }
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status);
            prepStmt.setString(2, serialNo);
            prepStmt.executeUpdate();
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }

    /**
     * Gets the certificate specified by the given serial number
     *
     * @param serialNo serial number of the certificate
     * @return Certificate if exists
     */
    public X509Certificate getCertificate(String serialNo) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.GET_CERTIFICATE_QUERY;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
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
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving certificate", e);
        } catch (CertificateException e) {
            log.error("Error generating certificate from blob for serial no: " + serialNo,e);
            throw new CaException("Error when retrieving certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        //Reaches below when certificate does not exist
        if(log.isDebugEnabled()){
            log.debug("No Certificate with serial no : " + serialNo);
        }
        throw new CaException("No such certificate");
    }

    /**
     * Get information about the certificate specified by the serial number.
     *
     * @param serialNo serial number of the certificate
     * @return Information about the certificate
     */
    public CertificateInfo getCertificateInfo(String serialNo, int tenantID) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.GET_CERTIFICATE_INFO_FOR_ADMIN_QUERY;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setInt(2, tenantID);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                String status = resultSet.getString(SqlConstants.STATUS_COLUMN);
                Date expiryDate = resultSet.getTimestamp(SqlConstants
                        .CERTIFICATE_EXPIRY_DATE_COLUMN);
                Date issuedDate = resultSet.getTimestamp(SqlConstants
                        .CERTIFICATE_ISSUED_DATE_COLUMN);
                String username = resultSet.getString(SqlConstants.USERNAME_COLUMN);
                String userStoreDomain = resultSet.getString(SqlConstants.USERSTORE_DOMAIN_COLUMN);
                return new CertificateInfo(serialNo, issuedDate,
                        expiryDate, status, username, tenantID, userStoreDomain);
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        //Reaches below when certificate does not exist
        if(log.isDebugEnabled()){
            log.debug("No Certificate with serial no : " + serialNo);
        }
        throw new CaException("No such certificate");
    }

    /**
     * Lists all certificates issued by a tenant's CA
     *
     * @param tenantId Id of the tenant
     * @return Set of all the certificates issued by the tenant's CA
     * @throws CaException
     */
    public List<CertificateInfo> listCertificates(int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.LIST_CERTIFICATES_QUERY;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            return getCertificateInfoFromResultSet(resultSet, tenantId);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Lists all certificates issued by a tenant's CA with given status
     *
     * @param status   Status filter for the certificates
     * @param tenantId Tenant Id
     * @return Set of certificates with given status issued by the given CA
     * @throws CaException
     */
    public List<CertificateInfo> listCertificates(String status, int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet;
        String sql = SqlConstants.LIST_CERTIFICATES_BY_STATUS_QUERY;
        try {
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, CertificateStatus.valueOf(status).toString());
            prepStmt.setInt(2, tenantId);
            resultSet = prepStmt.executeQuery();
            return getCertificateInfoFromResultSet(resultSet, tenantId);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Retrieve Certificate data from ResultSet
     * @param resultSet The result set from which the certificates are retrieved
     * @param tenantId The id of the tenant CA relevant to the query
     * @return Set of certificates from the result set
     * @throws SQLException
     */
    private List<CertificateInfo> getCertificateInfoFromResultSet(ResultSet resultSet,
                                                                  int tenantId)
            throws SQLException {
        List<CertificateInfo> certificateInfoList = new ArrayList<CertificateInfo>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SqlConstants.SERIAL_NO_COLUMN);
            String status = resultSet.getString(SqlConstants.STATUS_COLUMN);
            Date expiryDate = resultSet.getTimestamp(SqlConstants
                    .CERTIFICATE_EXPIRY_DATE_COLUMN);
            Date issuedDate = resultSet.getTimestamp(SqlConstants
                    .CERTIFICATE_ISSUED_DATE_COLUMN);
            String username = resultSet.getString(SqlConstants.USERNAME_COLUMN);
            String userStoreDomain = resultSet.getString(SqlConstants.USERSTORE_DOMAIN_COLUMN);
            certificateInfoList.add(new CertificateInfo(serialNo, issuedDate, expiryDate,
                    status, username, tenantId, userStoreDomain));
        }
        return certificateInfoList;
    }

}