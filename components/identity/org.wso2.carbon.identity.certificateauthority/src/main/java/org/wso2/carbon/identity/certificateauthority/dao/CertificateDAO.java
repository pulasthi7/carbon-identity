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

public class CertificateDAO {
    private static final Log LOGGER = LogFactory.getLog(CertificateDAO.class);

    /**
     * adds a certificate to the database
     *
     * @param serial   serial number of the certificate
     * @param tenantID id of the tenant tenant who issued the certificate
     * @return
     */
    public void addCertificate(String serial, X509Certificate certificate, int tenantID,
                               String username, String userStoreDomain) throws CaException {
        Connection connection = null;
        Date requestDate = new Date();
        String sql = SqlConstants.ADD_CERTIFICATE_QUERY;
        PreparedStatement prepStmt = null;
        try {
            Date expiryDate = certificate.getNotAfter();
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serial);
            prepStmt.setBlob(2, new ByteArrayInputStream(certificate.getEncoded()));
            prepStmt.setString(3, CertificateStatus.ACTIVE.toString());
            prepStmt.setTimestamp(4, new Timestamp(requestDate.getTime()));
            prepStmt.setTimestamp(5, new Timestamp(expiryDate.getTime()));
            prepStmt.setInt(6, tenantID);
            prepStmt.setString(7, username);
            prepStmt.setString(8, userStoreDomain);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql,e);
            throw new CaException("Error while adding the certificate", e);
        } catch (CertificateEncodingException e) {
            LOGGER.error("Error while encoding certificate", e);
            throw new CaException("Error while adding the certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * update certificate status to a given string
     *
     * @param serialNo serial number of the PC
     * @param status   Status of the PC
     */
    public void updateCertificateStatus(String serialNo, String status) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.UPDATE_CERTIFICATE_QUERY;
        int result = 0;
        try {
            LOGGER.debug("updating PC with serial number :" + serialNo);
            connection = JDBCPersistenceManager.getInstance().getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status);
            prepStmt.setString(2, serialNo);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error updating certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Gets a certificate from a serial number
     *
     * @param serialNo serial number of the certificate
     * @return Certificate
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
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving certificate", e);
        } catch (CertificateException e) {
            LOGGER.error("Error generating certificate from blob for serial no: " + serialNo);
            throw new CaException("Error when retrieving certificate", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }

        //Reaches below when certificate does not exist
        LOGGER.debug("No Certificate with serial no : " + serialNo);
        throw new CaException("No such certificate");
    }

    /**
     * Get certificate information given the serial number.
     *
     * @param serialNo serial number of the certificate
     * @return Certificate
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
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        //Reaches below when certificate does not exist
        LOGGER.debug("No Certificate with serial no : " + serialNo);
        throw new CaException("No such certificate");
    }

    /**
     * Lists all certificates issued by a tenant's CA
     *
     * @param tenantId id of the tenant
     * @return set of certificate meta infos of all the certificates issued by the given tenant
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
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Lists all certificates issued by a tenant's CA with given status
     *
     * @param status   status of the certificate
     * @param tenantId tenant Id
     * @return
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
            LOGGER.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            LOGGER.error("Error when executing the SQL : " + sql);
            throw new CaException("Error when retrieving certificate information", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

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
