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
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.common.CsrStatus;
import org.wso2.carbon.identity.certificateauthority.data.CsrInfo;
import org.wso2.carbon.identity.certificateauthority.utils.CaObjectUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Performs DAO operations related to the CSRs
 */
public class CsrDAO {

    private static final Log log = LogFactory.getLog(CsrDAO.class);

    /**
     * Adds a new CSR to the DB
     * @param csrContent The CSR as an encoded string
     * @param userName The user who requested the CSR to sign
     * @param tenantID The id of the tenant where the user belongs
     * @param userStoreDomain The user store where the user is
     * @return The serial no of the newly added CSR, which can be used in later queries
     * @throws CaException
     */
    public String addCsr(String csrContent, String userName, int tenantID, String userStoreDomain)
            throws CaException {
        PKCS10CertificationRequest request = CaObjectUtils.toPkcs10CertificationRequest
                (csrContent);
        return addCsr(request,userName,tenantID,userStoreDomain);
    }

    /**
     * Adds a new CSR to the DB
     * @param request PKCS10CertificationRequest form of the request
     * @param userName   The user who requested the CSR to sign
     * @param tenantID   The id of the tenant where the user belongs
     * @param userStoreDomain The user store where the user is
     * @return
     */
    public String addCsr(PKCS10CertificationRequest request, String userName, int tenantID,
                         String userStoreDomain) throws CaException {
        String csrSerialNo = new BigInteger(32, new SecureRandom()).toString();
        Connection connection = null;
        Date requestDate = new Date();
        String sql = SqlConstants.ADD_CSR_QUERY;
        PreparedStatement prepStmt = null;

        //Some RDNs are stored separately for indexing purposes
        RDN[] orgRdNs = request.getSubject().getRDNs(BCStyle.O);
        //Organization is not a mandatory field, it may be null, therefore initializing it to
        // empty string
        String organization = "";
        if (orgRdNs.length > 0) {
            organization = orgRdNs[0].getFirst().getValue().toString();
        }
        RDN[] cnRdNs = request.getSubject().getRDNs(BCStyle.CN);
        String commonName = "";
        if (cnRdNs.length > 0) {
            commonName = cnRdNs[0].getFirst().getValue().toString();
        }
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setBlob(1, new ByteArrayInputStream(request.getEncoded()));
            prepStmt.setString(2, CsrStatus.PENDING.toString());
            prepStmt.setString(3, userName);
            prepStmt.setTimestamp(4, new Timestamp(requestDate.getTime()));
            prepStmt.setString(5, csrSerialNo);
            prepStmt.setInt(6, tenantID);
            prepStmt.setString(7, commonName);
            prepStmt.setString(8, organization);
            prepStmt.setString(9, userStoreDomain);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error storing CSR to the database", e);
        } catch (IOException e) {
            log.error("Error when reading CSR to byte stream", e);
            throw new CaException("Error with the CSR provided",e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return csrSerialNo;
    }

    /**
     * Gets CSR data from database for given serial number
     *
     * @param serialNo serial number of the CSR
     * @return Details about the CSR
     */
    public CsrInfo getCSR(String serialNo, String userStoreDomain, String userName,
                          int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.GET_CSR_FOR_USER_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, serialNo);
            prepStmt.setString(2, userName);
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userStoreDomain);
            resultSet = prepStmt.executeQuery();
            List<CsrInfo> csrInfoList = getCsrListFromResultSet(resultSet);
            if (!csrInfoList.isEmpty()) {
                return csrInfoList.get(0);
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when retrieving the CSR details", e);
        } catch (IOException e) {
            log.error("Error decoding CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found, " +
                    "or not accessible by " + userStoreDomain + "\\" + userName + " of tenant id " +
                    tenantId);
        }
        throw new CaException("CSR for given serial not found");
    }

    /**
     * Mark the CSR as a rejected one
     * @param serialNo The serial no of the CSR to be marked as rejected
     * @param tenantId The id of the tenant CA
     * @throws CaException
     */
    public void rejectCSR(String serialNo, int tenantId) throws CaException{
        Connection connection = null;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            updateStatus(connection, serialNo, CsrStatus.REJECTED, tenantId);
            connection.commit();
        } catch (IdentityException e) {
            log.error("Error when getting an Identity Persistence Store instance.", e);
            throw new CaException("Error rejecting certificate", e);
        } catch (SQLException e) {
            try{
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back rejection of CSR",e1);
            }
            log.error("Error rejecting certificate",e);
            throw new CaException("Error rejecting certificate", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    /**
     * Retrieves the CSRs stored in the DB
     * @param serialNo The serial no of the CSR to be retrieved
     * @return The CSR as a PKCS10CertificationRequest
     * @throws CaException
     */
    public PKCS10CertificationRequest getPKCS10CertificationRequest(String serialNo)
            throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.GET_CSR_CONTENT_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                Blob csrBlob = resultSet.getBlob(SqlConstants.CSR_CONTENT_COLUMN);
                return new PKCS10CertificationRequest(csrBlob.getBytes(1, (int) csrBlob.length()));
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when retrieving the CSR", e);
        } catch (IOException e) {
            log.error("Error decoding CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found");
        }
        throw new CaException("CSR for given serial not found");
    }

    /**
     * Retrieve the CSR details for the given serial no
     * @param serialNo The serial no of the CSR to be retrieved
     * @param tenantId The id of the tenant CA
     * @return The CSR details
     * @throws CaException
     */
    public CsrInfo getCSR(String serialNo, int tenantId) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.GET_CSR_FOR_ADMIN_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setInt(2, tenantId);
            resultSet = prepStmt.executeQuery();
            List<CsrInfo> csrInfoList = getCsrListFromResultSet(resultSet);
            if (!csrInfoList.isEmpty()) {
                return csrInfoList.get(0);
            }
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when retrieving the CSR details", e);
        } catch (IOException e) {
            log.error("Error decoding CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found, " +
                    "or not accessible by tenant id " + tenantId);
        }
        throw new CaException("CSR for given serial not found");
    }

    /**
     * Lists CSRs that are for the specified tenant
     * @param tenantID The id of the tenant whose CSRs need to be listed
     * @return The list of CSRs for the tenant
     * @throws CaException
     */
    public List<CsrInfo> listCsrs(int tenantID) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.LIST_CSR_FOR_ADMIN_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            resultSet = prepStmt.executeQuery();
            return getCsrListFromResultSet(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error listing CSRs", e);
        } catch (IOException e) {
            log.error("Error when decoding the CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Lists CSRs requested by a user
     * @param username The username of the user whose CSRs need to be listed
     * @param userStoreDomain The user store where the user is
     * @param tenantID The id of the tenant where the user belongs
     * @return List of CSRs from the user
     * @throws CaException
     */
    public List<CsrInfo> listCsrs(String username, String userStoreDomain, int tenantID)
            throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.LIST_CSR_FOR_NON_ADMIN_QUERY;

        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, username);
            prepStmt.setInt(2, tenantID);
            prepStmt.setString(3, userStoreDomain);
            resultSet = prepStmt.executeQuery();
            return getCsrListFromResultSet(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error listing CSRs", e);
        } catch (IOException e) {
            log.error("Error when decoding the CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Lists CSRs by status for a given tenant CA
     * @param tenantID The id of the tenant whose CSRs need to be listed
     * @param status The filter for the status
     * @return List of CSRs with the given status
     * @throws CaException
     */
    public List<CsrInfo> listCsrsByStatus(int tenantID, String status) throws CaException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SqlConstants.LIST_CSR_BY_STATUS_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            sql = "SELECT * FROM CA_CSR_STORE WHERE TENANT_ID = ? AND STATUS = ?";
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantID);
            prepStmt.setString(2, status);
            resultSet = prepStmt.executeQuery();
            return getCsrListFromResultSet(resultSet);
        } catch (IdentityException e) {
            String errorMsg = "Error when getting an Identity Persistence Store instance.";
            log.error(errorMsg, e);
            throw new CaException(errorMsg, e);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error listing CSRs", e);
        } catch (IOException e) {
            log.error("Error when decoding the CSR", e);
            throw new CaException("Error when decoding the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Gets the CSRs from a ResultSet
     * @param resultSet The resultSet from which the CSRs are retrieved
     * @return The List of CSR from the ResultSet
     * @throws SQLException
     * @throws IOException
     */
    private List<CsrInfo> getCsrListFromResultSet(ResultSet resultSet)
            throws SQLException, IOException {
        ArrayList<CsrInfo> csrList = new ArrayList<CsrInfo>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SqlConstants.SERIAL_NO_COLUMN);
            String status = resultSet.getString(SqlConstants.STATUS_COLUMN);
            String commonName = resultSet.getString(SqlConstants.CSR_COMMON_NAME_COLUMN);
            String organization = resultSet.getString(SqlConstants.CSR_ORGANIZATION_COLUMN);
            String country = null;
            String department = null;
            String city = null;
            String state = null;
            Blob csrBlob = resultSet.getBlob(SqlConstants.CSR_CONTENT_COLUMN);
            Date requestedDate = resultSet.getTimestamp(SqlConstants.REQUESTED_DATE_COLUMN);
            String username = resultSet.getString(SqlConstants.USERNAME_COLUMN);
            int tenantID = resultSet.getInt(SqlConstants.TENANT_ID_COLUMN);
            String userStoreDomain = resultSet.getString(SqlConstants.USERSTORE_DOMAIN_COLUMN);
            PKCS10CertificationRequest csr =
                    new PKCS10CertificationRequest(csrBlob.getBytes(1, (int) csrBlob.length()));
            RDN[] rdns = csr.getSubject().getRDNs();
            for (RDN rdn : rdns) {
                AttributeTypeAndValue typeAndValue = rdn.getFirst();
                if(BCStyle.C.equals(typeAndValue.getType())){
                    country = typeAndValue.getValue().toString();
                } else if (BCStyle.L.equals(typeAndValue.getType())){
                    city = typeAndValue.getValue().toString();
                } else if (BCStyle.OU.equals(typeAndValue.getType())){
                    department = typeAndValue.getValue().toString();
                } else if (BCStyle.ST.equals(typeAndValue.getType())){
                    state = typeAndValue.getValue().toString();
                }
            }

            CsrInfo csrInfo = new CsrInfo(serialNo, requestedDate, status, commonName, organization,
                    department, city, country, state, username, userStoreDomain, tenantID);
            csrList.add(csrInfo);
        }
        return csrList;
    }

    /**
     * Update the status of a CSR to the given status
     *
     * @param serialNo The serial number of the CSR
     * @param status   The new status of the csr
     * @see org.wso2.carbon.identity.certificateauthority.common.CsrStatus
     */
    public void updateStatus(Connection connection, String serialNo, CsrStatus status,
                             int tenantID) throws SQLException {
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.UPDATE_CSR_STATUS_QUERY;
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status.toString());
            prepStmt.setString(2, serialNo);
            prepStmt.setInt(3, tenantID);
            prepStmt.executeUpdate();
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }

    /**
     * Delete the CSR with given serial number
     *
     * @param serialNo serial number of the CSR which need to be deleted from DB
     */
    public void deleteCSR(Connection connection, String serialNo, int tenantId) throws CaException {
        PreparedStatement prepStmt = null;
        String sql = SqlConstants.DELETE_CSR_QUERY;
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setInt(2, tenantId);
        } catch (SQLException e) {
            log.error("Error when executing the SQL : " + sql, e);
            throw new CaException("Error when deleting the CSR", e);
        } finally {
            IdentityDatabaseUtil.closeStatement(prepStmt);
        }
    }
}
