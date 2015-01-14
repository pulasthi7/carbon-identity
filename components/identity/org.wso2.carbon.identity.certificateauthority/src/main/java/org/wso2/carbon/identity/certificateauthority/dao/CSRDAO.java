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
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.common.CSRStatus;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.identity.certificateauthority.model.CSR;
import org.wso2.carbon.identity.certificateauthority.utils.CAObjectUtils;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Performs DAO operations related to the CSRs
 */
public class CSRDAO {

    private static final Log log = LogFactory.getLog(CSRDAO.class);

    /**
     * Adds a new CSR to the DB
     *
     * @param csrContent      The CSR as an encoded string
     * @param userName        The user who requested the CSR to sign
     * @param tenantDomain    The domain of the tenant where the user belongs
     * @param userStoreDomain The user store where the user is
     * @return The serial no of the newly added CSR, which can be used in later queries
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public String addCSR(String csrContent, String userName, String tenantDomain, String userStoreDomain)
            throws CAException {
        PKCS10CertificationRequest request = null;
        try {
            request = CAObjectUtils.toPkcs10CertificationRequest(csrContent);
            return addCSR(request, userName, tenantDomain, userStoreDomain);
        } catch (IOException e) {
            throw new CAException("Error when decoding encoded CSR, CSR:\n" + csrContent + "\n", e);
        }
    }

    /**
     * Adds a new CSR to the DB
     *
     * @param request         PKCS10CertificationRequest form of the request
     * @param userName        The user who requested the CSR to sign
     * @param tenantDomain    The domain of the tenant where the user belongs
     * @param userStoreDomain The user store where the user is
     * @return
     */
    public String addCSR(PKCS10CertificationRequest request, String userName, String tenantDomain,
                         String userStoreDomain) throws CAException {
        String csrSerialNo = new BigInteger(32, new SecureRandom()).toString();
        Connection connection = null;
        Date requestDate = new Date();
        String sql = SQLConstants.ADD_CSR_QUERY;
        PreparedStatement prepStmt = null;

        //Some RDNs are stored separately for indexing purposes
        RDN[] orgRdNs = request.getSubject().getRDNs(BCStyle.O);
        //Organization is not a mandatory field, it may be null, therefore initializing it to
        // empty string

        String organization = null;
        if (orgRdNs.length > 0) {
            organization = orgRdNs[0].getFirst().getValue().toString();
        }
        RDN[] cnRdNs = request.getSubject().getRDNs(BCStyle.CN);
        String commonName;
        if (cnRdNs.length > 0) {
            //Although not used in practice, cnRdNs can have multiple RDNs, if so we'll consider only the first one
            commonName = cnRdNs[0].getFirst().getValue().toString();
        } else {
            throw new IllegalArgumentException("The CN is mandatory, but it was not found in the CSR");
        }
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setBlob(1, new ByteArrayInputStream(request.getEncoded()));
            prepStmt.setString(2, CSRStatus.PENDING.toString());
            prepStmt.setString(3, userName);
            prepStmt.setTimestamp(4, new Timestamp(requestDate.getTime()));
            prepStmt.setString(5, csrSerialNo);
            prepStmt.setInt(6, tenantId);
            prepStmt.setString(7, commonName);
            prepStmt.setString(8, organization);
            prepStmt.setString(9, userStoreDomain);
            prepStmt.executeUpdate();
            connection.commit();
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error when reading CSR to byte stream", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
        return csrSerialNo;
    }

    /**
     * Gets CSR model from database for given serial number
     *
     * @param serialNo serial number of the CSR
     * @return Details about the CSR
     */
    public CSR getCSR(String serialNo, String userStoreDomain, String userName, String tenantDomain)
            throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.GET_CSR_FOR_USER_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, serialNo);
            prepStmt.setString(2, userName);
            prepStmt.setInt(3, tenantId);
            prepStmt.setString(4, userStoreDomain);
            resultSet = prepStmt.executeQuery();
            List<CSR> csrInfoList = getCSRListFromResultSet(resultSet, tenantDomain);
            if (!csrInfoList.isEmpty()) {
                return csrInfoList.get(0);
            }
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error decoding CSR", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found, " +
                    "or not accessible by " + userStoreDomain + "\\" + userName + " of tenant " + tenantDomain);
        }
        return null;
    }

    /**
     * Mark the CSR as a rejected one
     *
     * @param serialNo     The serial no of the CSR to be marked as rejected
     * @param tenantDomain The domain of the tenant CA
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void rejectCSR(String serialNo, String tenantDomain) throws CAException {
        Connection connection = null;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            updateStatus(connection, serialNo, CSRStatus.REJECTED, tenantId);
            connection.commit();
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            try {
                connection.rollback();
            } catch (SQLException e1) {
                log.error("Error when rolling back rejection of CSR", e1);
            }
            throw new CAException("Error rejecting certificate", e);
        } finally {
            IdentityDatabaseUtil.closeConnection(connection);
        }
    }

    /**
     * Retrieves the CSRs stored in the DB
     *
     * @param serialNo The serial no of the CSR to be retrieved
     * @return The CSR as a PKCS10CertificationRequest
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public PKCS10CertificationRequest getPKCS10CertificationRequest(String serialNo)
            throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.GET_CSR_CONTENT_QUERY;
        try {
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);

            prepStmt.setString(1, serialNo);
            resultSet = prepStmt.executeQuery();
            if (resultSet.next()) {
                Blob csrBlob = resultSet.getBlob(SQLConstants.CSR_CONTENT_COLUMN);
                return new PKCS10CertificationRequest(csrBlob.getBytes(1, (int) csrBlob.length()));
            }
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error decoding CSR", e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found");
        }
        return null;
    }

    /**
     * Retrieve the CSR details for the given serial no
     *
     * @param serialNo     The serial no of the CSR to be retrieved
     * @param tenantDomain The id of the tenant CA
     * @return The CSR details
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public CSR getCSR(String serialNo, String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.GET_CSR_FOR_ADMIN_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setInt(2, tenantId);
            resultSet = prepStmt.executeQuery();
            List<CSR> csrInfoList = getCSRListFromResultSet(resultSet, tenantDomain);
            if (!csrInfoList.isEmpty()) {
                return csrInfoList.get(0);
            }
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error decoding CSR", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
        if (log.isDebugEnabled()) {
            log.debug("CSR with serial no " + serialNo + " not found, " +
                    "or not accessible by tenant " + tenantDomain);
        }
        throw new CAException("CSR for given serial not found");
    }

    /**
     * Lists CSRs that are for the specified tenant
     *
     * @param tenantDomain The domain of the tenant whose CSRs need to be listed
     * @return The list of CSRs for the tenant
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRs(String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.LIST_CSR_FOR_ADMIN_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            resultSet = prepStmt.executeQuery();
            return getCSRListFromResultSet(resultSet, tenantDomain);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error when decoding the CSR", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Lists CSRs requested by a user
     *
     * @param username        The username of the user whose CSRs need to be listed
     * @param userStoreDomain The user store where the user is
     * @param tenantDomain    The domain of the tenant where the user belongs
     * @return List of CSRs from the user
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRs(String username, String userStoreDomain, String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.LIST_CSR_FOR_NON_ADMIN_QUERY;

        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, username);
            prepStmt.setInt(2, tenantId);
            prepStmt.setString(3, userStoreDomain);
            resultSet = prepStmt.executeQuery();
            return getCSRListFromResultSet(resultSet, tenantDomain);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error when decoding the CSR", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Lists CSRs by status for a given tenant CA
     *
     * @param tenantDomain The domain of the tenant whose CSRs need to be listed
     * @param status       The filter for the status
     * @return List of CSRs with the given status
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public List<CSR> listCSRsByStatus(String tenantDomain, String status) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        ResultSet resultSet = null;
        String sql = SQLConstants.LIST_CSR_BY_STATUS_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setInt(1, tenantId);
            prepStmt.setString(2, status);
            resultSet = prepStmt.executeQuery();
            return getCSRListFromResultSet(resultSet, tenantDomain);
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (IOException e) {
            throw new CAException("Error when decoding the CSR", e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, resultSet, prepStmt);
        }
    }

    /**
     * Gets the CSRs from a ResultSet
     *
     * @param resultSet The resultSet from which the CSRs are retrieved
     * @return The List of CSR from the ResultSet
     * @throws SQLException
     * @throws IOException
     */
    private List<CSR> getCSRListFromResultSet(ResultSet resultSet, String tenantDomain)
            throws SQLException, IOException {
        ArrayList<CSR> csrList = new ArrayList<CSR>();
        while (resultSet.next()) {
            String serialNo = resultSet.getString(SQLConstants.SERIAL_NO_COLUMN);
            String status = resultSet.getString(SQLConstants.STATUS_COLUMN);
            String commonName = resultSet.getString(SQLConstants.CSR_COMMON_NAME_COLUMN);
            String organization = resultSet.getString(SQLConstants.CSR_ORGANIZATION_COLUMN);
            String country = null;
            String department = null;
            String city = null;
            String state = null;
            Blob csrBlob = resultSet.getBlob(SQLConstants.CSR_CONTENT_COLUMN);
            Date requestedDate = resultSet.getTimestamp(SQLConstants.REQUESTED_DATE_COLUMN);
            String username = resultSet.getString(SQLConstants.USERNAME_COLUMN);
            String userStoreDomain = resultSet.getString(SQLConstants.USERSTORE_DOMAIN_COLUMN);
            PKCS10CertificationRequest certificationRequest =
                    new PKCS10CertificationRequest(csrBlob.getBytes(1, (int) csrBlob.length()));
            RDN[] rdns = certificationRequest.getSubject().getRDNs();
            for (RDN rdn : rdns) {
                AttributeTypeAndValue typeAndValue = rdn.getFirst();
                if (BCStyle.C.equals(typeAndValue.getType())) {
                    country = typeAndValue.getValue().toString();
                } else if (BCStyle.L.equals(typeAndValue.getType())) {
                    city = typeAndValue.getValue().toString();
                } else if (BCStyle.OU.equals(typeAndValue.getType())) {
                    department = typeAndValue.getValue().toString();
                } else if (BCStyle.ST.equals(typeAndValue.getType())) {
                    state = typeAndValue.getValue().toString();
                }
            }

            CSR csr = new CSR(serialNo, requestedDate, status, commonName, organization,
                    department, city, country, state, username, userStoreDomain, tenantDomain);
            csrList.add(csr);
        }
        return csrList;
    }

    /**
     * Update the status of a CSR to the given status
     *
     * @param serialNo The serial number of the CSR
     * @param status   The new status of the csr
     * @see org.wso2.carbon.identity.certificateauthority.common.CSRStatus
     */
    public void updateStatus(Connection connection, String serialNo, CSRStatus status,
                             int tenantId) throws SQLException {
        PreparedStatement prepStmt = null;
        String sql = SQLConstants.UPDATE_CSR_STATUS_QUERY;
        try {
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, status.toString());
            prepStmt.setString(2, serialNo);
            prepStmt.setInt(3, tenantId);
            prepStmt.executeUpdate();
        } finally {
            //Keeps the database connection unclosed, because the callee of this method is responsible for closing it.
            IdentityDatabaseUtil.closeAllConnections(null, null, prepStmt);
        }
    }

    /**
     * Delete the CSR with given serial number
     *
     * @param serialNo     The serial no of the CSR to be deleted
     * @param tenantDomain The domain of the tenant CA
     * @throws CAException
     */
    public void deleteCSR(String serialNo, String tenantDomain) throws CAException {
        Connection connection = null;
        PreparedStatement prepStmt = null;
        String sql = SQLConstants.DELETE_CSR_QUERY;
        try {
            int tenantId = CAServiceComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
            connection = IdentityDatabaseUtil.getDBConnection();
            prepStmt = connection.prepareStatement(sql);
            prepStmt.setString(1, serialNo);
            prepStmt.setInt(2, tenantId);
            prepStmt.executeUpdate();
        } catch (IdentityException e) {
            throw new CAException("Error when getting an Identity Persistence Store instance.", e);
        } catch (SQLException e) {
            throw new CAException("Error when executing the SQL : " + sql, e);
        } catch (UserStoreException e) {
            throw new CAException("Invalid tenant domain :" + tenantDomain, e);
        } finally {
            IdentityDatabaseUtil.closeAllConnections(connection, null, prepStmt);
        }
    }
}
