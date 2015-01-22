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

package org.wso2.carbon.identity.certificateauthority.endpoint.cert;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CAServerException;
import org.wso2.carbon.identity.certificateauthority.endpoint.CAEndpointConstants;
import org.wso2.carbon.identity.certificateauthority.endpoint.util.CAEndpointUtils;
import org.wso2.carbon.identity.certificateauthority.services.CAConfigurationService;
import org.wso2.carbon.identity.certificateauthority.services.CertificateService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Class to handle certificate downloads
 */
@Path("/certificate")
public class CertificateRetriever {
    private static final Log log = LogFactory.getLog(CertificateRetriever.class);

    /**
     * Responds with the certificate with the given serial number
     *
     * @param serialNo The serial number of the certificate to be downloaded
     * @return The PEM encoded certificate as a "application/x-x509-user-cert"
     */
    @GET
    @Path("/{serialNo}.crt")
    @Produces("application/x-x509-user-cert")
    public Response getCertificate(@PathParam("serialNo") String serialNo) {
        try {
            CertificateService certificateService = CAEndpointUtils.getCertificateService();
            String certificate = certificateService.getPemEncodedCertificate(serialNo);
            if (StringUtils.isNotBlank(certificate)) {
                return Response.ok().type(CAEndpointConstants.X509_USER_CERT_MEDIA_TYPE).entity(certificate).build();
            }
        } catch (CAServerException e) {
            log.error("Server error getting certificate.", e);
            return Response.serverError().build();
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred retrieving certificate with serialNo no:" + serialNo, e);
            }
            return Response.serverError().build();
        }
        // certificate not available, so return a NOT_FOUND status
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Responds with the CA certificate for the given tenant domain
     *
     * @param tenantDomain The tenant domain of the CA whose certificate need to be downloaded
     * @return The PEM encoded certificate as a "application/x-x509-ca-cert"
     */
    @GET
    @Path("/_t/{tenantDomain}.crt")
    @Produces("application/x-x509-ca-cert")
    public Response getCaCertificate(@PathParam("tenantDomain") String tenantDomain) {
        try {
            CAConfigurationService configurationService = CAEndpointUtils.getCaConfigurationService();
            String certificate = configurationService.getPemEncodedCACert(tenantDomain);
            return Response.ok().type(CAEndpointConstants.X509_CA_CERT_MEDIA_TYPE).entity(certificate).build();
        } catch (CAServerException e) {
            log.error("Server error when getting CA certificate.", e);
            return Response.serverError().build();
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred while retrieving CA certificate for tenant domain:" + tenantDomain, e);
            }
            return Response.serverError().build();
        }
    }

    /**
     * This is the same as {@link #getCertificate(String)} except the response type. The response
     * type is "application/octet-string" for make it possible to download the certificate
     * without warnings or blocking at the browser
     *
     * @param serialNo The serial no of the certificate to be downloaded
     * @return The PEM encoded certificate as a "application/octet-string"
     */
    @GET
    @Path("/download/{serialNo}.crt")
    @Produces("application/octet-string")
    public Response downloadCertificate(@PathParam("serialNo") String serialNo) {
        try {
            CertificateService certificateService = CAEndpointUtils.getCertificateService();
            String certificate = certificateService.getPemEncodedCertificate(serialNo);
            if (StringUtils.isNotBlank(certificate)) {
                return Response.ok().type(MediaType.APPLICATION_OCTET_STREAM_TYPE).entity(certificate).build();
            }
        } catch (CAServerException e) {
            log.error("Server error when getting encoded certificate serialNo no:" + serialNo, e);
            return Response.serverError().build();
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred retrieving certificate with serialNo no:" + serialNo, e);
            }
            return Response.serverError().build();
        }
        // certificate not available, so return a NOT_FOUND status
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * This is the same as {@link #getCaCertificate(String)} except the response type. The response
     * type is "application/octet-string" for make it possible to download the certificate
     * without warnings or blocking at the browser
     *
     * @param tenantDomain The tenant domain of the CA whose certificate need to be downloaded
     * @return The PEM encoded certificate as a "application/octet-string"
     */
    @GET
    @Path("/download/_t/{tenantDomain}.crt")
    @Produces("application/octet-string")
    public Response downloadCaCertificate(@PathParam("tenantDomain") String tenantDomain) {
        try {
            CAConfigurationService configurationService = CAEndpointUtils.getCaConfigurationService();
            String certificate = configurationService.getPemEncodedCACert(tenantDomain);
            return Response.ok().type(MediaType.APPLICATION_OCTET_STREAM_TYPE).entity(certificate).build();
        } catch (CAServerException e) {
            log.error("Server error when getting CA certificate for tenant domain" + tenantDomain, e);
            return Response.serverError().build();
        } catch (CAException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error occurred retrieving CA certificate for tenant domain" + tenantDomain, e);
            }
            return Response.serverError().build();
        }
    }
}
