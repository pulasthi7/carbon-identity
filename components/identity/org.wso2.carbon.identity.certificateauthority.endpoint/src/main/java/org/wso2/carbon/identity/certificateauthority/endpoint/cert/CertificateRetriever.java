/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.certificateauthority.endpoint.cert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.certificateauthority.config.CaConfiguration;
import org.wso2.carbon.identity.certificateauthority.CertificateManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Response;

@Path("/certificate")
public class CertificateRetriever {
    private static final Log log = LogFactory.getLog(CertificateRetriever.class);

    /**
     * Responds with the certificate with the given serial no
     * @param serial The serial no of the certificate to be downloaded
     * @return The PEM encoded certificate as a "application/x-x509-user-cert"
     */
    @GET
    @Path("/{serial}.crt")
    @Produces("application/x-x509-user-cert")
    public Response getCertificate(@PathParam("serial") String serial) {
        try {
            String certificate = CertificateManager.getInstance().getPemEncodedCertificate(serial);

            //the actual mime type for certificate is "application/x-x509-user-cert",
            // but that will cause browsers issuing warnings and not allowing the download.
            return Response.ok().type("application/x-x509-user-cert").entity(certificate).build();
        } catch (Exception e) {
            log.error("Error occurred retrieving certificate", e);
            return Response.serverError().build();
        }
    }

    /**
     * Responds with the CA certificate for the given tenant domain
     * @param tenantDomain The tenant domain of the CA whose certificate need to be downloaded
     * @return The PEM encoded certificate as a "application/x-x509-ca-cert"
     */
    @GET
    @Path("/_t/{tenantDomain}.crt")
    @Produces("application/x-x509-ca-cert")
    public Response getCaCertificate(@PathParam("tenantDomain") String tenantDomain) {
        try {
            String certificate = CaConfiguration.getInstance().getPemEncodedCaCert
                    (tenantDomain);
            return Response.ok().type("application/x-x509-ca-cert").entity(certificate).build();
        } catch (Exception e) {
            log.error("Error occurred retrieving certificate", e);
            return Response.serverError().build();
        }
    }

    /**
     * This is the same as {@link #getCertificate(String)} except the response type. The response
     * type is "application/octet-string" for make it possible to download the certificate
     * without warnings or blocking at the browser
     * @param serial The serial no of the certificate to be downloaded
     * @return The PEM encoded certificate as a "application/octet-string"
     */
    @GET
    @Path("/download/{serial}.crt")
    @Produces("application/octet-string")
    public Response downloadCertificate(@PathParam("serial") String serial) {
        try {
            String certificate = CertificateManager.getInstance().getPemEncodedCertificate(serial);
            return Response.ok().type("application/octet-string").entity(certificate).build();
        } catch (Exception e) {
            log.error("Error occurred retrieving certificate", e);
            return Response.serverError().build();
        }
    }

    /**
     * This is the same as {@link #getCaCertificate(String)} except the response type. The response
     * type is "application/octet-string" for make it possible to download the certificate
     * without warnings or blocking at the browser
     * @param tenantDomain The tenant domain of the CA whose certificate need to be downloaded
     * @return The PEM encoded certificate as a "application/octet-string"
     */
    @GET
    @Path("/download/_t/{tenantDomain}.crt")
    @Produces("application/octet-string")
    public Response downloadCaCertificate(@PathParam("tenantDomain") String tenantDomain) {
        try {
            String certificate = CaConfiguration.getInstance().getPemEncodedCaCert
                    (tenantDomain);
            return Response.ok().type("application/octet-string").entity(certificate).build();
        } catch (Exception e) {
            log.error("Error occurred retrieving certificate", e);
            return Response.serverError().build();
        }
    }
}
