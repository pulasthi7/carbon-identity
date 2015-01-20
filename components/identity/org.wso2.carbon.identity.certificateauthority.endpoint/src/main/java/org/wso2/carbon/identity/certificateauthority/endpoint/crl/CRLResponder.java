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

package org.wso2.carbon.identity.certificateauthority.endpoint.crl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.endpoint.CAEndpointConstants;
import org.wso2.carbon.identity.certificateauthority.endpoint.util.CAEndpointUtils;
import org.wso2.carbon.identity.certificateauthority.services.CRLService;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

/**
 * Class to handle CRL queries
 */
@Path("/crl")
public class CRLResponder {

    private static final Log log = LogFactory.getLog(CRLResponder.class);

    /**
     * Responds with the CRL for the given tenant domain
     *
     * @param command      Whether the request is for CRL or Delta CRL
     * @param tenantDomain The CA's tenant domain
     * @return The CRL response with the revoked certificates of the tenant CA
     */
    @GET
    @Path("/_t/{tenantDomain}")
    @Produces("application/pkix-crl")
    public Response getCRL(@QueryParam(CAEndpointConstants.CRL_COMMAND) String command,
                           @PathParam("tenantDomain") String tenantDomain) {
        CRLService crlService = CAEndpointUtils.getCRLService();
        if (CAEndpointConstants.REQUEST_TYPE_CRL.equals(command)) {
            try {
                byte[] crl = crlService.getLatestCrl(tenantDomain);
                return Response.ok().type(CAEndpointConstants.PKIX_CRL_MEDIA_TYPE).entity(crl).build();
            } catch (CAException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while retrieving CRL for the tenant :" + tenantDomain, e);
                }
            }
        } else if (CAEndpointConstants.REQUEST_TYPE_DELTA_CRL.equals(command)) {
            try {
                byte[] deltaCRL = crlService.getLatestDeltaCrl(tenantDomain);
                return Response.ok().type(CAEndpointConstants.PKIX_CRL_MEDIA_TYPE).entity(deltaCRL).build();
            } catch (CAException e) {
                if (log.isDebugEnabled()) {
                    log.debug("error while while retrieving delta CRL for the tenant :" + tenantDomain, e);
                }
            }
        }
        //Any other parameter for command is not valid, so every other cases are considered as bad requests and
        // responded accordingly
        return Response.status(Response.Status.BAD_REQUEST).build();
    }
}
