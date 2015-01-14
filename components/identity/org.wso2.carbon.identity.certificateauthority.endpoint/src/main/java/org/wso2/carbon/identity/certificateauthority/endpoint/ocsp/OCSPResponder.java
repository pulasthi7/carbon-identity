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

package org.wso2.carbon.identity.certificateauthority.endpoint.ocsp;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.endpoint.CAEndpointConstants;
import org.wso2.carbon.identity.certificateauthority.services.OCSPService;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 * Handles OCSP requests
 */
@Path("/ocsp")
public class OCSPResponder {

    private static Log log = LogFactory.getLog(OCSPResponder.class);

    /**
     * Responds for the OCSP requests
     *
     * @param request The HttpServletRequest from the context
     * @param tenant  The tenant domain for whom the request is made
     * @return The OCSP response
     */
    @POST
    @Path("/_t/{tenantDomain}")
    @Consumes("application/ocsp-request")
    @Produces("application/ocsp-response")
    public Response handleOCSPRequest(@Context HttpServletRequest request, @PathParam("tenantDomain") String tenant) {
        try {
            OCSPReq ocspReq = new OCSPReq(IOUtils.toByteArray(request.getInputStream()));
            OCSPService ocspService = new OCSPService();
            OCSPResp ocspResp = ocspService.handleOCSPRequest(ocspReq, tenant);
            return Response.ok().type(CAEndpointConstants.OCSP_RESPONSE_MEDIA_TYPE).entity(ocspResp.getEncoded())
                    .build();
        } catch (CAException e) {
            //This can be thrown due to multiple reasons, the reason and context can be found at exception's message
            if (log.isDebugEnabled()) {
                log.debug("Error when handling the OCSP request for tenant:" + tenant, e);
            }
            return Response.serverError().build();
        } catch (IOException e) {
            //The request is malformed, and the OCSPReq object cannot be built with that
            if (log.isDebugEnabled()) {
                log.debug("Error with the OCSP request, invalid request body", e);
            }
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }
}
