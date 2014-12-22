/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.CRLManager;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;

@Path("/crl")
public class CRLResponder {
    private static final Log log = LogFactory.getLog(CRLResponder.class);

    /**
     * Responds with the CRL for the given tenant domain
     *
     * @param command
     * @param tenant
     * @return
     */
    @GET
    @Path("/_t/{tenantDomain}")
    @Produces("application/pkix-crl")
    public Response getCRL(@QueryParam(CAConstants.CRL_COMMAND) String command,
                           @PathParam("tenantDomain") String tenant) {
        if (CAConstants.REQUEST_TYPE_CRL.equals(command)) {
            CRLManager crlManager = CRLManager.getInstance();
            try {
                byte[] crlBytes = crlManager.getLatestCrl(tenant);
                return Response.ok().type("application/pkix-crl").entity(crlBytes).build();
            } catch (Exception e) {
                log.error("error while trying to get CRL for the tenant :" + tenant, e);
            }
        } else if (CAConstants.REQUEST_TYPE_DELTA_CRL.equals(command)) {
            CRLManager crlManager = CRLManager.getInstance();
            try {
                return Response.ok().type("application/pkix-crl").entity(crlManager
                        .getLatestDeltaCrl(tenant)).build();
            } catch (Exception e) {
                log.error("error while trying to get CRL for the tenant :" + tenant, e);
            }
        }
        return Response.status(Response.Status.BAD_REQUEST).build();
    }


}
