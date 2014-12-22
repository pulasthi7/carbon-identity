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

package org.wso2.carbon.identity.certificateauthority.endpoint.scep;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jscep.server.ScepServlet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import java.io.IOException;

@Path("/scep")
public class SCEPEndpoint {

    private static final Log log = LogFactory.getLog(SCEPEndpoint.class);

    /**
     * Responds to the SCEP requests
     *
     * @param request  The HttpServletRequest from context
     * @param response The HttpServletResponse from context
     * @param tenant   The tenant domain for whom the request is made
     */
    @Path("/_t/{tenantDomain}")
    public void service(@Context HttpServletRequest request, @Context HttpServletResponse
            response, @PathParam("tenantDomain") String tenant) {
        try {
            ScepServlet scepServlet = new SCEPServletImpl(tenant);
            scepServlet.service(request, response);

            //If the response is not committed jax-rs seems to modify the response headers to
            // return text/xml. So we are committing the response if it has not already
            if (!response.isCommitted()) {
                response.flushBuffer();
            }
        } catch (ServletException e) {
            log.error("Error serving the request", e);
        } catch (IOException e) {
            log.error("Error serving the request", e);
        }
    }

}
