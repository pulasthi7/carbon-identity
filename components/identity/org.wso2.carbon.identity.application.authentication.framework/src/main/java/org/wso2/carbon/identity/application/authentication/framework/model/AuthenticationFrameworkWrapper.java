/*
 *Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *WSO2 Inc. licenses this file to you under the Apache License,
 *Version 2.0 (the "License"); you may not use this file except
 *in compliance with the License.
 *You may obtain a copy of the License at
 *
 *http://www.apache.org/licenses/LICENSE-2.0
 *
 *Unless required by applicable law or agreed to in writing,
 *software distributed under the License is distributed on an
 *"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *KIND, either express or implied.  See the License for the
 *specific language governing permissions and limitations
 *under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

/**
 * This class is used as a wrapper to the incoming http request to authentication framework.
 * On the arrival of a request to authentication endpoint. The request will be wrapped from this
 * wrapper with all the information in the AuthenticationRequestCache
 */
public class AuthenticationFrameworkWrapper extends HttpServletRequestWrapper {

    private static Log log = LogFactory.getLog(AuthenticationFrameworkWrapper.class);

    //map which keeps parameters from authentication request cache
    private final Map<String, String[]> modifiableParameters;
    // This map will contain all the parameters including cache params and original req params
    private Map<String, String[]> allParameters = null;
    //this map keeps headers which are appended from cache
    private final Map<String, String> modifiableHeaders;

    /**
     * Create a new request wrapper that will merge additional parameters into
     * the request object without prematurely reading parameters from the
     * original request.
     *
     * @param request HttpServletRequest
     * @param additionalParams All Query Params
     * @param additionalHeaders All Headers
     */
    public AuthenticationFrameworkWrapper(final HttpServletRequest request,
                                          final Map<String, String[]> additionalParams,
                                          final Map<String, String> additionalHeaders) {
        super(request);
        modifiableParameters = new TreeMap<String, String[]>();
        modifiableParameters.putAll(additionalParams);
        modifiableHeaders = new TreeMap<String, String>();
        modifiableHeaders.putAll(additionalHeaders);
    }

    @Override
    public String getParameter(final String name) {
        String[] strings = getParameterMap().get(name);
        if (strings != null) {
            return strings[0];
        }
        return super.getParameter(name);
    }

    public String getHeader(String name) {
        String header = super.getHeader(name);
        return (header != null) ? header : modifiableHeaders.get(name).toString();
    }

    /**
     * Will return header names which were in original request and will append
     * all the header names which were in authentication request cache entry
     *
     */
    public Enumeration<String> getHeaderNames() {
        List<String> list = new ArrayList<String>();
        for (Enumeration<String> e = super.getHeaderNames(); e.hasMoreElements(); ) {
            list.add(e.nextElement().toString());
        }
        for (Iterator<String> i = modifiableHeaders.keySet().iterator(); i.hasNext(); ) {
            list.add(i.next());
        }
        return Collections.enumeration(list);
    }

    /**
     * Will return params which were in original request and will append
     * all the params which were in authentication request cache entry
     *
     */
    @Override
    public Map<String, String[]> getParameterMap() {
        if (allParameters == null) {
            allParameters = new TreeMap<String, String[]>();
            allParameters.putAll(super.getParameterMap());
            allParameters.putAll(modifiableParameters);
        }
        //Return an unmodifiable collection because we need to uphold the interface contract.
        return Collections.unmodifiableMap(allParameters);
    }

    @Override
    public Enumeration<String> getParameterNames() {
        return Collections.enumeration(getParameterMap().keySet());
    }

    @Override
    public String[] getParameterValues(final String name) {
        return getParameterMap().get(name);
    }

    /**
     * Will construct the new query parameter with the params
     *
     */
    @Override
    public String getQueryString() {

        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String[]> entry : getParameterMap().entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            try {
                sb.append(URLEncoder.encode(entry.getKey(), "UTF-8"))
                        .append('=')
                        .append(URLEncoder.encode(entry.getValue()[0], "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                log.error(e.getMessage(), e);
            }
        }
        return sb.toString();
    }

    public void addHeader(String key, String values) {
        modifiableHeaders.put(key, values);
    }

}
