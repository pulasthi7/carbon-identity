<%--
  ~ Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~    http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar"
           prefix="carbon" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.common.CsrStatus" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.stub.CsrInfo" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.CaUiConstants" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.client.CaAdminServiceClient" %>
<%@ page import="org.wso2.carbon.identity.certificateauthority.ui.util.ClientUtil" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.ui.util.CharacterEncoder" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.text.DateFormat" %>
<%

    CsrInfo[] csrsToDisplay = null;
    CaAdminServiceClient client = null;
    CsrInfo[] csrs = null;
    int numberOfPages = 0;
    int pageNumberInt = 0;
    DateFormat dateFormat = new SimpleDateFormat("MM/dd/yyyy");

    String statusTypeFilter =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.STATUS_PARAM));
    if (statusTypeFilter == null || "".equals(statusTypeFilter)) {
        statusTypeFilter = CaUiConstants.STATUS_ALL;
    }

    boolean isPaginated =
            Boolean.parseBoolean(request.getParameter(CaUiConstants.IS_PAGINATED_PARAM));
    String csrSearchString =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.SEARCH_STRING_PARAM));

    if (csrSearchString == null) {
        csrSearchString = CaUiConstants.SEARCH_STRING_ANY;
    } else {
        csrSearchString = csrSearchString.trim();
    }

    //todo:
    String paginationValue = CaUiConstants.IS_PAGINATED_PARAM + "=true&" +
            CaUiConstants.SEARCH_STRING_PARAM + "=" + csrSearchString;

    String pageNumber =
            CharacterEncoder.getSafeText(request.getParameter(CaUiConstants.PAGE_NUMBER_PARAM));

    if (pageNumber != null) {
        try {
            pageNumberInt = Integer.parseInt(pageNumber);
        } catch (NumberFormatException ignored) {
            // ignored since defaults to 0
        }
    }

    String serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    ConfigurationContext configContext =
            (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.
                    CONFIGURATION_CONTEXT);
    String cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);

    try {
        if (client == null) {
            client = new CaAdminServiceClient(cookie,
                    serverURL, configContext);
            session.setAttribute(CaUiConstants.CA_ADMIN_CLIENT, client);
        }


        csrs = (CsrInfo[]) session.getAttribute(CaUiConstants.CSRS_ATTRIB);
        if (csrs == null || !isPaginated) {

            if (CaUiConstants.SEARCH_STRING_ANY.equals(csrSearchString)) {
                if (statusTypeFilter.equals(CaUiConstants.STATUS_ALL)) {
                    csrs = client.getCSRFileList();
                } else {
                    csrs = client.getCSRsFromType(statusTypeFilter);
                }
            } else {
                csrs = client.getCSRsFromCommonName(csrSearchString);
            }
            session.setAttribute(CaUiConstants.CSRS_ATTRIB, csrs);
        }

        int itemsPerPageInt = CaUiConstants.DEFAULT_ITEMS_PER_PAGE;

        if (csrs != null) {
//            numberOfPages = (int) Math.ceil((double) csrs.length / itemsPerPageInt);
            numberOfPages = (csrs.length + itemsPerPageInt - 1) / itemsPerPageInt;
            csrsToDisplay = ClientUtil.doPagingForCsrs(pageNumberInt, itemsPerPageInt, csrs);
        }
    } catch (Exception e) {
%>

<script type="text/javascript">
    CARBON.showErrorDialog('<%=e.getMessage()%>', function () {
        location.href = "../admin/index.jsp";
    });
</script>
<%
    }
%>
<fmt:bundle basename="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources">
    <carbon:breadcrumb
            label="identity.ca.csr.list"
            resourceBundle="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources"
            topPage="true"
            request="<%=request%>"/>

    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="resources/js/main.js"></script>
    <!--Yahoo includes for dom event handling-->
    <script src="../yui/build/yahoo-dom-event/yahoo-dom-event.js" type="text/javascript"></script>
    <script src="../ca/js/create-basic-policy.js" type="text/javascript"></script>
    <link href="css/ca.css" rel="stylesheet" type="text/css" media="all"/>

    <script type="text/javascript">

        function getSelectedStatusType() {
            var comboBox = document.getElementById("statusTypeFilter");
            var statusTypeFilter = comboBox[comboBox.selectedIndex].value;
            location.href = 'csr-list-view.jsp?statusTypeFilter=' + statusTypeFilter;
        }
        function searchServices() {
            document.searchForm.submit();
        }
        function viewCSR(serialNo) {
            location.href = "view-csr.jsp?view=true&serialNo=" + serialNo;
        }

    </script>

    <div id="middle">
        <h2><fmt:message key="csr.list"/></h2>

        <div id="workArea">
            <form action="csr-list-view.jsp" name="searchForm" method="post">
                <table id="searchTable" name="searchTable" class="styledLeft" style="border:0;
                                                !important margin-top:10px;margin-bottom:10px;">
                    <tr>
                        <td>
                            <table style="border:0; !important">
                                <tbody>
                                <tr style="border:0; !important">
                                    <td style="border:0; !important">
                                        <nobr>
                                            <fmt:message key="csr.type"/>
                                            <select name="statusTypeFilter" id="statusTypeFilter"
                                                    onchange="getSelectedStatusType();">
                                                <%
                                                    if (CaUiConstants.STATUS_ALL
                                                            .equals(statusTypeFilter)) {
                                                %>
                                                <option value="ALL" selected="selected"><fmt:message
                                                        key="all"/></option>
                                                <%
                                                } else {
                                                %>
                                                <option value="ALL"><fmt:message
                                                        key="all"/></option>
                                                <%
                                                    }
                                                    for (CsrStatus status : CsrStatus.values()) {
                                                        if (statusTypeFilter
                                                                .equals(status.toString())) {
                                                %>
                                                <option value="<%= status.toString()%>"
                                                        selected="selected"><%= status.toString()%>
                                                </option>
                                                <%
                                                } else {
                                                %>
                                                <option value="<%= status.toString()%>">
                                                    <%= status.toString()%>
                                                </option>
                                                <%
                                                        }
                                                    }
                                                %>
                                            </select>
                                            &nbsp;&nbsp;&nbsp;
                                            <fmt:message key="search.csr"/>
                                            <input type="text" name="csrSearchString"
                                                   value="<%= csrSearchString != null?
                                                    csrSearchString
                                                    : CaUiConstants.SEARCH_STRING_ANY %>"/>
                                            &nbsp;
                                        </nobr>
                                    </td>
                                    <td style="border:0; !important">
                                        <a class="icon-link" href="#"
                                           style="background-image: url(images/search.gif);"
                                           onclick="searchServices(); return false;"
                                           alt="<fmt:message key="search"/>"></a>
                                    </td>
                                </tr>
                                </tbody>
                            </table>
                        </td>
                    </tr>
                </table>
            </form>

            <form action="" name="policyForm" method="post">
                <table style="width: 100%" id="dataTable" class="styledLeft">
                    <thead>
                    <tr>
                        <th><fmt:message key='user'/></th>
                        <th><fmt:message key='serial.No'/></th>
                        <th><fmt:message key='csr.detail.cn'/></th>
                        <th><fmt:message key='csr.detail.org'/></th>
                        <th><fmt:message key='requested.date'/></th>
                        <th><fmt:message key='status'/></th>
                        <th><fmt:message key='action'/></th>
                    </tr>
                    </thead>
                    <%
                        if (csrsToDisplay != null && csrsToDisplay.length > 0) {
                            for (CsrInfo csr : csrsToDisplay) {
                                if (csr != null && csr.getSerialNo().trim().length() > 0) {
                    %>
                    <tr>
                        <td width="20%"><%=csr.getUserName()%>
                        </td>
                        <td><%=csr.getSerialNo()%>
                        </td>
                        <td><%=csr.getCommonName()%>
                        </td>
                        <td><%=csr.getOrganization()%>
                        </td>
                        <td><%=dateFormat.format(csr.getRequestedDate())%>
                        </td>
                        <td><%=csr.getStatus()%>
                        </td>

                        <td>
                            <a onclick="viewCSR('<%=csr.getSerialNo()%>');return false;"
                               href="#" style="background-image: url(images/view.gif);"
                               class="icon-link">
                                <fmt:message key='view.csr'/></a>
                        </td>
                    </tr>
                    <%
                                }
                            }
                        }
                    %>

                </table>
                <carbon:paginator pageNumber="<%=pageNumberInt%>"
                                  numberOfPages="<%=numberOfPages%>"
                                  page="csr-list-view.jsp"
                                  pageNumberParameterName="pageNumber"
                                  parameters="<%=paginationValue%>"
                                  resourceBundle="org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources"
                                  prevKey="prev" nextKey="next"/>
            </form>

        </div>
    </div>
</fmt:bundle>