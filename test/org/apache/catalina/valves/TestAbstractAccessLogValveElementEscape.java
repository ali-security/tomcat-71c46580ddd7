/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.valves;

import java.io.CharArrayWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.connector.Request;
import org.apache.catalina.valves.AbstractAccessLogValve.AccessLogElement;
import org.apache.tomcat.util.json.JSONParser;

/**
 * Checks that the request line (%r), query string (%q) and request URI (%U)
 * access log elements escape the client supplied values so that they can not
 * be used to forge access log entries or to inject content into JSON access
 * logs.
 */
public class TestAbstractAccessLogValveElementEscape {

    private static final String PROTOCOL = "HTTP/1.1";

    private static final String MALICIOUS_URI = "/a\"b\nc\rd\te\\f\u0001g";
    private static final String MALICIOUS_URI_ESCAPED = "/a\\\"b\\nc\\rd\\te\\\\f\\u0001g";

    private static final String MALICIOUS_QUERY = "x=\"1\"\r\ny=\t\u007f\\";
    private static final String MALICIOUS_QUERY_ESCAPED = "x=\\\"1\\\"\\r\\ny=\\t\\u007f\\\\";


    @Test
    public void testRequestURIElementEscapes() {
        Request request = new TesterAccessLogRequest("GET", MALICIOUS_URI, null);
        Assert.assertEquals(MALICIOUS_URI_ESCAPED,
                render(new AbstractAccessLogValve.RequestURIElement(), request));
    }


    @Test
    public void testRequestURIElementPlain() {
        Request request = new TesterAccessLogRequest("GET", "/foo/bar", "a=b");
        Assert.assertEquals("/foo/bar", render(new AbstractAccessLogValve.RequestURIElement(), request));
    }


    @Test
    public void testRequestURIElementNullRequest() {
        Assert.assertEquals("-", render(new AbstractAccessLogValve.RequestURIElement(), null));
    }


    @Test
    public void testQueryElementEscapes() {
        Request request = new TesterAccessLogRequest("GET", "/", MALICIOUS_QUERY);
        Assert.assertEquals("?" + MALICIOUS_QUERY_ESCAPED,
                render(new AbstractAccessLogValve.QueryElement(), request));
    }


    @Test
    public void testQueryElementEmptyQuery() {
        // An empty query string must be logged as "?" and not "?-"
        Request request = new TesterAccessLogRequest("GET", "/", "");
        Assert.assertEquals("?", render(new AbstractAccessLogValve.QueryElement(), request));
    }


    @Test
    public void testQueryElementNullQuery() {
        Request request = new TesterAccessLogRequest("GET", "/", null);
        Assert.assertEquals("", render(new AbstractAccessLogValve.QueryElement(), request));
    }


    @Test
    public void testQueryElementNullRequest() {
        Assert.assertEquals("", render(new AbstractAccessLogValve.QueryElement(), null));
    }


    @Test
    public void testRequestElementEscapes() {
        Request request = new TesterAccessLogRequest("GET", MALICIOUS_URI, MALICIOUS_QUERY);
        Assert.assertEquals("GET " + MALICIOUS_URI_ESCAPED + "?" + MALICIOUS_QUERY_ESCAPED + " " + PROTOCOL,
                render(new AbstractAccessLogValve.RequestElement(), request));
    }


    @Test
    public void testRequestElementEmptyQuery() {
        // An empty query string must be logged as "?" and not "?-"
        Request request = new TesterAccessLogRequest("GET", "/path", "");
        Assert.assertEquals("GET /path? " + PROTOCOL, render(new AbstractAccessLogValve.RequestElement(), request));
    }


    @Test
    public void testRequestElementNullQuery() {
        Request request = new TesterAccessLogRequest("GET", "/path", null);
        Assert.assertEquals("GET /path " + PROTOCOL, render(new AbstractAccessLogValve.RequestElement(), request));
    }


    @Test
    public void testRequestElementNoMethod() {
        Request request = new TesterAccessLogRequest(null, "/path", "a=b");
        Assert.assertEquals("-", render(new AbstractAccessLogValve.RequestElement(), request));
    }


    @Test
    public void testRequestElementNullRequest() {
        Assert.assertEquals("-", render(new AbstractAccessLogValve.RequestElement(), null));
    }


    @Test
    public void testTextLogEntryForgery() {
        // CR/LF in the request must not allow an attacker to start a new,
        // forged, access log entry
        String forgedEntry = "127.0.0.1 - admin [01/Jan/2026:00:00:00 +0000] \"GET /admin HTTP/1.1\" 200 0";
        String forgedEntryEscaped = forgedEntry.replace("\"", "\\\"");
        Request request = new TesterAccessLogRequest("GET", "/x\r\n" + forgedEntry, "q=1\r\n" + forgedEntry);

        AccessLogValve valve = new AccessLogValve();
        valve.setPattern("\"%r\" %q %U");
        String line = render(valve.logElements, request);

        Assert.assertEquals(line, -1, line.indexOf('\n'));
        Assert.assertEquals(line, -1, line.indexOf('\r'));
        Assert.assertEquals("\"GET /x\\r\\n" + forgedEntryEscaped + "?q=1\\r\\n" + forgedEntryEscaped + " " + PROTOCOL +
                "\" ?q=1\\r\\n" + forgedEntryEscaped + " /x\\r\\n" + forgedEntryEscaped, line);
    }


    @Test
    public void testJsonInjection() throws Exception {
        Request request = new TesterAccessLogRequest("GET", "/a\",\"admin\":\"true",
                "b=1\",\"user\":\"root\\\r\n");

        JsonAccessLogValve valve = new JsonAccessLogValve();
        valve.setPattern("%r %q %U");
        String line = render(valve.logElements, request);

        JSONParser parser = new JSONParser(line);
        LinkedHashMap<String,Object> result = parser.parseObject();

        // No additional attributes may have been injected
        Assert.assertEquals(line, Arrays.asList("request", "query", "path"), new ArrayList<String>(result.keySet()));
        Assert.assertEquals("GET /a\\\",\\\"admin\\\":\\\"true?b=1\\\",\\\"user\\\":\\\"root\\\\\\r\\n " + PROTOCOL,
                result.get("request"));
        Assert.assertEquals("?b=1\\\",\\\"user\\\":\\\"root\\\\\\r\\n", result.get("query"));
        Assert.assertEquals("/a\\\",\\\"admin\\\":\\\"true", result.get("path"));
    }


    private static String render(AccessLogElement element, Request request) {
        return render(new AccessLogElement[] { element }, request);
    }


    private static String render(AccessLogElement[] elements, Request request) {
        CharArrayWriter buf = new CharArrayWriter();
        Date date = new Date();
        for (AccessLogElement element : elements) {
            element.addElement(buf, date, request, null, 0);
        }
        return buf.toString();
    }


    private static class TesterAccessLogRequest extends Request {

        private final String method;
        private final String requestURI;
        private final String queryString;

        TesterAccessLogRequest(String method, String requestURI, String queryString) {
            super(null);
            this.method = method;
            this.requestURI = requestURI;
            this.queryString = queryString;
        }

        @Override
        public String getMethod() {
            return method;
        }

        @Override
        public String getRequestURI() {
            return requestURI;
        }

        @Override
        public String getQueryString() {
            return queryString;
        }

        @Override
        public String getProtocol() {
            return PROTOCOL;
        }
    }
}
