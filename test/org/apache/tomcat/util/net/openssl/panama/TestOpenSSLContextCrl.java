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
package org.apache.tomcat.util.net.openssl.panama;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.junit.Assert;
import org.junit.Test;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.startup.TomcatBaseTest;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.SSLHostConfigCertificate.Type;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks that the OpenSSL FFM TLS implementation, in line with the other TLS implementations, fails to initialise the
 * TLS configuration (and hence the connector) if the configured CRL(s) cannot be loaded rather than logging the error
 * and continuing.
 * <p>
 * The test sources are compiled for Java 8 so the FFM implementation is only referenced by name.
 */
public class TestOpenSSLContextCrl extends TomcatBaseTest {

    private static final String SSL_IMPLEMENTATION_NAME =
            "org.apache.tomcat.util.net.openssl.panama.OpenSSLImplementation";


    @Test
    public void testLoadableCrlFile() throws Exception {
        // Control. OpenSSL is able to load the file so the connector must start.
        Connector connector = configure(new File(TesterSupport.CA_CERT_PEM).getAbsolutePath(), null);

        getTomcatInstance().start();

        Assert.assertEquals(LifecycleState.STARTED, connector.getState());
        Assert.assertTrue(connector.getLocalPort() > 0);
    }


    @Test
    public void testInvalidCrlFile() throws Exception {
        // The file exists but does not contain anything OpenSSL can load
        File crlFile = new File(getTemporaryDirectory(), "invalid-crl.pem");
        Files.write(crlFile.toPath(), "This is not a CRL\n".getBytes(StandardCharsets.US_ASCII));
        addDeleteOnTearDown(crlFile);

        doTestStartFails(crlFile.getAbsolutePath(), null);
    }


    @Test
    public void testInvalidCrlPath() throws Exception {
        // OpenSSL rejects an empty directory name
        doTestStartFails(null, "");
    }


    private void doTestStartFails(String crlFile, String crlPath) throws Exception {
        Connector connector = configure(crlFile, crlPath);

        Throwable cause = null;
        try {
            getTomcatInstance().start();
        } catch (LifecycleException e) {
            cause = e;
        }
        Assert.assertNotNull("The connector started even though the CRL could not be loaded", cause);
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        Assert.assertTrue(cause.toString(), cause instanceof IllegalArgumentException);
        Assert.assertEquals(LifecycleState.FAILED, connector.getState());
    }


    private Connector configure(String crlFile, String crlPath) throws Exception {
        Tomcat tomcat = getTomcatInstance();
        Connector connector = tomcat.getConnector();

        connector.setPort(0);
        connector.setScheme("https");
        connector.setSecure(true);
        Assert.assertTrue(connector.setProperty("SSLEnabled", "true"));

        SSLHostConfig sslHostConfig = new SSLHostConfig();
        SSLHostConfigCertificate certificate = new SSLHostConfigCertificate(sslHostConfig, Type.RSA);
        certificate.setCertificateFile(new File(TesterSupport.LOCALHOST_RSA_CERT_PEM).getAbsolutePath());
        certificate.setCertificateKeyFile(new File(TesterSupport.LOCALHOST_RSA_KEY_PEM).getAbsolutePath());
        sslHostConfig.addCertificate(certificate);
        if (crlFile != null) {
            sslHostConfig.setCertificateRevocationListFile(crlFile);
        }
        if (crlPath != null) {
            sslHostConfig.setCertificateRevocationListPath(crlPath);
        }
        connector.addSslHostConfig(sslHostConfig);

        // Skips the test if the OpenSSL FFM implementation is not available
        TesterSupport.configureSSLImplementation(tomcat, SSL_IMPLEMENTATION_NAME, true);

        return connector;
    }
}
