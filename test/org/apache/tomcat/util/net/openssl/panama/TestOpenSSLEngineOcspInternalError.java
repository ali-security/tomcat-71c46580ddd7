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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Array;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Locale;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import org.apache.catalina.core.OpenSSLLifecycleListener;
import org.apache.tomcat.util.compat.JreCompat;
import org.apache.tomcat.util.net.TesterSupport;

/**
 * Checks that the OpenSSL FFM OCSP client reports a failure to obtain an OCSP response (internal error at the
 * responder, unreachable responder, oversized response) as {@code X509_V_ERR_UNABLE_TO_GET_CRL} and returns
 * {@code V_OCSP_CERTSTATUS_UNKNOWN}, aligning with Tomcat Native, while an invalid response body is still reported as
 * {@code X509_V_ERR_APPLICATION_VERIFICATION}.
 * <p>
 * The test sources are compiled for Java 8 so all FFM access is performed via reflection.
 */
public class TestOpenSSLEngineOcspInternalError {

    private static final int OCSP_TIMEOUT = 5000;
    private static final int OCSP_RESPONSE_OVERSIZED = 200 * 1024;

    private static Class<?> memorySegmentClass;
    private static Class<?> arenaClass;
    private static Class<?> opensslClass;
    private static Object nullSegment;
    private static Object arena;
    private static Object x509;
    private static Object issuer;
    private static Object x509ctx;
    private static Object engineState;
    private static MethodHandle x509StoreCtxFree;
    private static Method processOCSPRequest;
    private static Method x509StoreCtxGetError;
    private static Method x509StoreCtxSetError;
    private static Method x509Free;

    private static int unableToGetCrl;
    private static int applicationVerification;
    private static int certStatusUnknown;


    @BeforeClass
    public static void setup() throws Exception {
        Assume.assumeTrue("FFM requires Java 22+", JreCompat.isJre22Available());
        new OpenSSLLifecycleListener();
        Assume.assumeTrue("OpenSSL FFM is not available", OpenSSLLifecycleListener.isAvailable());
        Assume.assumeFalse("BoringSSL does not support OCSP",
                Class.forName("org.apache.tomcat.util.openssl.openssl_h_Compatibility").getField("BORINGSSL")
                        .getBoolean(null));

        memorySegmentClass = Class.forName("java.lang.foreign.MemorySegment");
        arenaClass = Class.forName("java.lang.foreign.Arena");
        opensslClass = Class.forName("org.apache.tomcat.util.openssl.openssl_h");
        Class<?> memoryLayoutClass = Class.forName("java.lang.foreign.MemoryLayout");
        Class<?> functionDescriptorClass = Class.forName("java.lang.foreign.FunctionDescriptor");
        Class<?> linkerClass = Class.forName("java.lang.foreign.Linker");
        Class<?> linkerOptionClass = Class.forName("java.lang.foreign.Linker$Option");
        Object addressLayout = Class.forName("java.lang.foreign.ValueLayout").getField("ADDRESS").get(null);

        nullSegment = memorySegmentClass.getField("NULL").get(null);
        arena = arenaClass.getMethod("ofShared").invoke(null);

        unableToGetCrl = ((Integer) opensslClass.getMethod("X509_V_ERR_UNABLE_TO_GET_CRL").invoke(null)).intValue();
        applicationVerification =
                ((Integer) opensslClass.getMethod("X509_V_ERR_APPLICATION_VERIFICATION").invoke(null)).intValue();
        certStatusUnknown = ((Integer) opensslClass.getMethod("V_OCSP_CERTSTATUS_UNKNOWN").invoke(null)).intValue();
        Assert.assertNotEquals(unableToGetCrl, applicationVerification);

        x509StoreCtxGetError = opensslClass.getMethod("X509_STORE_CTX_get_error", memorySegmentClass);
        x509StoreCtxSetError = opensslClass.getMethod("X509_STORE_CTX_set_error", memorySegmentClass, int.class);
        x509Free = opensslClass.getMethod("X509_free", memorySegmentClass);

        // The certificates only need to be valid X509 structures for OCSP_cert_to_id
        x509 = loadCertificate(TesterSupport.LOCALHOST_RSA_CERT_PEM, addressLayout);
        issuer = loadCertificate(TesterSupport.CA_CERT_PEM, addressLayout);

        // X509_STORE_CTX_new is not part of the generated bindings
        Method findOrThrow = opensslClass.getDeclaredMethod("findOrThrow", String.class);
        findOrThrow.setAccessible(true);
        Object linker = linkerClass.getMethod("nativeLinker").invoke(null);
        Method downcallHandle = linkerClass.getMethod("downcallHandle", memorySegmentClass, functionDescriptorClass,
                Array.newInstance(linkerOptionClass, 0).getClass());
        Object memoryLayoutArray = Array.newInstance(memoryLayoutClass, 0);
        Object newDescriptor = functionDescriptorClass
                .getMethod("of", memoryLayoutClass, memoryLayoutArray.getClass())
                .invoke(null, addressLayout, memoryLayoutArray);
        Object freeArgs = Array.newInstance(memoryLayoutClass, 1);
        Array.set(freeArgs, 0, addressLayout);
        Object freeDescriptor =
                functionDescriptorClass.getMethod("ofVoid", memoryLayoutArray.getClass()).invoke(null, freeArgs);
        MethodHandle x509StoreCtxNew = (MethodHandle) downcallHandle.invoke(linker,
                findOrThrow.invoke(null, "X509_STORE_CTX_new"), newDescriptor,
                Array.newInstance(linkerOptionClass, 0));
        x509StoreCtxFree = (MethodHandle) downcallHandle.invoke(linker,
                findOrThrow.invoke(null, "X509_STORE_CTX_free"), freeDescriptor,
                Array.newInstance(linkerOptionClass, 0));
        try {
            x509ctx = x509StoreCtxNew.invokeWithArguments();
        } catch (Throwable t) {
            throw new Exception(t);
        }
        Assert.assertFalse("X509_STORE_CTX_new failed", nullSegment.equals(x509ctx));

        Class<?> engineStateClass =
                Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine$EngineState");
        Constructor<?> engineStateConstructor = engineStateClass.getDeclaredConstructor(memorySegmentClass,
                memorySegmentClass, int.class, boolean.class, int.class, int.class);
        engineStateConstructor.setAccessible(true);
        // No SSL / BIO are required for the OCSP request processing
        engineState = engineStateConstructor.newInstance(nullSegment, nullSegment, Integer.valueOf(10),
                Boolean.FALSE, Integer.valueOf(OCSP_TIMEOUT), Integer.valueOf(0));

        processOCSPRequest = Class.forName("org.apache.tomcat.util.net.openssl.panama.OpenSSLEngine")
                .getDeclaredMethod("processOCSPRequest", engineStateClass, URL.class, memorySegmentClass,
                        memorySegmentClass, memorySegmentClass, arenaClass);
        processOCSPRequest.setAccessible(true);
    }


    @AfterClass
    public static void cleanup() throws Exception {
        if (x509ctx != null && x509StoreCtxFree != null) {
            try {
                x509StoreCtxFree.invokeWithArguments(x509ctx);
            } catch (Throwable t) {
                throw new Exception(t);
            }
            x509ctx = null;
        }
        if (x509 != null) {
            x509Free.invoke(null, x509);
            x509 = null;
        }
        if (issuer != null) {
            x509Free.invoke(null, issuer);
            issuer = null;
        }
        if (engineState != null) {
            // Remove from the engine state map
            ((Runnable) engineState).run();
            engineState = null;
        }
        if (arena != null) {
            arenaClass.getMethod("close").invoke(arena);
            arena = null;
        }
    }


    @Before
    public void resetError() throws Exception {
        x509StoreCtxSetError.invoke(null, x509ctx, Integer.valueOf(0));
    }


    @Test
    public void testResponderInternalError() throws Exception {
        byte[] response = ("HTTP/1.1 500 Internal Server Error\r\n" + "Content-Length: 0\r\n" +
                "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1);
        try (ServerSocket serverSocket = startResponder(response, false)) {
            doTest(serverSocket.getLocalPort(), unableToGetCrl);
        }
    }


    @Test
    public void testResponderUnavailable() throws Exception {
        int port;
        try (ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = serverSocket.getLocalPort();
        }
        // Nothing listening any more - connection refused
        doTest(port, unableToGetCrl);
    }


    @Test
    public void testResponderTimeout() throws Exception {
        try (ServerSocket serverSocket = startResponder(null, true)) {
            doTest(serverSocket.getLocalPort(), unableToGetCrl);
        }
    }


    @Test
    public void testResponseTooLarge() throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(("HTTP/1.1 200 OK\r\n" + "Content-Type: application/ocsp-response\r\n" + "Content-Length: " +
                OCSP_RESPONSE_OVERSIZED + "\r\n" + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        baos.write(new byte[OCSP_RESPONSE_OVERSIZED]);
        try (ServerSocket serverSocket = startResponder(baos.toByteArray(), false)) {
            doTest(serverSocket.getLocalPort(), unableToGetCrl);
        }
    }


    @Test
    public void testInvalidResponse() throws Exception {
        byte[] body = "This is not an OCSP response".getBytes(StandardCharsets.ISO_8859_1);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(("HTTP/1.1 200 OK\r\n" + "Content-Type: application/ocsp-response\r\n" + "Content-Length: " +
                body.length + "\r\n" + "Connection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        baos.write(body);
        try (ServerSocket serverSocket = startResponder(baos.toByteArray(), false)) {
            doTest(serverSocket.getLocalPort(), applicationVerification);
        }
    }


    private void doTest(int port, int expectedError) throws Exception {
        URL url = new URL("http://127.0.0.1:" + port + "/ocsp");
        int result = ((Integer) processOCSPRequest.invoke(null, engineState, url, issuer, x509, x509ctx, arena))
                .intValue();
        int error = ((Integer) x509StoreCtxGetError.invoke(null, x509ctx)).intValue();
        Assert.assertEquals("OCSP status", certStatusUnknown, result);
        Assert.assertEquals("X509_STORE_CTX error", expectedError, error);
    }


    private static Object loadCertificate(String pemFile, Object addressLayout) throws Exception {
        String pem = new String(Files.readAllBytes(Paths.get(pemFile)), StandardCharsets.US_ASCII);
        int start = pem.indexOf("-----BEGIN CERTIFICATE-----");
        int end = pem.indexOf("-----END CERTIFICATE-----");
        Assert.assertTrue(start >= 0 && end > start);
        byte[] der = Base64.getMimeDecoder()
                .decode(pem.substring(start + "-----BEGIN CERTIFICATE-----".length(), end).trim());

        Class<?> segmentAllocatorClass = Class.forName("java.lang.foreign.SegmentAllocator");
        Method allocate = segmentAllocatorClass.getMethod("allocate", long.class);
        Object data = allocate.invoke(arena, Long.valueOf(der.length));
        ((ByteBuffer) memorySegmentClass.getMethod("asByteBuffer").invoke(data)).put(der);
        Object dataPointer = allocate.invoke(arena, Long.valueOf(8));
        memorySegmentClass.getMethod("set", Class.forName("java.lang.foreign.AddressLayout"), long.class,
                memorySegmentClass).invoke(dataPointer, addressLayout, Long.valueOf(0), data);

        Object result = opensslClass.getMethod("d2i_X509", memorySegmentClass, memorySegmentClass, long.class)
                .invoke(null, nullSegment, dataPointer, Long.valueOf(der.length));
        Assert.assertFalse("d2i_X509 failed for " + pemFile, nullSegment.equals(result));
        return result;
    }


    private static ServerSocket startResponder(final byte[] response, final boolean hang) throws IOException {
        final ServerSocket serverSocket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
        if (hang) {
            serverSocket.setSoTimeout(OCSP_TIMEOUT * 2);
        }
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try (Socket socket = serverSocket.accept()) {
                    InputStream is = socket.getInputStream();
                    // Read the request headers
                    StringBuilder headers = new StringBuilder();
                    int b;
                    while ((b = is.read()) != -1) {
                        headers.append((char) b);
                        if (headers.length() > 3 && headers.substring(headers.length() - 4).equals("\r\n\r\n")) {
                            break;
                        }
                    }
                    // Read the request body
                    int contentLength = 0;
                    for (String header : headers.toString().split("\r\n")) {
                        if (header.toLowerCase(Locale.ENGLISH).startsWith("content-length:")) {
                            contentLength = Integer.parseInt(header.substring("content-length:".length()).trim());
                        }
                    }
                    for (int i = 0; i < contentLength; i++) {
                        if (is.read() == -1) {
                            break;
                        }
                    }
                    if (hang) {
                        // Never respond. Wait for the client to give up.
                        socket.setSoTimeout(OCSP_TIMEOUT * 2);
                        while (is.read() != -1) {
                            // Ignore
                        }
                    } else {
                        OutputStream os = socket.getOutputStream();
                        os.write(response);
                        os.flush();
                    }
                } catch (IOException ioe) {
                    // Expected when the client stops reading / disconnects
                }
            }
        }, "OcspResponder");
        t.setDaemon(true);
        t.start();
        return serverSocket;
    }
}
