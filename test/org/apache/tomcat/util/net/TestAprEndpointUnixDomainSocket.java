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
package org.apache.tomcat.util.net;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.junit.After;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import org.apache.catalina.core.AprLifecycleListener;
import org.apache.coyote.http11.Http11AprProtocol;
import org.apache.tomcat.jni.Library;

/**
 * Tests the checks the APR/Native connector applies to the directory in which a Unix Domain Socket is created. The
 * parent directory must be created (or verified) with restrictive permissions and the expected owner before the
 * socket is bound, otherwise other local users may access the socket in the window between it being created with the
 * default (umask derived) permissions and the configured permissions being applied.
 */
@SuppressWarnings("deprecation")
public class TestAprEndpointUnixDomainSocket {

    private Path baseDir;
    private final List<Path> sharedDirSockets = new ArrayList<>();


    @Before
    public void setUp() throws Exception {
        // An instance must have been created for isAprAvailable() to initialise the native library
        new AprLifecycleListener();
        Assume.assumeTrue("APR/Native library is not available", AprLifecycleListener.isAprAvailable());
        Assume.assumeTrue("APR/Native library does not support Unix Domain Sockets", Library.APR_HAVE_UNIX);

        // Use the system temporary directory to keep socket paths well within the sun_path length limit
        baseDir = Files.createTempDirectory("tomcat-uds-").toRealPath();
        Assume.assumeTrue("POSIX file system is required",
                baseDir.getFileSystem().supportedFileAttributeViews().contains("posix"));
    }


    @After
    public void tearDown() throws IOException {
        for (Path socket : sharedDirSockets) {
            Files.deleteIfExists(socket);
        }
        if (baseDir != null) {
            deleteRecursively(baseDir);
        }
    }


    @Test
    public void testParentCreatedWithDerivedPermissions() throws Exception {
        Path parent = baseDir.resolve("parent");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-rw----");

        doInitSuccess(endpoint, socket, "rw-rw----");

        // Execute added for every read/write permission and group/other write removed
        Assert.assertEquals("rwxr-x---", getPermissions(parent));
    }


    @Test
    public void testParentCreatedWithDerivedPermissionsOwnerOnly() throws Exception {
        Path parent = baseDir.resolve("parent");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        doInitSuccess(endpoint, socket, "rw-------");

        Assert.assertEquals("rwx------", getPermissions(parent));
    }


    @Test
    public void testParentCreatedWithExplicitPermissions() throws Exception {
        // Intermediate directories are created as well, the immediate parent gets the configured permissions
        Path parent = baseDir.resolve("a").resolve("parent");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-rw-rw-");
        endpoint.setUnixDomainSocketParentPermissions("rwx------");

        doInitSuccess(endpoint, socket, "rw-rw-rw-");

        Assert.assertEquals("rwx------", getPermissions(parent));
    }


    @Test
    public void testParentCreatedWithoutSocketPermissions() throws Exception {
        Path parent = baseDir.resolve("parent");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketParentPermissions("rwx------");

        doInitSuccess(endpoint, socket);

        Assert.assertEquals("rwx------", getPermissions(parent));
    }


    @Test
    public void testParentPermissionsViaProperty() throws Exception {
        Path parent = baseDir.resolve("parent");
        Path socket = parent.resolve("test.sock");

        // Configure the way server.xml does, via the generic protocol properties
        AprEndpoint endpoint = new AprEndpoint();
        Http11AprProtocol protocol = new Http11AprProtocol(endpoint);
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPath", socket.toString()));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketPathPermissions", "rw-rw-rw-"));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketParentPermissions", "rwx--x---"));
        Assert.assertTrue(protocol.setProperty("unixDomainSocketParentOwner", ""));
        Assert.assertEquals("rwx--x---", endpoint.getUnixDomainSocketParentPermissions());
        Assert.assertEquals("", endpoint.getUnixDomainSocketParentOwner());

        doInitSuccess(endpoint, socket, "rw-rw-rw-");

        Assert.assertEquals("rwx--x---", getPermissions(parent));
    }


    @Test
    public void testExistingParentLaxPermissions() throws Exception {
        // Directory pre-created (e.g. by another local user) that other users can write to
        Path parent = createDirectory(baseDir.resolve("parent"), "rwxrwxrwx");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");

        Exception e = doInitFailure(endpoint, socket);
        Assert.assertTrue(e.toString(), e instanceof IllegalStateException);
        Assert.assertTrue(e.getMessage(), e.getMessage().contains(parent.toString()));

        // The existing directory must not have been modified
        Assert.assertEquals("rwxrwxrwx", getPermissions(parent));
    }


    @Test
    public void testExistingParentLaxPermissionsExplicit() throws Exception {
        Path parent = createDirectory(baseDir.resolve("parent"), "rwxr-xr-x");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-rw-rw-");
        endpoint.setUnixDomainSocketParentPermissions("rwx------");

        Exception e = doInitFailure(endpoint, socket);
        Assert.assertTrue(e.toString(), e instanceof IllegalStateException);
        Assert.assertTrue(e.getMessage(), e.getMessage().contains(parent.toString()));
    }


    @Test
    public void testExistingParentRestrictivePermissions() throws Exception {
        // More restrictive than required is acceptable
        Path parent = createDirectory(baseDir.resolve("parent"), "rwx------");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-rw----");

        doInitSuccess(endpoint, socket, "rw-rw----");

        Assert.assertEquals("rwx------", getPermissions(parent));
    }


    @Test
    public void testExistingParentSymbolicLink() throws Exception {
        // The parent is a symbolic link to a directory rather than a directory
        Path target = createDirectory(baseDir.resolve("target"), "rwx------");
        Path parent = Files.createSymbolicLink(baseDir.resolve("parent"), target);
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions("rwx------");

        doInitFailure(endpoint, socket);
        Assert.assertFalse(Files.exists(target.resolve("test.sock"), LinkOption.NOFOLLOW_LINKS));
    }


    @Test
    public void testEmptyParentPermissionsSkipsChecks() throws Exception {
        Path parent = createDirectory(baseDir.resolve("parent"), "rwxrwxrwx");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions("");

        doInitSuccess(endpoint, socket, "rw-------");

        Assert.assertEquals("rwxrwxrwx", getPermissions(parent));
    }


    @Test
    public void testNoPermissionsSkipsChecks() throws Exception {
        // No permissions configured so no checks (unchanged behaviour)
        Path parent = createDirectory(baseDir.resolve("parent"), "rwxrwxrwx");
        Path socket = parent.resolve("test.sock");

        AprEndpoint endpoint = createEndpoint(socket);

        doInitSuccess(endpoint, socket);

        Assert.assertEquals("rwxrwxrwx", getPermissions(parent));
    }


    @Test
    public void testParentOwnerMismatch() throws Exception {
        Path sharedDir = getSharedDirectoryNotOwnedByCurrentUser();
        Path socket = createSharedDirSocketPath(sharedDir);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        // Match the actual permissions so only the ownership check can fail
        endpoint.setUnixDomainSocketParentPermissions(getPermissions(sharedDir));

        Exception e = doInitFailure(endpoint, socket);
        Assert.assertTrue(e.toString(), e instanceof IllegalStateException);
        Assert.assertTrue(e.getMessage(), e.getMessage().contains(sharedDir.toString()));
    }


    @Test
    public void testParentOwnerMismatchExplicitOwner() throws Exception {
        Path sharedDir = getSharedDirectoryNotOwnedByCurrentUser();
        Path socket = createSharedDirSocketPath(sharedDir);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions(getPermissions(sharedDir));
        endpoint.setUnixDomainSocketParentOwner("tomcat-uds-no-such-user");

        Exception e = doInitFailure(endpoint, socket);
        Assert.assertTrue(e.toString(), e instanceof IllegalStateException);
    }


    @Test
    public void testParentOwnerExpected() throws Exception {
        Path sharedDir = getSharedDirectoryNotOwnedByCurrentUser();
        Path socket = createSharedDirSocketPath(sharedDir);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions(getPermissions(sharedDir));
        endpoint.setUnixDomainSocketParentOwner(Files.getOwner(sharedDir, LinkOption.NOFOLLOW_LINKS).getName());

        doInitSuccess(endpoint, socket);
    }


    @Test
    public void testEmptyParentOwnerSkipsCheck() throws Exception {
        Path sharedDir = getSharedDirectoryNotOwnedByCurrentUser();
        Path socket = createSharedDirSocketPath(sharedDir);

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentPermissions(getPermissions(sharedDir));
        endpoint.setUnixDomainSocketParentOwner("");

        doInitSuccess(endpoint, socket);
    }


    @Test
    public void testParentOwnerCurrentUser() throws Exception {
        // Owned by the current user is always acceptable even if a different owner is expected
        Path parent = createDirectory(baseDir.resolve("parent"), "rwx------");
        Path socket = parent.resolve("test.sock");
        Assert.assertEquals(System.getProperty("user.name"),
                Files.getOwner(parent, LinkOption.NOFOLLOW_LINKS).getName());

        AprEndpoint endpoint = createEndpoint(socket);
        endpoint.setUnixDomainSocketPathPermissions("rw-------");
        endpoint.setUnixDomainSocketParentOwner("tomcat-uds-no-such-user");

        doInitSuccess(endpoint, socket);
    }


    private static AprEndpoint createEndpoint(Path socket) {
        AprEndpoint endpoint = new AprEndpoint();
        // Registers the connection handler with the endpoint
        new Http11AprProtocol(endpoint);
        endpoint.setUnixDomainSocketPath(socket.toString());
        return endpoint;
    }


    private static void doInitSuccess(AprEndpoint endpoint, Path socket) throws Exception {
        doInitSuccess(endpoint, socket, null);
    }


    private static void doInitSuccess(AprEndpoint endpoint, Path socket, String expectedSocketPermissions)
            throws Exception {
        try {
            endpoint.init();
            Assert.assertTrue(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
            // Check while bound as the socket is removed when it is closed
            if (expectedSocketPermissions != null) {
                Assert.assertEquals(expectedSocketPermissions, getPermissions(socket));
            }
        } finally {
            endpoint.destroy();
        }
    }


    private static Exception doInitFailure(AprEndpoint endpoint, Path socket) throws Exception {
        try {
            endpoint.init();
        } catch (Exception e) {
            // The socket must not have been created
            Assert.assertFalse(Files.exists(socket, LinkOption.NOFOLLOW_LINKS));
            return e;
        }
        endpoint.destroy();
        Assert.fail("Unix Domain Socket [" + socket + "] was created when it should not have been");
        return null;
    }


    private Path getSharedDirectoryNotOwnedByCurrentUser() throws IOException {
        // Typically /tmp, owned by root
        Path sharedDir = baseDir.getParent();
        Assume.assumeNotNull(sharedDir);
        String owner = Files.getOwner(sharedDir, LinkOption.NOFOLLOW_LINKS).getName();
        Assume.assumeFalse("Shared directory [" + sharedDir + "] is owned by the current user",
                owner.equals(System.getProperty("user.name")));
        return sharedDir;
    }


    private Path createSharedDirSocketPath(Path sharedDir) {
        Path socket = sharedDir.resolve("tomcat-uds-" + UUID.randomUUID().toString() + ".sock");
        sharedDirSockets.add(socket);
        return socket;
    }


    private static Path createDirectory(Path dir, String permissions) throws IOException {
        Files.createDirectory(dir);
        // Set explicitly as the permissions at creation are subject to the umask
        Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString(permissions));
        return dir;
    }


    private static String getPermissions(Path path) throws IOException {
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
        return PosixFilePermissions.toString(permissions);
    }


    private static void deleteRecursively(Path root) throws IOException {
        final boolean posix = root.getFileSystem().supportedFileAttributeViews().contains("posix");
        Files.walkFileTree(root, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                // Ensure the contents can be removed regardless of the permissions the test applied
                if (posix) {
                    Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                Files.delete(file);
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                Files.delete(dir);
                return FileVisitResult.CONTINUE;
            }
        });
    }
}
