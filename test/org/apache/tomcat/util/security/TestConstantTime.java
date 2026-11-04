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
package org.apache.tomcat.util.security;

import java.nio.charset.StandardCharsets;

import org.junit.Assert;
import org.junit.Test;

import org.apache.tomcat.util.buf.ByteChunk;

public class TestConstantTime {

    private static ByteChunk chunk(String prefix, String value) {
        byte[] all = (prefix + value).getBytes(StandardCharsets.ISO_8859_1);
        ByteChunk bc = new ByteChunk();
        bc.setBytes(all, prefix.length(), value.length());
        return bc;
    }


    @Test
    public void testByteChunkNulls() {
        Assert.assertTrue(ConstantTime.equals((ByteChunk) null, (String) null));
        Assert.assertFalse(ConstantTime.equals((ByteChunk) null, "a"));
        Assert.assertFalse(ConstantTime.equals(chunk("", "a"), null));
    }


    @Test
    public void testByteChunkEqual() {
        Assert.assertTrue(ConstantTime.equals(chunk("", "secret"), "secret"));
    }


    @Test
    public void testByteChunkEqualNonZeroStart() {
        Assert.assertTrue(ConstantTime.equals(chunk("XXXXXX", "secret"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("secret", "XXXXXX"), "secret"));
    }


    @Test
    public void testByteChunkDifferent() {
        Assert.assertFalse(ConstantTime.equals(chunk("", "secreT"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("", "Secret"), "secret"));
    }


    @Test
    public void testByteChunkLengthMismatch() {
        Assert.assertFalse(ConstantTime.equals(chunk("", "secre"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("", "secrets"), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("", ""), "secret"));
        Assert.assertFalse(ConstantTime.equals(chunk("", "secret"), ""));
        Assert.assertTrue(ConstantTime.equals(chunk("abc", ""), ""));
    }


    @Test
    public void testByteChunkHighBytes() {
        // Bytes >= 0x80 must not be sign extended
        Assert.assertTrue(ConstantTime.equals(chunk("", "éÿ"), "éÿ"));
        Assert.assertFalse(ConstantTime.equals(chunk("", "é"), "￩"));
    }


    @Test
    public void testString() {
        Assert.assertTrue(ConstantTime.equals("abc", "abc", false));
        Assert.assertFalse(ConstantTime.equals("abc", "ABC", false));
        Assert.assertTrue(ConstantTime.equals("abc", "ABC", true));
        Assert.assertFalse(ConstantTime.equals("abc", "abcd", false));
        Assert.assertFalse(ConstantTime.equals("abc", null, false));
        Assert.assertTrue(ConstantTime.equals((String) null, (String) null, false));
    }


    @Test
    public void testBytes() {
        Assert.assertTrue(ConstantTime.equals(new byte[] { 1, 2 }, new byte[] { 1, 2 }));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2 }, new byte[] { 1, 3 }));
        Assert.assertFalse(ConstantTime.equals(new byte[] { 1, 2 }, new byte[] { 1 }));
    }
}
