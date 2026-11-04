/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.coyote.http2;

import java.nio.ByteBuffer;

import org.junit.Assert;
import org.junit.Test;


public class TestHPackHuffman {

    /*
     * This specific String exposed an edge case that triggered an unexpected HPACK parsing failure.
     */
    @Test
    public void testValueLeftBrace() throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(10);
        String data = "x-value{";
        HPackHuffman.encode(buf, data, false);

        buf.flip();
        // Remove the header byte (in Tomcat this is parsed before the bytes are passed to the HPACK decoder)
        buf.get();

        StringBuilder target = new StringBuilder();
        HPackHuffman.decode(buf, buf.remaining(), target);

        Assert.assertEquals("Value changed after encode/decode roundtrip", data, target.toString());
    }


    /*
     * Every character must survive a Huffman encode/decode round trip at the start, in the middle and at the end of a
     * value. The HTTP/2 field validation relies on this to see the characters the client actually sent.
     */
    @Test
    public void testFullRangeRoundTrip() throws Exception {
        for (int i = 0; i < 256; i++) {
            char c = (char) i;
            doTestRoundTrip(c + "x-value");
            doTestRoundTrip("x-va" + c + "lue");
            doTestRoundTrip("x-value" + c);
        }
    }


    private void doTestRoundTrip(String data) throws Exception {
        ByteBuffer buf = ByteBuffer.allocate(64);
        if (!HPackHuffman.encode(buf, data, false)) {
            // Huffman encoding was longer than the original. Nothing to test.
            return;
        }

        buf.flip();
        // Remove the header byte (in Tomcat this is parsed before the bytes are passed to the HPACK decoder)
        buf.get();

        StringBuilder target = new StringBuilder();
        HPackHuffman.decode(buf, buf.remaining(), target);

        Assert.assertEquals("Value changed after encode/decode roundtrip", data, target.toString());
    }
}
