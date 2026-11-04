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

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

import org.junit.Assert;
import org.junit.Test;

import org.apache.coyote.Request;
import org.apache.tomcat.util.http.MimeHeaders;

/**
 * Tests that headers received for a stream that is replaced (and has its request and response recycled for re-use) by
 * a container thread while the parser is still processing the header block for that stream are never passed to the
 * replaced stream and therefore can not leak into the request of a subsequent stream.
 */
public class TestHttp2StreamEmitter {

    private static final int FLAG_END_OF_HEADERS = 0x04;

    private static final String INJECTED_NAME = "x-injected";
    private static final String INJECTED_VALUE = "injected";


    /*
     * Single threaded version of the race. The container thread completes the replacement and recycling of the stream
     * between the parser reading the HEADERS frame and the CONTINUATION frame for that stream.
     */
    @Test
    public void testContinuationAfterStreamReplacement() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        TesterInput input = new TesterInput();
        Http2Parser parser = new Http2Parser("0", input, handler);
        HpackEncoder encoder = new HpackEncoder();

        // Start of the header block for stream 3
        input.addFrame(buildFrame(encoder, FrameType.HEADERS, 0, 3, requestHeaders()));
        Assert.assertTrue(parser.readFrame());

        Stream stream3 = handler.getStream(3);
        Assert.assertNotNull(stream3);
        Request request = stream3.getCoyoteRequest();

        // Container thread resets and replaces the stream and recycles the request and response for re-use
        stream3.replace();
        stream3.recycle();

        // Remainder of the header block for stream 3
        input.addFrame(buildFrame(encoder, FrameType.CONTINUATION, FLAG_END_OF_HEADERS, 3, injectedHeaders()));
        Assert.assertTrue(parser.readFrame());

        Assert.assertNull(request.getMimeHeaders().getHeader(INJECTED_NAME));

        // New stream re-uses the recycled request and response
        input.addFrame(buildFrame(encoder, FrameType.HEADERS, 0, 5, requestHeaders()));
        Assert.assertTrue(parser.readFrame());

        Stream stream5 = handler.getStream(5);
        Assert.assertNotNull(stream5);
        Assert.assertSame(request, stream5.getCoyoteRequest());
        // The header received for the replaced stream must not leak into the request for stream 5
        Assert.assertNull(stream5.getCoyoteRequest().getMimeHeaders().getHeader(INJECTED_NAME));
    }


    /*
     * Multi-threaded version of the race. The container thread replaces the stream while the parser thread is
     * decoding a header for that stream.
     */
    @Test
    public void testHeaderDecodedDuringStreamReplacement() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        TesterInput input = new TesterInput();
        Http2Parser parser = new Http2Parser("0", input, handler);
        HpackEncoder encoder = new HpackEncoder();

        // Start of the header block for stream 3
        input.addFrame(buildFrame(encoder, FrameType.HEADERS, 0, 3, requestHeaders()));
        Assert.assertTrue(parser.readFrame());

        Stream stream3 = handler.getStream(3);
        Assert.assertNotNull(stream3);
        Request request = stream3.getCoyoteRequest();

        // Remainder of the header block for stream 3
        input.addFrame(buildFrame(encoder, FrameType.CONTINUATION, FLAG_END_OF_HEADERS, 3, injectedHeaders()));

        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread parserThread = new Thread(() -> {
            try {
                parser.readFrame();
            } catch (Throwable t) {
                failure.set(t);
            }
        });

        ReentrantLock streamEmitterLock = handler.getHpackDecoder().getStreamEmitterLock();
        // Container thread starts to replace the stream
        streamEmitterLock.lock();
        try {
            parserThread.start();
            // The header must not be emitted while the stream is being replaced
            Assert.assertTrue(waitForQueuedThread(streamEmitterLock, parserThread));
            Assert.assertNull(request.getMimeHeaders().getHeader(INJECTED_NAME));
            stream3.replace();
            stream3.recycle();
        } finally {
            streamEmitterLock.unlock();
        }
        parserThread.join(TimeUnit.SECONDS.toMillis(10));

        Assert.assertFalse(parserThread.isAlive());
        Assert.assertNull(failure.get());
        // The header must not be passed to the replaced stream
        Assert.assertNull(request.getMimeHeaders().getHeader(INJECTED_NAME));
        Assert.assertNull(handler.getStream(3));
        Assert.assertFalse(streamEmitterLock.isLocked());
    }


    @Test
    public void testHeadersStartBlockedDuringStreamReplacement() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();
        ReentrantLock streamEmitterLock = decoder.getStreamEmitterLock();

        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread parserThread = new Thread(() -> {
            try {
                handler.headersStart(3, false);
            } catch (Throwable t) {
                failure.set(t);
            }
        });

        // Container thread is replacing a stream
        streamEmitterLock.lock();
        try {
            parserThread.start();
            // Look-up of the stream and setting of the header emitter must wait for the replacement to complete
            Assert.assertTrue(waitForQueuedThread(streamEmitterLock, parserThread));
            Assert.assertNull(handler.getStream(3));
            Assert.assertNull(decoder.getHeaderEmitter());
        } finally {
            streamEmitterLock.unlock();
        }
        parserThread.join(TimeUnit.SECONDS.toMillis(10));

        Assert.assertFalse(parserThread.isAlive());
        Assert.assertNull(failure.get());
        Stream stream3 = handler.getStream(3);
        Assert.assertNotNull(stream3);
        Assert.assertSame(stream3, decoder.getHeaderEmitter());
        Assert.assertFalse(streamEmitterLock.isLocked());
    }


    @Test
    public void testReplaceStreamBlockedWhileHeaderEmitted() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();
        ReentrantLock streamEmitterLock = decoder.getStreamEmitterLock();

        handler.headersStart(3, false);
        Stream stream3 = handler.getStream(3);
        Assert.assertNotNull(stream3);
        Assert.assertSame(stream3, decoder.getHeaderEmitter());
        Assert.assertFalse(streamEmitterLock.isLocked());

        AtomicReference<Throwable> failure = new AtomicReference<>();
        Thread containerThread = new Thread(() -> {
            try {
                stream3.replace();
            } catch (Throwable t) {
                failure.set(t);
            }
        });

        // Parser thread is emitting a header
        streamEmitterLock.lock();
        try {
            containerThread.start();
            // Replacement of the stream must wait for the header to be emitted
            Assert.assertTrue(waitForQueuedThread(streamEmitterLock, containerThread));
            Assert.assertSame(stream3, handler.getStream(3));
            Assert.assertSame(stream3, decoder.getHeaderEmitter());
        } finally {
            streamEmitterLock.unlock();
        }
        containerThread.join(TimeUnit.SECONDS.toMillis(10));

        Assert.assertFalse(containerThread.isAlive());
        Assert.assertNull(failure.get());
        Assert.assertNull(handler.getStream(3));
        // Any further headers for the replaced stream are swallowed
        Assert.assertSame(Http2UpgradeHandler.HEADER_SINK, decoder.getHeaderEmitter());
        Assert.assertFalse(streamEmitterLock.isLocked());
    }


    @Test
    public void testReplaceStreamDoesNotAffectOtherStream() throws Exception {
        Http2UpgradeHandler handler = new Http2UpgradeHandler(new Http2Protocol(), null, null);
        HpackDecoder decoder = handler.getHpackDecoder();

        handler.headersStart(3, false);
        Stream stream3 = handler.getStream(3);
        Assert.assertNotNull(stream3);
        // Header block for stream 3 complete
        decoder.clearHeaderEmitter();

        handler.headersStart(5, false);
        Stream stream5 = handler.getStream(5);
        Assert.assertNotNull(stream5);
        Assert.assertSame(stream5, decoder.getHeaderEmitter());

        // Replacing stream 3 must not change the target of the header block being processed for stream 5
        stream3.replace();

        Assert.assertNull(handler.getStream(3));
        Assert.assertSame(stream5, decoder.getHeaderEmitter());
    }


    @Test
    public void testEmitHeaderHoldsStreamEmitterLock() throws Exception {
        MimeHeaders headers = new MimeHeaders();
        headers.setValue(INJECTED_NAME).setString(INJECTED_VALUE);
        ByteBuffer output = ByteBuffer.allocate(512);
        HpackEncoder encoder = new HpackEncoder();
        encoder.encode(headers, output);
        output.flip();

        HpackDecoder decoder = new HpackDecoder();
        AtomicReference<Boolean> lockHeld = new AtomicReference<>();
        AtomicReference<String> emittedValue = new AtomicReference<>();
        decoder.setHeaderEmitter(new HpackDecoder.HeaderEmitter() {
            @Override
            public void emitHeader(String name, String value) {
                lockHeld.set(Boolean.valueOf(decoder.getStreamEmitterLock().isHeldByCurrentThread()));
                emittedValue.set(value);
            }

            @Override
            public void setHeaderException(StreamException streamException) {
                // NO-OP
            }

            @Override
            public void validateHeaders() throws StreamException {
                // NO-OP
            }
        });
        decoder.decode(output);

        Assert.assertEquals(INJECTED_VALUE, emittedValue.get());
        Assert.assertEquals(Boolean.TRUE, lockHeld.get());
        Assert.assertFalse(decoder.getStreamEmitterLock().isLocked());
    }


    private static MimeHeaders requestHeaders() {
        MimeHeaders headers = new MimeHeaders();
        headers.addValue(":method").setString("POST");
        headers.addValue(":scheme").setString("http");
        headers.addValue(":path").setString("/simple");
        return headers;
    }


    private static MimeHeaders injectedHeaders() {
        MimeHeaders headers = new MimeHeaders();
        headers.addValue(INJECTED_NAME).setString(INJECTED_VALUE);
        return headers;
    }


    private static byte[] buildFrame(HpackEncoder encoder, FrameType frameType, int flags, int streamId,
            MimeHeaders headers) {
        ByteBuffer payload = ByteBuffer.allocate(512);
        Assert.assertEquals(HpackEncoder.State.COMPLETE, encoder.encode(headers, payload));
        payload.flip();

        byte[] frame = new byte[9 + payload.limit()];
        ByteUtil.setThreeBytes(frame, 0, payload.limit());
        frame[3] = frameType.getIdByte();
        frame[4] = (byte) flags;
        ByteUtil.set31Bits(frame, 5, streamId);
        payload.get(frame, 9, payload.limit());
        return frame;
    }


    private static boolean waitForQueuedThread(ReentrantLock lock, Thread thread) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
        while (!lock.hasQueuedThread(thread)) {
            if (!thread.isAlive() || System.nanoTime() > deadline) {
                return false;
            }
            Thread.sleep(5);
        }
        return true;
    }


    private static class TesterInput implements Http2Parser.Input {

        private byte[] data = new byte[0];
        private int pos = 0;

        synchronized void addFrame(byte[] frame) {
            int remaining = data.length - pos;
            byte[] newData = new byte[remaining + frame.length];
            System.arraycopy(data, pos, newData, 0, remaining);
            System.arraycopy(frame, 0, newData, remaining, frame.length);
            data = newData;
            pos = 0;
        }

        @Override
        public synchronized boolean fill(boolean block, byte[] dest, int offset, int length) throws IOException {
            if (length == 0) {
                return true;
            }
            if (!block && pos == data.length) {
                return false;
            }
            if (data.length - pos < length) {
                throw new EOFException();
            }
            System.arraycopy(data, pos, dest, offset, length);
            pos += length;
            return true;
        }

        @Override
        public int getMaxFrameSize() {
            return ConnectionSettingsBase.DEFAULT_MAX_FRAME_SIZE;
        }
    }
}
