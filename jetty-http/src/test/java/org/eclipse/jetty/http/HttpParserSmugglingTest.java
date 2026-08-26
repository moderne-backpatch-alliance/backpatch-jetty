// ========================================================================
// Copyright (c) 2004-2009 Mort Bay Consulting Pty. Ltd.
// ------------------------------------------------------------------------
// All rights reserved. This program and the accompanying materials
// are made available under the terms of the Eclipse Public License v1.0
// and Apache License v2.0 which accompanies this distribution.
// The Eclipse Public License is available at
// http://www.eclipse.org/legal/epl-v10.html
// The Apache License v2.0 is available at
// http://www.opensource.org/licenses/apache2.0.php
// You may elect to redistribute this code under either of these licenses.
// ========================================================================

package org.eclipse.jetty.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.eclipse.jetty.io.Buffer;
import org.eclipse.jetty.io.ByteArrayBuffer;
import org.eclipse.jetty.io.SimpleBuffers;
import org.eclipse.jetty.io.bio.StringEndPoint;
import org.junit.Test;

/**
 * Request-smuggling regression tests for CVE-2017-7657 (chunk-length integer overflow) and
 * CVE-2017-7658 (ambiguous framing from duplicate Content-Length, or Content-Length together
 * with a chunked Transfer-Encoding).
 *
 * Each rejection case fails on the unpatched 8.0.4 parser: it accepts the message and reports
 * a completed request instead of throwing, which is exactly the framing disagreement an
 * intermediary can be made to exploit.
 */
public class HttpParserSmugglingTest
{
    @Test
    public void rejectsAChunkSizeThatOverflowsTheChunkLength() throws Exception
    {
        // 0x1000000000 truncates to 0 in a 32-bit int, so the unpatched parser reads this as the
        // terminating chunk and treats the body that follows as a new pipelined request.
        HttpException e = parseExpectingFailure(
                "POST /smuggle HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Transfer-Encoding: chunked\015\012"
                        + "\015\012"
                        + "1000000000\015\012"
                        + "GET /admin HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "\015\012");
        assertEquals(HttpStatus.REQUEST_ENTITY_TOO_LARGE_413, e.getStatus());
    }

    @Test
    public void rejectsASecondContentLengthHeader() throws Exception
    {
        HttpException e = parseExpectingFailure(
                "POST /smuggle HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Content-Length: 6\015\012"
                        + "Content-Length: 0\015\012"
                        + "\015\012"
                        + "hello!");
        assertEquals(HttpStatus.BAD_REQUEST_400, e.getStatus());
    }

    @Test
    public void rejectsChunkedTransferEncodingAfterAContentLength() throws Exception
    {
        HttpException e = parseExpectingFailure(
                "POST /smuggle HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Content-Length: 6\015\012"
                        + "Transfer-Encoding: chunked\015\012"
                        + "\015\012"
                        + "0\015\012"
                        + "\015\012");
        assertEquals(HttpStatus.BAD_REQUEST_400, e.getStatus());
    }

    @Test
    public void rejectsAContentLengthAfterAChunkedTransferEncoding() throws Exception
    {
        HttpException e = parseExpectingFailure(
                "POST /smuggle HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Transfer-Encoding: chunked\015\012"
                        + "Content-Length: 6\015\012"
                        + "\015\012"
                        + "0\015\012"
                        + "\015\012");
        assertEquals(HttpStatus.BAD_REQUEST_400, e.getStatus());
    }

    @Test
    public void stillAcceptsAnOrdinaryChunkedBody() throws Exception
    {
        Handler handler = parse(
                "POST /ok HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Transfer-Encoding: chunked\015\012"
                        + "\015\012"
                        + "a\015\012"
                        + "0123456789\015\012"
                        + "0\015\012"
                        + "\015\012");
        assertTrue("message did not complete", handler.completed);
        assertEquals("0123456789", handler.content);
    }

    @Test
    public void stillAcceptsASingleContentLength() throws Exception
    {
        Handler handler = parse(
                "POST /ok HTTP/1.1\015\012"
                        + "Host: localhost\015\012"
                        + "Content-Length: 6\015\012"
                        + "\015\012"
                        + "hello!");
        assertTrue("message did not complete", handler.completed);
        assertEquals("hello!", handler.content);
    }

    private static HttpException parseExpectingFailure(String request) throws Exception
    {
        try
        {
            Handler handler = parse(request);
            fail("parser accepted an ambiguously framed request; completed=" + handler.completed);
            return null; // unreachable
        }
        catch (HttpException e)
        {
            return e;
        }
    }

    private static Handler parse(String request) throws Exception
    {
        StringEndPoint io = new StringEndPoint();
        io.setInput(request);
        SimpleBuffers buffers = new SimpleBuffers(new ByteArrayBuffer(4096), new ByteArrayBuffer(8192));
        Handler handler = new Handler();
        new HttpParser(buffers, io, handler).parse();
        return handler;
    }

    private static class Handler extends HttpParser.EventHandler
    {
        String content = "";
        boolean completed;

        @Override
        public void content(Buffer ref) throws IOException
        {
            content += ref.toString();
        }

        @Override
        public void messageComplete(long contentLength) throws IOException
        {
            completed = true;
        }

        @Override
        public void startRequest(Buffer method, Buffer url, Buffer version) throws IOException
        {
        }

        @Override
        public void startResponse(Buffer version, int status, Buffer reason) throws IOException
        {
        }
    }
}
