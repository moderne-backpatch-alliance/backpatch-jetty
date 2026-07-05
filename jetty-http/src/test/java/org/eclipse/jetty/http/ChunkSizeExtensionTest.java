//
//  ========================================================================
//  Copyright (c) 1995-2022 Mort Bay Consulting Pty Ltd and others.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.http;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import org.eclipse.jetty.util.BufferUtil;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression tests for CVE-2026-2332 (CWE-444 HTTP request smuggling): the {@code HttpParser}
 * chunk-extension parser must reject a CR/LF (or other control) that appears inside a
 * quoted-string chunk-ext-value instead of silently terminating the chunk-size line there.
 * The permissive 9.4.x parser consumed every byte up to the first LF with no quoted-string
 * awareness, so a fronting proxy that understood quoted-strings and Jetty could disagree on
 * where the chunk-size line ended, desyncing request boundaries.
 *
 * <p>Backpatch-fresh (declared in candidates/jetty.yml with {@code source: fresh}); the upstream
 * ChunkSizeExtensionTest lives against the jetty-12 {@code jetty-server} API, so these are ported
 * onto the 9.4 {@link HttpParser.RequestHandler} harness. A bad chunk faults after the headers
 * are complete, so the parser signals it via {@code earlyEOF} and moves to the CLOSE state.
 */
public class ChunkSizeExtensionTest
{
    @Test
    public void rejectsCrlfInsideQuotedChunkExtensionValue()
    {
        // The quoted chunk-ext-value opens with a DQUOTE and then contains a raw CRLF. A strict
        // parser must fault before any body is delivered. The vulnerable 9.4.x parser terminated
        // the chunk-size line at that LF and then delivered the smuggled request-line bytes as
        // chunk content — that leaked content is exactly the desync this test guards against.
        Handler handler = new Handler();
        HttpParser parser = new HttpParser(handler);
        ByteBuffer buffer = BufferUtil.toBuffer(
            "POST / HTTP/1.1\r\n" +
                "Host: local\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5;x=\"\r\n" +
                "GET /smuggled HTTP/1.1\r\n" +
                "\"\r\n" +
                "hello\r\n" +
                "0\r\n" +
                "\r\n");
        parseAll(parser, buffer);

        assertTrue(handler.faulted(), "CRLF inside a quoted chunk-extension must fault the parse");
        assertNull(handler._content, "no chunk body must be delivered from the smuggled request");
        assertTrue(parser.isState(HttpParser.State.CLOSE), "parser must move to CLOSE on the bad chunk");
    }

    @Test
    public void acceptsLegitTokenAndQuotedChunkExtensionsAndDeliversBody()
    {
        // A well-formed token extension and a well-formed quoted-string extension must still parse
        // and the chunk body must be delivered unchanged (drop-in behavior preserved).
        Handler handler = new Handler();
        HttpParser parser = new HttpParser(handler);
        ByteBuffer buffer = BufferUtil.toBuffer(
            "POST / HTTP/1.1\r\n" +
                "Host: local\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "a;name=value;q=\"quoted value\"\r\n" +
                "0123456789\r\n" +
                "0\r\n" +
                "\r\n");
        parseAll(parser, buffer);

        assertTrue(!handler.faulted(), "well-formed chunk extensions must be accepted");
        assertEquals("0123456789", handler._content);
        assertTrue(handler._messageCompleted);
    }

    @Test
    public void rejectsBareCrAndControlCharsInsideQuotes()
    {
        // A bare CR (not part of a CRLF) inside the quoted value is illegal.
        Handler crHandler = new Handler();
        HttpParser crParser = new HttpParser(crHandler);
        parseAll(crParser, BufferUtil.toBuffer(
            "POST / HTTP/1.1\r\n" +
                "Host: local\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5;x=\"a\rb\"\r\n" +
                "hello\r\n" +
                "0\r\n" +
                "\r\n"));
        assertTrue(crHandler.faulted(), "bare CR inside a quoted chunk-extension must fault the parse");
        assertNull(crHandler._content, "no chunk body must be delivered after a bad quoted extension");

        // A control character (0x01) inside the quoted value is illegal.
        Handler ctlHandler = new Handler();
        HttpParser ctlParser = new HttpParser(ctlHandler);
        parseAll(ctlParser, BufferUtil.toBuffer(
            "POST / HTTP/1.1\r\n" +
                "Host: local\r\n" +
                "Transfer-Encoding: chunked\r\n" +
                "\r\n" +
                "5;x=\"ab\"\r\n" +
                "hello\r\n" +
                "0\r\n" +
                "\r\n"));
        assertTrue(ctlHandler.faulted(), "control char inside a quoted chunk-extension must fault the parse");
        assertNull(ctlHandler._content, "no chunk body must be delivered after a bad quoted extension");
    }

    private static void parseAll(HttpParser parser, ByteBuffer buffer)
    {
        int remaining = buffer.remaining();
        while (!parser.isState(HttpParser.State.END) && remaining > 0)
        {
            int wasRemaining = remaining;
            parser.parseNext(buffer);
            remaining = buffer.remaining();
            if (remaining == wasRemaining)
                break;
        }
    }

    private static class Handler implements HttpParser.RequestHandler
    {
        private String _content;
        private String _bad;
        private boolean _early;
        private boolean _messageCompleted;

        private boolean faulted()
        {
            return _bad != null || _early;
        }

        @Override
        public boolean content(ByteBuffer ref)
        {
            if (_content == null)
                _content = "";
            _content += BufferUtil.toString(ref, StandardCharsets.UTF_8);
            ref.position(ref.limit());
            return false;
        }

        @Override
        public boolean startRequest(String method, String uri, HttpVersion version)
        {
            return false;
        }

        @Override
        public void parsedHeader(HttpField field)
        {
        }

        @Override
        public boolean headerComplete()
        {
            return false;
        }

        @Override
        public boolean contentComplete()
        {
            return false;
        }

        @Override
        public boolean messageComplete()
        {
            _messageCompleted = true;
            return true;
        }

        @Override
        public void badMessage(BadMessageException failure)
        {
            _bad = failure.getReason() == null ? String.valueOf(failure.getCode()) : failure.getReason();
        }

        @Override
        public void earlyEOF()
        {
            _early = true;
        }

        @Override
        public int getHeaderCacheSize()
        {
            return 0;
        }
    }
}
