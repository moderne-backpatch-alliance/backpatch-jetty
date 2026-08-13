//
//  ========================================================================
//  Copyright (c) 1995-2020 Mort Bay Consulting Pty Ltd and others.
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

package org.eclipse.jetty.server.handler;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.http.HttpStatus;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Server;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * CVE-2024-8184: ThreadLimitHandler retained one Remote entry per distinct remote IP forever, so a
 * client varying the forwarded-for address exhausted the server's memory. The fix reference-counts
 * each Remote and drops the map entry when the last request for that IP is destroyed.
 */
public class ThreadLimitHandlerRemoteLeakTest
{
    private Server _server;
    private LocalConnector _local;
    private ThreadLimitHandler _handler;

    @Before
    public void before() throws Exception
    {
        _server = new Server();
        _local = new LocalConnector(_server);
        _server.addConnector(_local);

        _handler = new ThreadLimitHandler("X-Forwarded-For");
        _handler.setHandler(new AbstractHandler()
        {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                response.setStatus(HttpStatus.OK_200);
            }
        });

        // ThreadLimitHandler releases its Remote entries from a ServletRequestListener, so it has to
        // run inside a context for the entries to be reclaimed at all.
        ContextHandler context = new ContextHandler("/");
        context.setHandler(_handler);
        _server.setHandler(context);
        _server.start();
    }

    @After
    public void after() throws Exception
    {
        _server.stop();
    }

    @Test
    public void releasesRemoteEntryOfEveryDistinctIpOnceItsRequestsComplete() throws Exception
    {
        for (int i = 0; i < 200; i++)
        {
            String response = _local.getResponse("GET / HTTP/1.0\r\nX-Forwarded-For: 10.0.0." + i + "\r\n\r\n");
            assertThat(response.startsWith("HTTP/1.1 200"), is(true));
        }

        assertThat(_handler.getRemoteCount(), is(0));
    }

    @Test
    public void releasesTheSingleRemoteEntryAfterRepeatedRequestsFromOneIp() throws Exception
    {
        for (int i = 0; i < 10; i++)
            _local.getResponse("GET / HTTP/1.0\r\nX-Forwarded-For: 10.0.0.1\r\n\r\n");

        assertThat(_handler.getRemoteCount(), is(0));
    }
}
