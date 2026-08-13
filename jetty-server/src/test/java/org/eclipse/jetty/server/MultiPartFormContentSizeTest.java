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

package org.eclipse.jetty.server;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicReference;

import javax.servlet.MultipartConfigElement;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.server.handler.AbstractHandler;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * CVE-2023-26048: a multipart part carrying a name but no filename is copied into a
 * ByteArrayOutputStream so it can be exposed as a request parameter, with no accounting against
 * maxFormContentSize. A single large part therefore drove the server to OutOfMemoryError. The fix
 * sums the sizes of the fileless parts and refuses the request once they exceed the limit.
 */
public class MultiPartFormContentSizeTest
{
    private static final String BOUNDARY = "AaB03x";

    private Server _server;
    private LocalConnector _connector;
    private File _tmpDir;
    private final AtomicReference<Throwable> _failure = new AtomicReference<>();

    @Before
    public void before() throws Exception
    {
        _tmpDir = File.createTempFile("mpsize", null);
        _tmpDir.delete();
        _tmpDir.mkdir();
        _tmpDir.deleteOnExit();

        _server = new Server();
        _connector = new LocalConnector(_server);
        _server.addConnector(_connector);

        ContextHandler context = new ContextHandler("/");
        context.setResourceBase(".");
        context.setMaxFormContentSize(1024);
        context.setHandler(new AbstractHandler()
        {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response)
                throws IOException, ServletException
            {
                baseRequest.setHandled(true);
                request.setAttribute(Request.__MULTIPART_CONFIG_ELEMENT,
                    new MultipartConfigElement(_tmpDir.getAbsolutePath(), -1, -1, 2));
                try
                {
                    request.getParts();
                    response.setStatus(200);
                }
                catch (Throwable t)
                {
                    _failure.set(t);
                    response.setStatus(500);
                }
            }
        });
        _server.setHandler(context);
        _server.start();
    }

    @After
    public void after() throws Exception
    {
        _server.stop();
    }

    @Test
    public void rejectsFilelessPartLargerThanMaxFormContentSize() throws Exception
    {
        send(filelessPart("field1", repeat('x', 4096)));

        Throwable failure = _failure.get();
        assertThat(failure instanceof IllegalStateException, is(true));
        assertThat(failure.getMessage(), containsString("Form is larger than max length 1024"));
    }

    @Test
    public void rejectsFilelessPartsThatOnlyExceedTheLimitInAggregate() throws Exception
    {
        String body = filelessPart("field1", repeat('x', 600)) + filelessPart("field2", repeat('y', 600));
        send(body);

        Throwable failure = _failure.get();
        assertThat(failure instanceof IllegalStateException, is(true));
        assertThat(failure.getMessage(), containsString("Form is larger than max length 1024"));
    }

    @Test
    public void acceptsFilelessPartWithinTheLimit() throws Exception
    {
        String response = send(filelessPart("field1", repeat('x', 512)));

        assertThat(_failure.get(), is((Throwable)null));
        assertThat(response.startsWith("HTTP/1.1 200"), is(true));
    }

    @Test
    public void doesNotCountPartsThatCarryAFilename() throws Exception
    {
        String body = "--" + BOUNDARY + "\r\n" +
            "content-disposition: form-data; name=\"upload\"; filename=\"big.bin\"\r\n" +
            "Content-Type: text/plain;charset=ISO-8859-1\r\n" +
            "\r\n" +
            repeat('z', 4096) + "\r\n";

        String response = send(body);

        assertThat(_failure.get(), is((Throwable)null));
        assertThat(response.startsWith("HTTP/1.1 200"), is(true));
    }

    private static String repeat(char c, int n)
    {
        StringBuilder b = new StringBuilder(n);
        for (int i = 0; i < n; i++)
            b.append(c);
        return b.toString();
    }

    private static String filelessPart(String name, String content)
    {
        return "--" + BOUNDARY + "\r\n" +
            "content-disposition: form-data; name=\"" + name + "\"\r\n" +
            "Content-Type: text/plain;charset=ISO-8859-1\r\n" +
            "\r\n" +
            content + "\r\n";
    }

    private String send(String body) throws Exception
    {
        String multipart = body + "--" + BOUNDARY + "--\r\n";
        String request = "POST / HTTP/1.1\r\n" +
            "Host: whatever\r\n" +
            "Content-Type: multipart/form-data; boundary=\"" + BOUNDARY + "\"\r\n" +
            "Content-Length: " + multipart.getBytes().length + "\r\n" +
            "Connection: close\r\n" +
            "\r\n" +
            multipart;
        return _connector.getResponses(request);
    }
}
