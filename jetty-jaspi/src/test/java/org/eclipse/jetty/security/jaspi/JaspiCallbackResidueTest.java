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

package org.eclipse.jetty.security.jaspi;

import java.lang.reflect.Proxy;
import java.security.Principal;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.callback.CallerPrincipalCallback;
import javax.security.auth.message.callback.GroupPrincipalCallback;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.eclipse.jetty.security.DefaultIdentityService;
import org.eclipse.jetty.server.UserIdentity;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

/**
 * CVE-2026-5795: {@link ServletCallbackHandler} parks the caller and group principal callbacks in
 * ThreadLocals, and {@link JaspiAuthenticator} only reads them back on the AuthStatus.SUCCESS path.
 * A request that leaves through any other exit therefore leaves its callbacks parked on the worker
 * thread, and the next request served by that thread inherits them.
 */
public class JaspiCallbackResidueTest
{
    private final ServletCallbackHandler _callbackHandler = new ServletCallbackHandler(null);
    private final Deque<ScriptedExchange> _script = new ArrayDeque<>();
    private final AtomicReference<String[]> _attributedGroups = new AtomicReference<>();

    /** What one scripted request's auth module does before it returns. */
    private interface ScriptedExchange
    {
        AuthStatus play(Subject clientSubject) throws Exception;
    }

    private final DefaultIdentityService _identityService = new DefaultIdentityService()
    {
        @Override
        public UserIdentity newUserIdentity(Subject subject, Principal userPrincipal, String[] roles)
        {
            _attributedGroups.set(roles);
            return super.newUserIdentity(subject, userPrincipal, roles);
        }
    };

    private final ServerAuthContext _authContext = new ServerAuthContext()
    {
        @Override
        public AuthStatus validateRequest(MessageInfo messageInfo, Subject clientSubject, Subject serviceSubject) throws AuthException
        {
            try
            {
                return _script.removeFirst().play(clientSubject);
            }
            catch (Exception e)
            {
                throw new AuthException(e.toString());
            }
        }

        @Override
        public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject)
        {
            return AuthStatus.SEND_SUCCESS;
        }

        @Override
        public void cleanSubject(MessageInfo messageInfo, Subject subject)
        {
        }
    };

    private final JaspiAuthenticator _authenticator = new JaspiAuthenticator(
        new SimpleAuthConfig(SimpleAuthConfig.HTTP_SERVLET, _authContext),
        new HashMap<>(), _callbackHandler, new Subject(), false, _identityService);

    private void deliver(Callback... callbacks) throws Exception
    {
        _callbackHandler.handle(callbacks);
    }

    private static Subject subjectWith(Principal principal)
    {
        Subject subject = new Subject();
        subject.getPrincipals().add(principal);
        return subject;
    }

    private static JaspiMessageInfo request()
    {
        ClassLoader loader = JaspiCallbackResidueTest.class.getClassLoader();
        ServletRequest req = (ServletRequest)Proxy.newProxyInstance(
            loader, new Class<?>[]{HttpServletRequest.class}, (p, m, a) -> null);
        ServletResponse res = (ServletResponse)Proxy.newProxyInstance(
            loader, new Class<?>[]{HttpServletResponse.class}, (p, m, a) -> null);
        return new JaspiMessageInfo(req, res, true);
    }

    private List<String> attributedGroups()
    {
        String[] groups = _attributedGroups.get();
        return groups == null ? Collections.emptyList() : Arrays.asList(groups);
    }

    @Test
    public void unprivilegedRequestDoesNotInheritGroupsFromAnEarlierRequestOnTheSameThread() throws Exception
    {
        // A privileged request whose auth module publishes its groups and then fails: an exit that
        // never reaches the code reading the callbacks back off the thread.
        _script.add(clientSubject ->
        {
            deliver(new GroupPrincipalCallback(clientSubject, new String[]{"admin"}));
            return AuthStatus.SEND_FAILURE;
        });

        // The next request on this thread authenticates as a different user and claims no groups.
        Principal bob = () -> "bob";
        _script.add(clientSubject ->
        {
            deliver(new CallerPrincipalCallback(subjectWith(bob), bob));
            return AuthStatus.SUCCESS;
        });

        _authenticator.validateRequest(request());
        _authenticator.validateRequest(request());

        assertThat("second request inherited the first request's groups",
            attributedGroups(), not(hasItem("admin")));
    }

    @Test
    public void groupsPublishedByTheAuthModuleAreStillAttributedToTheRequestThatPublishedThem() throws Exception
    {
        Principal alice = () -> "alice";
        _script.add(clientSubject ->
        {
            deliver(new CallerPrincipalCallback(subjectWith(alice), alice),
                new GroupPrincipalCallback(clientSubject, new String[]{"admin"}));
            return AuthStatus.SUCCESS;
        });

        _authenticator.validateRequest(request());

        assertThat(attributedGroups(), contains("admin"));
    }
}
