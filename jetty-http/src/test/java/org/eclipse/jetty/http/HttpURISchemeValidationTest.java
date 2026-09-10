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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * CVE-2025-11143: the scheme was accepted with any characters in it, so a URI whose
 * scheme a browser rejects or reads differently was parsed by HttpURI into a scheme
 * and a host that a second parser in the same system would not agree with.
 */
public class HttpURISchemeValidationTest
{
    @ParameterizedTest
    @ValueSource(strings = {
        "https>://vulndetector.com/path",
        "http^://host/path",
        "unknown^://host/path",
        "http|://host/path",
        "ht tp://host/path",
        "1http://host/path"
    })
    public void rejectsASchemeCarryingCharactersRfc3986DoesNotAllow(String uri)
    {
        assertThrows(IllegalArgumentException.class, () -> new HttpURI(uri));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "://host/path",
        "\t://host/path",
        "  ://host/path"
    })
    public void rejectsAnEmptyOrWhitespaceScheme(String uri)
    {
        assertThrows(IllegalArgumentException.class, () -> new HttpURI(uri));
    }

    /**
     * The other direction. A scheme the RFC allows must still parse, and must come back
     * byte-for-byte as it was written: the fix validates the scheme, it does not normalise
     * it, so a consumer comparing getScheme() sees exactly what this baseline always gave.
     */
    @ParameterizedTest
    @ValueSource(strings = {"http", "https", "HTTPS", "ws", "a", "x-y", "x+y", "x.y", "h2c", "view-source"})
    public void acceptsALegalSchemeAndReturnsItUnchanged(String scheme)
    {
        HttpURI uri = new HttpURI(scheme + "://host/path");
        assertThat(uri.getScheme(), is(scheme));
        assertThat(uri.getHost(), is("host"));
        assertThat(uri.getPath(), is("/path"));
    }

    /**
     * A relative request target has no scheme at all and must not be dragged into
     * validation by the new ':' case in the START state.
     */
    @Test
    public void leavesSchemeLessRequestTargetsAlone()
    {
        HttpURI uri = new HttpURI("/path/info?query=1#frag");
        assertThat(uri.getScheme(), is(nullValue()));
        assertThat(uri.getPath(), is("/path/info"));
        assertThat(uri.getQuery(), is("query=1"));
        assertThat(uri.getFragment(), is("frag"));
    }
}
