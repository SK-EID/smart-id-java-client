package ee.sk.smartid.rest;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 SK ID Solutions AS
 * %%
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 * #L%
 */

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.Charset;

import org.glassfish.jersey.message.MessageUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.client.ClientRequestContext;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.client.ClientResponseContext;
import jakarta.ws.rs.client.ClientResponseFilter;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.WriterInterceptor;
import jakarta.ws.rs.ext.WriterInterceptorContext;

public class LoggingFilter implements ClientRequestFilter, ClientResponseFilter, WriterInterceptor {

    private static final Logger logger = LoggerFactory.getLogger(LoggingFilter.class);
    private static final String LOGGING_OUTPUT_STREAM_PROPERTY = "loggingOutputStream";

    @Override
    public void filter(ClientRequestContext requestContext) {
        if (logger.isDebugEnabled()) {
            logUrl(requestContext);
        }
        if (logger.isTraceEnabled()) {
            logHeaders(requestContext);
            if (requestContext.hasEntity()) {
                wrapEntityStreamWithLogger(requestContext);
            }
        }
    }

    @Override
    public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext) throws IOException {
        if (logger.isDebugEnabled()) {
            logger.debug("Response status: " + responseContext.getStatus() + " - " + responseContext.getStatusInfo());
        }
        if (logger.isTraceEnabled() && responseContext.hasEntity()) {
            logResponseBody(responseContext);
        }
    }

    @Override
    public void aroundWriteTo(WriterInterceptorContext context) throws IOException, WebApplicationException {
        context.proceed();
        if (logger.isTraceEnabled()) {
            logRequestBody(context);
        }
    }

    private void logUrl(ClientRequestContext requestContext) {
        String method = requestContext.getMethod();
        URI uri = requestContext.getUri();
        logger.debug(method + " " + uri.toString());
    }

    private void logHeaders(ClientRequestContext requestContext) {
        MultivaluedMap<String, String> headers = requestContext.getStringHeaders();
        if (headers != null) {
            logger.trace("Request headers: {}", headers);
        }
    }

    private void wrapEntityStreamWithLogger(ClientRequestContext requestContext) {
        OutputStream entityStream = requestContext.getEntityStream();
        LoggingOutputStream loggingOutputStream = new LoggingOutputStream(entityStream);
        requestContext.setEntityStream(loggingOutputStream);
        requestContext.setProperty(LOGGING_OUTPUT_STREAM_PROPERTY, loggingOutputStream);
    }

    private void logResponseBody(ClientResponseContext responseContext) throws IOException {
        Charset charset = MessageUtils.getCharset(responseContext.getMediaType());
        InputStream entityStream = responseContext.getEntityStream();
        byte[] bodyBytes = readInputStreamBytes(entityStream);
        responseContext.setEntityStream(new ByteArrayInputStream(bodyBytes));
        logger.trace("Response body: " + new String(bodyBytes, charset));
    }

    private byte[] readInputStreamBytes(InputStream entityStream) throws IOException {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int length;
        while ((length = entityStream.read(buffer)) != -1) {
            result.write(buffer, 0, length);
        }
        return result.toByteArray();
    }

    private void logRequestBody(WriterInterceptorContext context) {
        LoggingOutputStream loggingOutputStream = (LoggingOutputStream) context.getProperty(LOGGING_OUTPUT_STREAM_PROPERTY);
        if (loggingOutputStream != null) {
            Charset charset = MessageUtils.getCharset(context.getMediaType());
            byte[] bytes = loggingOutputStream.getBytes();
            logger.trace("Message body: " + new String(bytes, charset));
        }
    }

    public static class LoggingOutputStream extends FilterOutputStream {

        private final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        public LoggingOutputStream(OutputStream out) {
            super(out);
        }

        @Override
        public void write(byte[] b) throws IOException {
            super.write(b);
            byteArrayOutputStream.write(b);
        }

        @Override
        public void write(int b) throws IOException {
            super.write(b);
            byteArrayOutputStream.write(b);
        }

        public byte[] getBytes() {
            return byteArrayOutputStream.toByteArray();
        }
    }
}
