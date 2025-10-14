package ee.sk.smartid.util;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2025 SK ID Solutions AS
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

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import ee.sk.smartid.DigestCalculator;
import ee.sk.smartid.HashAlgorithm;
import ee.sk.smartid.common.SmartIdInteraction;
import ee.sk.smartid.exception.permanent.SmartIdClientException;
import ee.sk.smartid.rest.dao.Interaction;

/**
 * Utility for interactions related actions
 */
public class InteractionUtil {

    private static final ObjectMapper mapper = new ObjectMapper();

    private InteractionUtil() {
    }

    /**
     * Encodes list of interactions to Base64-encoded string
     *
     * @param interactions list of interactions
     * @return base64 encoded string
     * @throws SmartIdClientException if unable to encode interactions
     */
    public static String encodeToBase64(List<Interaction> interactions) {
        try {
            String json = mapper.writeValueAsString(interactions);
            return Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8));
        } catch (JsonProcessingException ex) {
            throw new SmartIdClientException("Unable to encode interactions to Base64", ex);
        }
    }

    /**
     * Calculates SHA-256 digest of the interactions and encodes it to Base64
     *
     * @param interactions interactions string
     * @return base64 encoded SHA-256 digest
     */
    public static String calculateDigest(String interactions){
        byte[] digest = DigestCalculator.calculateDigest(interactions.getBytes(StandardCharsets.UTF_8), HashAlgorithm.SHA_256);
        return Base64.getEncoder().encodeToString(digest);
    }

    /**
     * Checks if the list of interactions is empty or contains only null values
     *
     * @param interactions list of interactions
     * @return true if the list is empty or contains only null values, false otherwise
     */
    public static boolean isEmpty(List<? extends SmartIdInteraction> interactions) {
        return interactions == null || interactions.stream().filter(Objects::nonNull).toList().isEmpty();
    }
}
