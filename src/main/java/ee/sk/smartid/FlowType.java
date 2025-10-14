package ee.sk.smartid;

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

import java.util.Arrays;

/**
 * Represents the flow types that user used to complete the authentication or signing.
 */
public enum FlowType {

    /**
     * QR-code (cross-device) flow. User scanned a QR-code with the Smart-ID app.
     */
    QR("QR"),

    /**
     * Web2App (same-device) flow. User clicked on a link in the browser on a mobile device
     * and confirmed with the Smart-ID app.
     */
    WEB2APP("Web2App"),

    /**
     * App2App (same-device) flow. User clicked on a link in the app on a mobile device
     * and confirmed with the Smart-ID app.
     */
    APP2APP("App2App"),

    /**
     * Notification flow. User received a push-notification and confirmed with the Smart-ID app.
     */
    NOTIFICATION("Notification");

    private final String description;

    FlowType(String description) {
        this.description = description;
    }

    /***
     * Gets the value used in the Smart ID API to represent the flow type.
     *
     * @return the flow type description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Checks if the provided flow type is supported.
     *
     * @param flowType the flow type to check
     * @return true if the flow type is supported, false otherwise
     */
    public static boolean isSupported(String flowType) {
        return Arrays.stream(FlowType.values())
                .anyMatch(f -> f.getDescription().equals(flowType));
    }

    /**
     * Converts a string representation of a flow type to the corresponding FlowType enum value.
     *
     * @param flowType the string representation of the flow type
     * @return the corresponding FlowType enum value
     * @throws IllegalArgumentException if the provided flow type is not valid
     */
    public static FlowType fromString(String flowType) {
        return Arrays.stream(FlowType.values())
                .filter(f -> f.getDescription().equals(flowType))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Invalid flowType value: " + flowType));
    }
}
