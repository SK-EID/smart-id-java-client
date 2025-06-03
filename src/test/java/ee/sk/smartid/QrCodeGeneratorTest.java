package ee.sk.smartid;

/*-
 * #%L
 * Smart ID sample Java client
 * %%
 * Copyright (C) 2018 - 2024 SK ID Solutions AS
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.exception.permanent.SmartIdClientException;

class QrCodeGeneratorTest {

    private static final int WHITE_COLOR = -1;

    @Test
    void generateDataUri_validateQrContent() {
        URI uri = createUri();
        String base64ImageData = QrCodeGenerator.generateDataUri(uri.toString());

        assertNotNull(base64ImageData);
        String[] parts = base64ImageData.split(",");
        assertEquals("data:image/png;base64", parts[0]);
        assertEquals(uri.toString(), QrCodeUtil.extractQrContent(parts[1]).getText());
    }

    @Nested
    class DefaultValues {

        @Test
        void generateDataUri() {
            URI uri = createUri();
            String qrDataUri = QrCodeGenerator.generateDataUri(uri.toString());
            String imgBase64 = qrDataUri.split(",")[1];
            BufferedImage qrImage = convertToBufferedImage(imgBase64);

            assertEquals(610, qrImage.getHeight());
            assertEquals(610, qrImage.getHeight());
            assertTrue(validateQuietArea(qrImage, 4, 10));
            assertQrModuleSize(qrImage, 4, 10);
        }

        @Test
        void generateBufferedImage() {
            URI uri = createUri();
            BufferedImage qrImage = QrCodeGenerator.generateImage(uri.toString());

            assertEquals(610, qrImage.getHeight());
            assertEquals(610, qrImage.getHeight());
            assertTrue(validateQuietArea(qrImage, 4, 10));
            assertQrModuleSize(qrImage, 4, 10);
        }
    }

    @Test
    void generateImage_providedCustomValues() {
        URI uri = createUri();
        int quietAreaSize = 2;
        BufferedImage bufferedImage = QrCodeGenerator.generateImage(uri.toString(), 100, 100, quietAreaSize);

        assertEquals(100, bufferedImage.getHeight());
        assertEquals(100, bufferedImage.getWidth());
        assertTrue(validateQuietArea(bufferedImage, 2, 1));

        float expectedModuleSize = (float) bufferedImage.getWidth() / (53 + 2 * quietAreaSize);
        assertQrModuleSize(bufferedImage, 2, expectedModuleSize);
    }

    @Nested
    class QrCodeModulePixelRanges {

        @Test
        void generateImage_providedCustomValues_moduleSize6px() {
            URI uri = createUri();
            int quietAreaSize = 2;
            BufferedImage bufferedImage = QrCodeGenerator.generateImage(uri.toString(), 366, 366, quietAreaSize);

            assertEquals(366, bufferedImage.getHeight());
            assertEquals(366, bufferedImage.getWidth());
            assertTrue(validateQuietArea(bufferedImage, 2, 1));

            assertQrModuleSize(bufferedImage, 4, 6);
        }

        @Test
        void generateImage_providedCustomValues_moduleSize19px() {
            URI uri = createUri();
            BufferedImage bufferedImage = QrCodeGenerator.generateImage(uri.toString(), 1159, 1159, 4);

            assertEquals(1159, bufferedImage.getHeight());
            assertEquals(1159, bufferedImage.getWidth());
            assertTrue(validateQuietArea(bufferedImage, 2, 1));

            assertQrModuleSize(bufferedImage, 4, 19);
        }
    }

    @ParameterizedTest
    @NullAndEmptySource
    void generateImage_providedDataIsEmpty_throwException(String data) {
        var ex = assertThrows(SmartIdClientException.class, () -> QrCodeGenerator.generateImage(data, 10, 10, 2));

        assertEquals("Provided data cannot be empty", ex.getMessage());
    }

    @Test
    void convertToBase64() {
        URI uri = createUri();
        BufferedImage bufferedImage = QrCodeGenerator.generateImage(uri.toString());
        String base64ImageData = QrCodeGenerator.convertToDataUri(bufferedImage, "png");

        String[] parts = base64ImageData.split(",");
        assertEquals("data:image/png;base64", parts[0]);
        Pattern pattern = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
        assertTrue(pattern.matcher(parts[1].replaceAll("\\s", "")).matches());
    }

    private static URI createUri() {
        return new DeviceContentBuilder()
                .withDeviceLinkType(DeviceLinkType.QR_CODE)
                .withSessionType(SessionType.AUTHENTICATION)
                .withSessionToken("rTBfEhy0z4SlqmGHjIW6uQid")
                .withAuthCode("Y7jBVqtP_KcY4GyJ0gTK717wZnfRLvondEUjjCRJAsQ")
                .withElapsedSeconds(1L)
                .createUri();
    }

    private static BufferedImage convertToBufferedImage(String qrDataUri) {
        byte[] qrCodeBytes = Base64.getMimeDecoder().decode(qrDataUri);
        try (ByteArrayInputStream bis = new ByteArrayInputStream(qrCodeBytes)) {
            return ImageIO.read(bis);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean validateQuietArea(BufferedImage qrImage, int quietZoneModules, int moduleSize) {
        int quietZonePixelSize = quietZoneModules * moduleSize;

        // Validate top and bottom quiet areas
        for (int y = 0; y < quietZonePixelSize; y++) {
            for (int x = 0; x < qrImage.getWidth(); x++) {
                if (qrImage.getRGB(x, y) != WHITE_COLOR || qrImage.getRGB(x, qrImage.getHeight() - 1 - y) != WHITE_COLOR) {
                    return false;
                }
            }
        }
        // Validate left and right quiet areas
        for (int x = 0; x < quietZonePixelSize; x++) {
            for (int y = 0; y < qrImage.getHeight(); y++) {
                if (qrImage.getRGB(x, y) != WHITE_COLOR || qrImage.getRGB(qrImage.getWidth() - 1 - x, y) != WHITE_COLOR) {
                    return false;
                }
            }
        }
        return true;
    }

    private static void assertQrModuleSize(BufferedImage qrImage,
                                           int nrOfQuietAreaModules,
                                           float expectedModuleSizePx) {
        float qrCodeWidth = 53 * expectedModuleSizePx;
        float quiteAreaWidth = nrOfQuietAreaModules * expectedModuleSizePx;
        float expectedWidth = qrCodeWidth + 2 * quiteAreaWidth;
        assertEquals(expectedWidth, qrImage.getWidth());
    }
}
