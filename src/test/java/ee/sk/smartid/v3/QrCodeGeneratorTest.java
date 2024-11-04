package ee.sk.smartid.v3;

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
import java.util.Base64;
import java.util.regex.Pattern;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import ee.sk.smartid.FileUtil;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

class QrCodeGeneratorTest {

    private static final int WHITE_COLOR = -1;
    private static final byte[] QR_IMAGE = FileUtil.readFileBytes("v3/qr-code.png");

    @Test
    void generateBase64ImageData_validateQrContent() {
        String base64ImageData = QrCodeGenerator.generateBase64ImageData("data");

        assertNotNull(base64ImageData);
        assertEquals("data", QrCodeUtil.extractQrContent(base64ImageData));
    }

    @Test
    void generateBase64ImageData_validateQrCodeDefaults() {
        String qrDataUri = QrCodeGenerator.generateBase64ImageData("data");

        BufferedImage qrImage = convertToBufferedImage(qrDataUri);

        assertEquals(570, qrImage.getHeight());
        assertEquals(570, qrImage.getHeight());
        assertTrue(validateQuietArea(qrImage, 4, 10));
    }

    @Test
    void generateImage_validateQrCodeAttributes() {
        BufferedImage bufferedImage = QrCodeGenerator.generateImage("data", 10, 10, 2);

        assertEquals(25, bufferedImage.getHeight());
        assertEquals(25, bufferedImage.getWidth());
        assertTrue(validateQuietArea(bufferedImage, 2, 1));
    }

    @ParameterizedTest
    @NullAndEmptySource
    void generateImage_providedDataIsEmpty_throwException(String data) {
        var ex = assertThrows(SmartIdClientException.class, () -> QrCodeGenerator.generateImage(data, 10, 10, 2));

        assertEquals("Data to be encoded cannot be null or empty", ex.getMessage());
    }

    @Test
    void convertToBase64() {
        BufferedImage bufferedImage = createBufferedImage(QR_IMAGE);
        String base64ImageData = QrCodeGenerator.convertToBase64(bufferedImage, "png");

        Pattern pattern = Pattern.compile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");

        assertTrue(pattern.matcher(base64ImageData).matches());
    }

    private static BufferedImage convertToBufferedImage(String qrDataUri) {
        byte[] qrCodeBytes = Base64.getDecoder().decode(qrDataUri);
        return createBufferedImage(qrCodeBytes);
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

    private static BufferedImage createBufferedImage(byte[] qrImage) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(qrImage)) {
            return ImageIO.read(bis);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
