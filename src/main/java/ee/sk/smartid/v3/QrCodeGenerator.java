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

import static com.google.zxing.EncodeHintType.ERROR_CORRECTION;
import static com.google.zxing.EncodeHintType.MARGIN;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import org.bouncycastle.util.encoders.Base64;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * This class is responsible for generating QR-codes
 */
public class QrCodeGenerator {

    private final static int DEFAULT_QR_CODE_WIDTH_PX = 570;
    private final static int DEFAULT_QR_CODE_HEIGHT = 570;
    private static final int DEFAULT_QUIET_AREA_SIZE_MODULES = 4;
    private static final String DEFAULT_FILE_FORMAT = "PNG";

    /**
     * Generates a QR-code
     * <p>
     * Uses default values for width (570px), height (570px), quiet area (4 modules) and file type (PNG).
     * <p>
     * Can be used with Data URI scheme in HTML
     *
     * @param data the data to be encoded
     * @return the QR-code as a Base64 encoded string
     */
    public static String generateBase64ImageData(String data) {
        BufferedImage bufferedImage = generateImage(data, DEFAULT_QR_CODE_WIDTH_PX, DEFAULT_QR_CODE_HEIGHT, DEFAULT_QUIET_AREA_SIZE_MODULES);
        return convertToBase64(bufferedImage, DEFAULT_FILE_FORMAT);
    }

    /**
     * Generates a QR-code
     * <p>
     * Uses LOW error correction level.
     *
     * @param data          the data to be encoded
     * @param widthPx       the width of the image
     * @param heightPx      the height of the image
     * @param quietAreaSize the size of the quiet area around the QR-code
     * @return the QR-code as a BufferedImage
     */
    public static BufferedImage generateImage(String data, int widthPx, int heightPx, Integer quietAreaSize) {
        if (data == null || data.isEmpty()) {
            throw new SmartIdClientException("Data to be encoded cannot be null or empty");
        }
        BitMatrix matrix;
        try {
            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(MARGIN, quietAreaSize);
            hints.put(ERROR_CORRECTION, ErrorCorrectionLevel.L);
            matrix = new MultiFormatWriter().encode(data, BarcodeFormat.QR_CODE, widthPx, heightPx, hints);
        } catch (WriterException ex) {
            throw new SmartIdClientException("Unable to create QR-code", ex);
        }
        return MatrixToImageWriter.toBufferedImage(matrix);
    }

    /**
     * Converts BufferedImage to Base64 encoded string
     *
     * @param bufferedImage the image to be encoded
     * @param fileFormat    the format of the image
     * @return the BufferedImage as a Base64 encoded string
     */
    public static String convertToBase64(BufferedImage bufferedImage, String fileFormat) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ImageIO.write(bufferedImage, fileFormat, baos);
            return Base64.toBase64String(baos.toByteArray());
        } catch (IOException ex) {
            throw new SmartIdClientException("Unable to generate QR-code", ex);
        }
    }
}
