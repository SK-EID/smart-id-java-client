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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.imageio.ImageIO;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import ee.sk.smartid.exception.permanent.SmartIdClientException;

/**
 * This class is responsible for generating QR-codes.
 * It can generate QR-codes as Data URIs or as BufferedImages.
 * <p>
 * The default image size of the generated QR code is 610x610px.
 * It is calculated based on the version 9 QR-code that contains 53x53 modules and four quiet area modules.
 * QR-code version 9 is selected automatically based on the provided length of the data.
 * The module size should be 10px, so the image size is 53x10=530px + 2x4x10=80px = 610px.
 * <p>
 * Generated QR-codes have LOW error correction level.
 */
public class QrCodeGenerator {

    private static final int DEFAULT_QR_CODE_WIDTH_PX = 610;
    private static final int DEFAULT_QR_CODE_HEIGHT = 610;
    private static final int DEFAULT_QUIET_AREA_SIZE_MODULES = 4;
    private static final String DEFAULT_FILE_FORMAT = "png";

    /**
     * Generates a QR-code as Data URI
     * <p>
     * Uses default values for width (610px), height (610px), quiet area (4 modules) and file type (PNG).
     *
     * @param data the data to be encoded
     * @return the QR-code as a Base64 encoded string
     */
    public static String generateDataUri(String data) {
        BufferedImage bufferedImage = generateImage(data, DEFAULT_QR_CODE_WIDTH_PX, DEFAULT_QR_CODE_HEIGHT, DEFAULT_QUIET_AREA_SIZE_MODULES);
        return convertToDataUri(bufferedImage, DEFAULT_FILE_FORMAT);
    }

    /**
     * Generates a QR-code as BufferedImage
     * <p>
     * Uses default values for width (610px), height (610px), quiet area (4 modules) and file type (PNG).
     *
     * @param data the data to be encoded
     * @return the QR-code as a BufferedImage
     */
    public static BufferedImage generateImage(String data) {
        return generateImage(data, DEFAULT_QR_CODE_WIDTH_PX, DEFAULT_QR_CODE_HEIGHT, DEFAULT_QUIET_AREA_SIZE_MODULES);
    }

    /**
     * Generates a QR-code as BufferedImage.
     * <p>
     * Provide the width and height of the image in pixels and the size of the quiet area around the QR-code in modules.
     *
     * @param data          the data to be encoded
     * @param widthPx       the width of the image in pixels
     * @param heightPx      the height of the image in pixels
     * @param quietAreaSize the size of the quiet area around the QR-code, value in modules
     * @return the QR-code as a BufferedImage
     */
    public static BufferedImage generateImage(String data, int widthPx, int heightPx, int quietAreaSize) {
        if (data == null || data.isEmpty()) {
            throw new SmartIdClientException("Provided data cannot be empty");
        }
        BitMatrix matrix;
        try {
            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(MARGIN, quietAreaSize);
            hints.put(ERROR_CORRECTION, ErrorCorrectionLevel.L);

            matrix = new QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, widthPx, heightPx, hints);
        } catch (WriterException ex) {
            throw new SmartIdClientException("Unable to create QR-code", ex);
        }
        return MatrixToImageWriter.toBufferedImage(matrix);
    }

    /**
     * Converts provided BufferedImage to Data URI with provided file format.
     *
     * @param bufferedImage the image to be converted
     * @param fileFormat    the format of the image
     * @return the image as a Data URI
     */
    public static String convertToDataUri(BufferedImage bufferedImage, String fileFormat) {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            ImageIO.write(bufferedImage, fileFormat, outputStream);
            String imgBase64 = Base64.getMimeEncoder().encodeToString(outputStream.toByteArray());
            return toDataUri(imgBase64, fileFormat);
        } catch (IOException ex) {
            throw new SmartIdClientException("Unable to generate QR-code", ex);
        }
    }

    private static String toDataUri(String imageData, String fileFormat) {
        return String.format("data:image/%s;base64,%s", fileFormat, imageData);
    }
}
