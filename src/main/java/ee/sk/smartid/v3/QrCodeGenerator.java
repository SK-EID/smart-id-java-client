package ee.sk.smartid.v3;

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

    private final static int DEFAULT_QR_CODE_WIDTH = 570;
    private final static int DEFAULT_QR_CODE_HEIGHT = 570;
    private static final int DEFAULT_QUIET_AREA_SIZE = 4;
    private static final String DEFAULT_FILE_FORMAT = "png";

    /**
     * Generates a QR-code
     * <p>
     * Default values for width (570px), height (570px) and quiet(4px) area size and file type (PNG) are used.
     * <p>
     * Can be used with Data URI scheme in HTML
     *
     * @param data the data to be encoded
     * @return the QR-code as a Base64 encoded string
     */
    public static String generateBase64ImageData(String data) {
        BufferedImage bufferedImage = generateImage(data, DEFAULT_QR_CODE_WIDTH, DEFAULT_QR_CODE_HEIGHT, DEFAULT_QUIET_AREA_SIZE);
        return convertToBase64(bufferedImage, DEFAULT_FILE_FORMAT);
    }

    /**
     * Generates a QR-code
     * <p>
     * Uses LOW error correction level
     *
     * @param data          the data to be encoded
     * @param width         the width of the image
     * @param height        the height of the image
     * @param quietAreaSize the size of the quiet area around the QR-code
     * @return the QR-code as a BufferedImage
     */
    public static BufferedImage generateImage(String data, int width, int height, Integer quietAreaSize) {
        if (data == null || data.isEmpty()) {
            throw new SmartIdClientException("Data to be encoded cannot be null or empty");
        }
        BitMatrix matrix;
        try {
            Map<EncodeHintType, Object> hints = new HashMap<>();
            hints.put(MARGIN, quietAreaSize);
            hints.put(ERROR_CORRECTION, ErrorCorrectionLevel.L);
            matrix = new MultiFormatWriter().encode(data, BarcodeFormat.QR_CODE, width, height, hints);
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
