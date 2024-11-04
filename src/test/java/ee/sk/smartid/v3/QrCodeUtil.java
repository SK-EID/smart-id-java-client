package ee.sk.smartid.v3;

import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Base64;

import javax.imageio.ImageIO;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.LuminanceSource;
import com.google.zxing.MultiFormatReader;
import com.google.zxing.NotFoundException;
import com.google.zxing.Result;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.HybridBinarizer;

public class QrCodeUtil {

    private QrCodeUtil() {
    }

    public static String extractQrContent(String qrDataUri) {
        byte[] qrCodeBytes = Base64.getDecoder().decode(qrDataUri);

        BufferedImage bufferedImage;
        try (ByteArrayInputStream bis = new ByteArrayInputStream(qrCodeBytes)) {
            bufferedImage = ImageIO.read(bis);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        LuminanceSource source = new BufferedImageLuminanceSource(bufferedImage);
        BinaryBitmap bitmap = new BinaryBitmap(new HybridBinarizer(source));
        Result result;
        try {
            result = new MultiFormatReader().decode(bitmap);
        } catch (NotFoundException e) {
            throw new RuntimeException(e);
        }
        return result.getText();
    }
}
