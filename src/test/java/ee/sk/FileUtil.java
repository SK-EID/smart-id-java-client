package ee.sk;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Assert;

public final class FileUtil {

    private FileUtil() {
    }

    public static String readFileToString(String fileName) {
        return new String(readFileBytes(fileName), StandardCharsets.UTF_8);
    }

    private static byte[] readFileBytes(String fileName) {
        try {
            ClassLoader classLoader = FileUtil.class.getClassLoader();
            URL resource = classLoader.getResource(fileName);
            Assert.assertNotNull("File not found: " + fileName, resource);
            return Files.readAllBytes(Paths.get(resource.toURI()));
        } catch (Exception e) {
            throw new RuntimeException("Exception: " + e.getMessage(), e);
        }
    }
}
