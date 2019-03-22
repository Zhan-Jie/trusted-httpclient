package zhanj.trustedhttpclient;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;

public class App {

    public static void main(String[] args) throws IOException {
        OkHttpClient client = getTrustedHttpClient("client.p12", "123456", "server.pem");
        Request req = new Request.Builder().url("https://www.baidu.com").build();
        Response resp = client.newCall(req).execute();
        String body = resp.body().string();
        if (resp.isSuccessful()) {
            System.out.println(body);
        } else {
            System.err.println("HTTP status code: " + resp.code());
            System.err.println("body:");
            System.err.println(body);
        }
    }

    private static OkHttpClient getTrustedHttpClient(String clientKeyPath, String clientKeyPwd, String trustedCertPath) {
        X509TrustManager trustManager;
        SSLSocketFactory sslSocketFactory;
        InputStream stream1 = null;
        InputStream stream2 = null;
        try {
            stream2 = readFile(clientKeyPath);

            KeyStore keyStore = getClientKeyStore(stream2, clientKeyPwd);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, clientKeyPwd.toCharArray());

            stream1 = readFile(trustedCertPath);
            X509Certificate caCert = getTrustedCaCert(stream1);

            KeyStore trustedStore = getTrustedStore(caCert);
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            // 这里如果传入的trustedStore为null，那么会使用系统默认的证书信任存储库
            tmf.init(trustedStore);

            TrustManager[] trustManagers = tmf.getTrustManagers();
            trustManager = (X509TrustManager) trustManagers[0];
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), trustManagers, null);
            sslSocketFactory = sslContext.getSocketFactory();
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        } finally {
            closeStreamQuietly(stream1);
            closeStreamQuietly(stream2);
        }
        return new OkHttpClient.Builder()
                .sslSocketFactory(sslSocketFactory, trustManager)
                .retryOnConnectionFailure(false)
                .connectTimeout(5, TimeUnit.SECONDS)
                .readTimeout(5, TimeUnit.SECONDS)
                .build();
    }

    private static InputStream readFile(String path) {
        ClassLoader cl = ClassLoader.getSystemClassLoader();
        return cl.getResourceAsStream(path);
    }

    private static KeyStore getClientKeyStore(InputStream input, String password) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(input, password.toCharArray());
        return keyStore;
    }

    private static KeyStore getTrustedStore(X509Certificate caCert) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException {
        KeyStore trustedStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustedStore.load(null);
        trustedStore.setCertificateEntry(caCert.getSubjectX500Principal().getName(), caCert);
        return trustedStore;
    }

    private static X509Certificate getTrustedCaCert(InputStream input) throws CertificateException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(input);
    }

    private static void closeStreamQuietly(InputStream input) {
        if (input != null) {
            try {
                input.close();
            } catch (IOException ignored) {
            }
        }
    }
}
