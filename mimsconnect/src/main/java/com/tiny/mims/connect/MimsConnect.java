package com.tiny.mims.connect;

import android.content.Context;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import com.android.volley.*;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONException;
import org.json.JSONObject;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static java.util.Collections.list;

public class MimsConnect {
    /**
     * Event handler for new key registration
     * Register one using addListener();
     */
    public interface RegisterEventListener {
        /** Called when registration is successful */
        void onSuccess(String uuid);

        /** Called when registration is failed */
        void onFailure(Exception error);

        /** Called when the user is registered with a duplicated username */
        void onDuplicated();
    }

    public interface DownloadKeyEventListener {
        /**
         *
         */
        void onSuccessfulImport();
    }

    private final URI apiUri;
    private final Context context;

    /* Encryption related constants */
    private final String RSA_SIGN_SCHEME = "SHA256withRSA/PSS";
    private final String RSA_SIGN_ALGRO = "RSA";
    private final String RSA_ENC_ALGRO = "RSA";
    private final String DERIVE_ALGRO = "PBKDF2WithHmacSHA1";
    private final String ENCRYPT_ALGRO = "AES/GCM/NoPadding";
    private final String KEYSTORE_ANDROID = "AndroidKeyStore";

    /* Api related constants */
    private final String ENDPOINT_REGISTER_UUID = "/register_uuid";
    private final String ENDPOINT_UPLOAD_KEYS = "/upload_keys";

    /* Key names for keystore retrieval */
    private final String KEY_ALIAS_ENC = "KEY_ALIAS_ENC";
    private final String KEY_ALIAS_SIGN = "KEY_ALIAS_SIGN";

    /* Event listeners */
    private List<RegisterEventListener> registerEventListeners = new ArrayList<RegisterEventListener>();

    /* User information */
    private String uuid = null;

    /**
     * Creates an instance to connect and interface with the MIMS server
     *
     * @throws NoSuchAlgorithmException User should be informed if encryption is not supported
     */
    public MimsConnect(Context context, String apiUrl) throws NoSuchAlgorithmException, URISyntaxException {
        try {
            // A quick test of client's capability before continuing further
            Signature.getInstance(RSA_SIGN_SCHEME);
            KeyStore.getInstance(KEYSTORE_ANDROID);
            SecretKeyFactory.getInstance(DERIVE_ALGRO);
            Cipher.getInstance(ENCRYPT_ALGRO);
        } catch (NoSuchAlgorithmException | KeyStoreException | NoSuchPaddingException e) {
            throw new NoSuchAlgorithmException(
                    "This version of your operating system does not support the type of encryption used in MIMS");
        }
        this.apiUri = new URI(apiUrl);
        this.context = context;
    }

    /**
     * Checks whether this client has existing private keys stored (i.e. registered and logged in)
     * It should be used to determine whether the user is logged in
     *
     * @return True if existing private key is present
     */
    public boolean hasExistingKey()
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        List<String> aliases = list(ks.aliases());
        return aliases.containsAll(Arrays.asList(KEY_ALIAS_ENC, KEY_ALIAS_SIGN));
    }

    /**
     * Generates public private key pairs for signature and encryption and register it on server
     * WARNING: This will overwrite the current stored private key, if any
     *
     * @throws NoSuchAlgorithmException Encryption scheme not supported by this client
     */
    public void registerNewKey(final String username, final String password) {
        ExecutorService threadPool = Executors.newCachedThreadPool();
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                KeyPairGenerator keygenEnc = null;
                KeyPairGenerator keygenSign = null;
                try {
                    keygenEnc = KeyPairGenerator.getInstance(RSA_ENC_ALGRO);
                    keygenSign = KeyPairGenerator.getInstance(RSA_SIGN_ALGRO);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                keygenEnc.initialize(2048);
                keygenSign.initialize(2048);
                final KeyPair keyPairEnc = keygenEnc.generateKeyPair();
                final KeyPair keyPairSign = keygenSign.generateKeyPair();
                final String pksPem = toBase64(toPem(keyPairSign.getPublic()));
                final String pkePem = toBase64(toPem(keyPairEnc.getPublic()));
                RequestQueue queue = Volley.newRequestQueue(context);
                StringRequest req = new StringRequest(
                        Request.Method.POST, apiUri.resolve(ENDPOINT_REGISTER_UUID).toString(),
                        new Response.Listener<String>() {
                            @Override
                            public void onResponse(String responseStr) {
                                try {
                                    JSONObject response = new JSONObject(responseStr);
                                    if (response.getBoolean("successful")) {
                                        onRegisterUploadKeys(
                                                response.getString("uuid"),
                                                username,
                                                password,
                                                keyPairEnc,
                                                keyPairSign
                                        );
                                    } else {
                                        onRegisterFailed(new RuntimeException("Unable to retrieve uuid from server"));
                                    }
                                } catch (JSONException e) {
                                    e.printStackTrace();
                                    onRegisterFailed(e);
                                }
                            }
                        }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        onRegisterFailed(error);
                    }
                }) {
                    @Override
                    protected Map<String, String> getParams() {
                        Map<String, String> params = new HashMap<String, String>();
                        params.put("pks_pem", pksPem);
                        params.put("pke_pem", pkePem);
                        try {
                            params.put("rsa_sig", getSignature(new String[]{pksPem, pkePem}, keyPairSign.getPrivate()));
                        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | KeyStoreException
                                | CertificateException | IOException | UnrecoverableEntryException e) {
                            e.printStackTrace();
                        }
                        return params;
                    }
                };
                queue.add(req);
            }
        });
    }

    /**
     * Use the currently stored key in the keystore and set their respective uuid (i.e log in)
     *
     * @return true if the keys are successfully loaded
     */
    public boolean useStoredKeys() {
        try {
            if (!hasExistingKey()) return false;
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            X509Certificate ce = (X509Certificate) keyStore.getCertificate(KEY_ALIAS_ENC);
            X509Certificate cs = (X509Certificate) keyStore.getCertificate(KEY_ALIAS_SIGN);
            String ceUuid = ce.getSubjectDN().getName().replace("CN=", "");
            String csUuid = cs.getSubjectDN().getName().replace("CN=", "");
            if (ceUuid.equals(csUuid)) {
                uuid = ceUuid;
                return true;
            } else {
                Log.e("MimsConnect", "Unable to use stored keys, encrypting and signing key uuid mismatch.");
                return false;
            }
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            e.printStackTrace();
            return false;
        }
    }

    public void downloadExistingKey(String username, String password) {
        throw new UnsupportedOperationException();
    }

    public void addListener(RegisterEventListener listener) {
        registerEventListeners.add(listener);
    }

    public void removeListener(RegisterEventListener listener) {
        registerEventListeners.remove(listener);
    }

    /**
     * Gets the uuid of the current user. Null if current user has no uuid registered
     *
     * @return uuid
     */
    public String getUuid() {
        return uuid;
    }

    private void onRegisterUploadKeys(final String uuid, final String username, final String password,
                                      final KeyPair keyEnc, final KeyPair keySign) {
        Random r = new SecureRandom();
        byte[] salt = new byte[32];
        r.nextBytes(salt);
        SecretKey secretKey = null;
        JSONObject keyObject;
        try {
            secretKey = deriveKey(password, salt);
            keyObject = buildPrivateKeyObject(secretKey, keyEnc.getPrivate(), keySign.getPrivate(), uuid);
        } catch (InvalidKeySpecException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException
                | JSONException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            onRegisterFailed(e);
            return;
        }
        final String saltEncoded = toBase64(salt);
        final String keyObjectEncoded = toBase64(keyObject.toString());
        final String retrievalHash = toBase64(getSha256(secretKey.getEncoded()));
        RequestQueue queue = Volley.newRequestQueue(context);
        StringRequest req = new StringRequest(
                Request.Method.POST, apiUri.resolve(ENDPOINT_UPLOAD_KEYS).toString(),
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String responseStr) {
                        try {
                            JSONObject response = new JSONObject(responseStr);
                            if (response.getBoolean("successful")) {
                                storeKeyInKeystore(keyEnc, KEY_ALIAS_ENC, uuid);
                                storeKeyInKeystore(keySign, KEY_ALIAS_SIGN, uuid);
                                MimsConnect.this.uuid = uuid;
                                onRegisterSuccessful(uuid);
                            } else if (response.getString("message").equals("duplicated")) {
                                onRegisterUsernameDuplicated();
                            } else {
                                onRegisterFailed(new RuntimeException("Unable to register key on server"));
                            }
                        } catch (JSONException e) {
                            e.printStackTrace();
                            onRegisterFailed(e);
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                onRegisterFailed(error);
            }
        }) {
            @Override
            protected Map<String, String> getParams() throws AuthFailureError {
                Map<String, String> params = new HashMap<String, String>();
                params.put("username", username);
                params.put("keys", keyObjectEncoded);
                params.put("retrieval_hash", retrievalHash);
                params.put("salt", saltEncoded);
                try {
                    params.put("rsa_sig", getSignature(new String[]{
                            username, keyObjectEncoded, retrievalHash, saltEncoded
                    }, getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | KeyStoreException
                        | CertificateException | IOException | UnrecoverableEntryException e) {
                    e.printStackTrace();
                }
                return params;
            }
        };
        req.setRetryPolicy(new DefaultRetryPolicy(
                15 * 1000,
                3,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));
        queue.add(req);
    }

    private void onRegisterSuccessful(String uuid) {
        for (RegisterEventListener listener : registerEventListeners) {
            listener.onSuccess(uuid);
        }
    }

    private void onRegisterFailed(Exception e) {
        for (RegisterEventListener listener : registerEventListeners) {
            listener.onFailure(e);
        }
    }

    private void onRegisterUsernameDuplicated() {
        for (RegisterEventListener listener : registerEventListeners) {
            listener.onDuplicated();
        }
    }

    private SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeSpec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(DERIVE_ALGRO);
        return factory.generateSecret(pbeSpec);
    }

    private byte[] wrapPrivateKey(SecretKey encryptKey, PrivateKey keyBeingWraped)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        SecretKeySpec spec = new SecretKeySpec(encryptKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.WRAP_MODE, spec);
        return cipher.wrap(keyBeingWraped);
    }

    private PrivateKey unwrapPrivateKey(SecretKey decryptKey, byte[] keyBeingUnwraped, String unwrapKeyAlgro)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec spec = new SecretKeySpec(decryptKey.getEncoded(), "AES");
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.UNWRAP_MODE, spec);
        return (PrivateKey) cipher.unwrap(keyBeingUnwraped, unwrapKeyAlgro, Cipher.PRIVATE_KEY);
    }

    private JSONObject buildPrivateKeyObject(
            SecretKey secretKey, PrivateKey rsaEncryptKey, PrivateKey rsaSignKey, String uuid)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            JSONException {
        JSONObject json = new JSONObject();
        json.put("ske", toBase64(wrapPrivateKey(secretKey, rsaEncryptKey)));
        json.put("sks", toBase64(wrapPrivateKey(secretKey, rsaSignKey)));
        json.put("uuid", uuid);
        return json;
    }

    private byte[] getSha256(byte[] bytes) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
        return digest.digest(bytes);
    }

    private boolean storeKeyInKeystore(KeyPair keyPair, String keyAlias, String uuid) {
        if (!Objects.equals(keyAlias, KEY_ALIAS_ENC) && !keyAlias.equals(KEY_ALIAS_SIGN)) {
            return false;
        }
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyAlias.equals(KEY_ALIAS_ENC)) {
                keyStore.setEntry(
                        KEY_ALIAS_ENC,
                        new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
                                new java.security.cert.Certificate[]{genSelfSignedCert(keyPair, KEY_ALIAS_ENC, uuid)}),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_DECRYPT)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                                .build()
                );
            } else if (keyAlias.equals(KEY_ALIAS_SIGN)) {
                keyStore.setEntry(
                        KEY_ALIAS_SIGN,
                        new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
                                new java.security.cert.Certificate[]{genSelfSignedCert(keyPair, KEY_ALIAS_SIGN, uuid)}),
                        new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
                                .build()
                );
            }
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | OperatorCreationException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private PrivateKey getPrivateKeyFromKeystore(String keyAlias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            return (PrivateKey) keyStore.getKey(keyAlias, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | UnrecoverableKeyException e) {
            e.printStackTrace();
            return null;
        }
    }

    private PublicKey getPublicKeyFromKeystore(String keyAlias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            java.security.cert.Certificate c = keyStore.getCertificate(keyAlias);
            if (c == null) return null;
            /* Work around for a Android 6.0 bug
             * https://developer.android.com/reference/android/security/keystore/KeyProtection#known-issues
             * */
            return KeyFactory.getInstance(c.getPublicKey().getAlgorithm()).generatePublic(
                    new X509EncodedKeySpec(c.getPublicKey().getEncoded())
            );
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }

    }

    /**
     * This is for use with the Android Keystore
     * The UUID is used to name that certificate for later retrieval
     */
    private Certificate genSelfSignedCert(KeyPair keyPair, String keyAlias, String uuid)
            throws OperatorCreationException, CertificateException {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);
        Date currentDate = new Date(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.YEAR, 100);
        Date expireDate = calendar.getTime();
        X500Name dnName = new X500Name("CN=" + uuid);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dnName,
                new BigInteger(Long.toString(currentDate.getTime())),
                currentDate,
                expireDate,
                dnName,
                keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider(bcProvider)
                .build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    /**
     * Get a signature for a given number of request parameters in String
     * Returns null if private key is not set
     *
     * @param params The parameters in String to be sent to the server
     * @return A base64 encoded signature ready to be sent to the server
     * @throws NoSuchAlgorithmException Encryption scheme not supported by this client
     * @throws InvalidKeyException      A valid key is not provided
     * @throws SignatureException       Signing failed
     */
    private String getSignature(String[] params, PrivateKey privateSignKey)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, KeyStoreException,
            CertificateException, IOException, UnrecoverableEntryException {
        Arrays.sort(params); // Server requires the params to be sorted first
        Signature signature = Signature.getInstance(RSA_SIGN_SCHEME);
        signature.initSign(privateSignKey);
        String paramsStr = TextUtils.join("", params);
        signature.update(paramsStr.getBytes(StandardCharsets.UTF_8));
        byte[] bytes = signature.sign();
        return toBase64(bytes);
    }

    private static String toBase64(byte[] bytes) {
        return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
    }

    private static String toBase64(String str) {
        return toBase64(str.getBytes(StandardCharsets.UTF_8));
    }

    private static String toPem(PublicKey key) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----");
        String encoded = android.util.Base64.encodeToString(key.getEncoded(), android.util.Base64.NO_WRAP);
        for (int i = 0; i < encoded.length(); i++) {
            if (i % 64 == 0) {
                pem.append('\n');
            }
            pem.append(encoded.charAt(i));
        }
        pem.append("\n-----END PUBLIC KEY-----");
        return pem.toString();
    }

    private static PublicKey fromPem(String pem, String algorithm)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        pem = pem.replace("-----BEGIN PUBLIC KEY-----\n", "")
                .replace("-----END PUBLIC KEY-----", "");
        byte[] decoded = android.util.Base64.decode(pem, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(spec);
    }
}