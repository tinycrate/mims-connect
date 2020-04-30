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
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
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

    /**
     * Event handler for downloading existing key
     * Register one using addListener();
     */
    public interface DownloadKeyEventListener {
        /** The key is downloaded and imported successfully */
        void onSuccessfulImport(String uuid);

        /** The key fails to decrypt, probably caused by a wrong username / password */
        void onFailedImport();

        /** The key fails to download, or other error occurs */
        void onError(Exception error);
    }

    private final String TAG = "MimsConnect";

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
    private final String ENDPOINT_GET_SALT = "/get_key_salt";
    private final String ENDPOINT_DOWNLOAD_KEYS = "/download_keys";
    private final String ENDPOINT_REQUEST_PUBLIC_KEYS = "/request_public_keys";

    /* Key names for keystore retrieval */
    private final String KEY_ALIAS_ENC = "KEY_ALIAS_ENC";
    private final String KEY_ALIAS_SIGN = "KEY_ALIAS_SIGN";

    /* Event listeners */
    private List<RegisterEventListener> registerEventListeners = new ArrayList<>();
    private List<DownloadKeyEventListener> downloadKeyEventListeners = new ArrayList<>();

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
    public boolean hasStoredKeys()
            throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
        keyStore.load(null);
        return keyStore.containsAlias(KEY_ALIAS_SIGN) && keyStore.containsAlias(KEY_ALIAS_ENC);
    }

    /**
     * Generates public private key pairs for signature and encryption and register it on server
     * WARNING: This will overwrite the current stored private key, if any
     *
     * @throws NoSuchAlgorithmException Encryption scheme not supported by this client
     */
    public void registerNewKeys(final String username, final String password) {
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
                    Log.e(TAG, "Error generating RSA keys", e);
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
                                    Log.e(TAG, "Error parsing key register response", e);
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
                        Map<String, String> params = new HashMap<>();
                        params.put("pks_pem", pksPem);
                        params.put("pke_pem", pkePem);
                        try {
                            params.put("rsa_sig", getSignature(new String[]{pksPem, pkePem}, keyPairSign.getPrivate()));
                        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                            Log.e(TAG, "Error generating signature", e);
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
            if (!hasStoredKeys()) return false;
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
            keyStore.load(null);
            X509Certificate ce = (X509Certificate) keyStore.getCertificate(KEY_ALIAS_ENC);
            X509Certificate cs = (X509Certificate) keyStore.getCertificate(KEY_ALIAS_SIGN);
            String ceUuid = ce.getSubjectDN().getName().substring(3);
            String csUuid = cs.getSubjectDN().getName().substring(3);
            if (ceUuid.equals(csUuid)) {
                uuid = ceUuid;
                return true;
            } else {
                Log.e(TAG, "Unable to use stored keys, encrypting and signing key uuid mismatch.");
                return false;
            }
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            Log.e(TAG, "Error using stored keys", e);
            return false;
        }
    }


    /**
     * This deletes the private keys stored on the device
     */
    public void deleteStoredKeys() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS_ENC);
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            Log.i(TAG, "Encryption key cannot be deleted. Probably does not exist.");
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
            keyStore.load(null);
            keyStore.deleteEntry(KEY_ALIAS_SIGN);
        } catch (CertificateException | NoSuchAlgorithmException | IOException | KeyStoreException e) {
            Log.i(TAG, "Signing key cannot be deleted. Probably does not exist.");
        }
        this.uuid = null;
    }

    public void downloadExistingKey(final String username, final String password) {
        ExecutorService threadPool = Executors.newCachedThreadPool();
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                RequestQueue queue = Volley.newRequestQueue(context);
                StringRequest req = new StringRequest(
                        Request.Method.POST, apiUri.resolve(ENDPOINT_GET_SALT).toString(),
                        new Response.Listener<String>() {
                            @Override
                            public void onResponse(String responseStr) {
                                try {
                                    JSONObject response = new JSONObject(responseStr);
                                    if (response.getBoolean("successful")) {
                                        onDownloadExistingKeys(
                                                username,
                                                password,
                                                fromBase64(response.getString("salt"))
                                        );
                                    } else if (response.get("message").equals("nouser")) {
                                        onDownloadKeyFailed();
                                    } else {
                                        onDownloadKeyError(new RuntimeException("Unable to retrieve salt from server"));
                                    }
                                } catch (JSONException e) {
                                    Log.e(TAG, "Error parsing salt", e);
                                    onDownloadKeyError(e);
                                }
                            }
                        }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        onDownloadKeyError(error);
                    }
                }) {
                    @Override
                    protected Map<String, String> getParams() {
                        Map<String, String> params = new HashMap<>();
                        params.put("username", username);
                        return params;
                    }
                };
                queue.add(req);
            }
        });
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
        byte[] salt = generateBytes(32);
        SecretKey secretKey = null;
        byte[] keyObject;
        try {
            secretKey = deriveKey(password, salt);
            keyObject = buildPrivateKeyObject(secretKey, keyEnc.getPrivate(), keySign.getPrivate(), uuid);
        } catch (InvalidKeySpecException | IllegalBlockSizeException | InvalidKeyException | NoSuchPaddingException
                | JSONException | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | BadPaddingException e) {
            Log.e(TAG, "Error encrypting keys", e);
            onRegisterFailed(e);
            return;
        }
        final String saltEncoded = toBase64(salt);
        final String keyObjectEncoded = toBase64(keyObject);
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
                                boolean keyEncSuccessful = storeKeyInKeystore(keyEnc, KEY_ALIAS_ENC, uuid);
                                boolean keySignSuccessful = storeKeyInKeystore(keySign, KEY_ALIAS_SIGN, uuid);
                                if (keyEncSuccessful && keySignSuccessful) {
                                    MimsConnect.this.uuid = uuid;
                                    onRegisterSuccessful(uuid);
                                } else {
                                    onRegisterFailed(new RuntimeException("Unable to import keys"));
                                }
                            } else if (response.getString("message").equals("duplicated")) {
                                onRegisterUsernameDuplicated();
                            } else {
                                onRegisterFailed(new RuntimeException("Unable to register key on server"));
                            }
                        } catch (JSONException e) {
                            Log.e(TAG, "Error parsing upload key response", e);
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
                Map<String, String> params = new HashMap<>();
                params.put("username", username);
                params.put("keys", keyObjectEncoded);
                params.put("retrieval_hash", retrievalHash);
                params.put("salt", saltEncoded);
                try {
                    params.put("rsa_sig", getSignature(new String[]{
                            username, keyObjectEncoded, retrievalHash, saltEncoded
                    }, getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    Log.e(TAG, "Error generating signature", e);
                }
                return params;
            }
        };
        req.setRetryPolicy(new DefaultRetryPolicy(
                10 * 1000,
                3,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));
        queue.add(req);
    }

    private void onDownloadExistingKeys(final String username, String password, byte[] salt) {
        final SecretKey secretKey;
        try {
            secretKey = deriveKey(password, salt);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "Error deriving key", e);
            onDownloadKeyError(e);
            return;
        }
        final String retrievalHash = toBase64(getSha256(secretKey.getEncoded()));
        RequestQueue queue = Volley.newRequestQueue(context);
        StringRequest req = new StringRequest(
                Request.Method.POST, apiUri.resolve(ENDPOINT_DOWNLOAD_KEYS).toString(),
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String responseStr) {
                        try {
                            JSONObject response = new JSONObject(responseStr);
                            if (response.getBoolean("successful")) {
                                onParseDownloadedKeys(secretKey, response.getString("keys"));
                            } else if (response.getString("message").equals("noentries")) {
                                onDownloadKeyFailed();
                            } else {
                                onDownloadKeyError(new RuntimeException("Unable to retrieve keys from server"));
                            }
                        } catch (JSONException e) {
                            Log.e(TAG, "Error parsing response", e);
                            onDownloadKeyError(e);
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                onDownloadKeyError(error);
            }
        }) {
            @Override
            protected Map<String, String> getParams() {
                Map<String, String> params = new HashMap<>();
                params.put("username", username);
                params.put("retrieval_hash", retrievalHash);
                return params;
            }
        };
        queue.add(req);
    }

    private void onParseDownloadedKeys(SecretKey secretKey, String b64Keys) {
        JSONObject privateKeyObject = null;
        try {
            privateKeyObject = decryptPrivateKeyObject(secretKey, fromBase64(b64Keys));
            PrivateKey enc = unwrapPrivateKey(
                    secretKey,
                    fromBase64(privateKeyObject.getString("ske")),
                    RSA_ENC_ALGRO
            );
            PrivateKey sign = unwrapPrivateKey(
                    secretKey,
                    fromBase64(privateKeyObject.getString("sks")),
                    RSA_SIGN_ALGRO
            );
            String uuid = privateKeyObject.getString("uuid");
            onImportDownloadedKeys(enc, sign, uuid);
        } catch (JSONException | NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException
                | IllegalBlockSizeException | BadPaddingException | InvalidKeyException e) {
            Log.e(TAG, "Error parsing retrieved keys", e);
            onDownloadKeyError(e);
            return;
        }
    }

    private void onImportDownloadedKeys(final PrivateKey encKey, final PrivateKey signKey, final String uuid) {
        RequestQueue queue = Volley.newRequestQueue(context);
        StringRequest req = new StringRequest(
                Request.Method.POST, apiUri.resolve(ENDPOINT_REQUEST_PUBLIC_KEYS).toString(),
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String responseStr) {
                        try {
                            JSONObject response = new JSONObject(responseStr);
                            if (response.getBoolean("successful")) {
                                JSONObject keys = response.getJSONObject("keys");
                                PublicKey encPublic = fromPem(keys.getString("pke"), RSA_ENC_ALGRO);
                                PublicKey signPublic = fromPem(keys.getString("pks"), RSA_SIGN_ALGRO);
                                KeyPair encPair = new KeyPair(encPublic, encKey);
                                KeyPair signPair = new KeyPair(signPublic, signKey);
                                boolean encSuccessful = storeKeyInKeystore(encPair, KEY_ALIAS_ENC, uuid);
                                boolean signSuccessful = storeKeyInKeystore(signPair, KEY_ALIAS_SIGN, uuid);
                                if (encSuccessful && signSuccessful) {
                                    MimsConnect.this.uuid = uuid;
                                    onDownloadKeySuccessful(uuid);
                                } else {
                                    onDownloadKeyError(new RuntimeException("Unable to import keys"));
                                }
                            } else {
                                onDownloadKeyError(new RuntimeException("Unable to retrieve public keys from server"));
                            }
                        } catch (JSONException | NoSuchAlgorithmException | InvalidKeySpecException e) {
                            Log.e(TAG, "Error parsing response", e);
                            onDownloadKeyError(e);
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                onDownloadKeyError(error);
            }
        }) {
            @Override
            protected Map<String, String> getParams() {
                Map<String, String> params = new HashMap<>();
                params.put("requesting_uuid", uuid);
                params.put("requester_uuid", uuid);
                try {
                    params.put("rsa_sig", getSignature(new String[]{uuid, uuid}, signKey));
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    Log.e(TAG, "Error generating signature", e);
                }
                return params;
            }
        };
        req.setRetryPolicy(new DefaultRetryPolicy(
                10 * 1000,
                3,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));
        queue.add(req);
    }

    private SecretKey deriveKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        PBEKeySpec pbeSpec = new PBEKeySpec(password.toCharArray(), salt, 100000, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(DERIVE_ALGRO);
        return factory.generateSecret(pbeSpec);
    }

    private byte[] wrapPrivateKey(SecretKey encryptKey, PrivateKey keyBeingWraped)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException,
            InvalidAlgorithmParameterException {
        byte[] iv = generateBytes(12);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.WRAP_MODE, encryptKey, spec);
        return concatBytes(iv, cipher.wrap(keyBeingWraped));
    }

    private PrivateKey unwrapPrivateKey(SecretKey decryptKey, byte[] keyBeingUnwraped, String unwrapKeyAlgro)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException {
        GCMParameterSpec spec = new GCMParameterSpec(128, keyBeingUnwraped, 0, 12);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.UNWRAP_MODE, decryptKey, spec);
        return (PrivateKey) cipher.unwrap(
                Arrays.copyOfRange(keyBeingUnwraped, 12, keyBeingUnwraped.length),
                unwrapKeyAlgro,
                Cipher.PRIVATE_KEY
        );
    }

    private byte[] encryptWithKey(SecretKey key, byte[] bytesBeingEncrypted)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, InvalidAlgorithmParameterException {
        byte[] iv = generateBytes(12);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        return concatBytes(iv, cipher.doFinal(bytesBeingEncrypted));
    }

    private byte[] decryptWithKey(SecretKey key, byte[] bytesBeingDecrypted)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        GCMParameterSpec spec = new GCMParameterSpec(128, bytesBeingDecrypted, 0, 12);
        Cipher cipher = Cipher.getInstance(ENCRYPT_ALGRO);
        cipher.init(Cipher.UNWRAP_MODE, key, spec);
        return cipher.doFinal(bytesBeingDecrypted, 12, bytesBeingDecrypted.length - 12);
    }

    private byte[] buildPrivateKeyObject(
            SecretKey secretKey, PrivateKey rsaEncryptKey, PrivateKey rsaSignKey, String uuid)
            throws IllegalBlockSizeException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            JSONException, InvalidAlgorithmParameterException, BadPaddingException {
        JSONObject json = new JSONObject();
        json.put("ske", toBase64(wrapPrivateKey(secretKey, rsaEncryptKey)));
        json.put("sks", toBase64(wrapPrivateKey(secretKey, rsaSignKey)));
        json.put("uuid", uuid);
        return encryptWithKey(secretKey, json.toString().getBytes());
    }

    private JSONObject decryptPrivateKeyObject(SecretKey key, byte[] encryptedObject)
            throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidKeyException, JSONException {
        return new JSONObject(new String(decryptWithKey(key, encryptedObject), StandardCharsets.UTF_8));
    }

    private byte[] generateBytes(int size) {
        Random r = new SecureRandom();
        byte[] bytes = new byte[size];
        r.nextBytes(bytes);
        return bytes;
    }

    private byte[] concatBytes(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    private byte[] getSha256(byte[] bytes) {
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "Error getting sha256", e);
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
            keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
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
            Log.e(TAG, "Error storing keys in keystore", e);
            return false;
        }
        return true;
    }

    private PrivateKey getPrivateKeyFromKeystore(String keyAlias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
            keyStore.load(null);
            return (PrivateKey) keyStore.getKey(keyAlias, null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException
                | UnrecoverableKeyException e) {
            Log.e(TAG, "Error retrieving keys", e);
            return null;
        }
    }

    private PublicKey getPublicKeyFromKeystore(String keyAlias) {
        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance(KEYSTORE_ANDROID);
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
            Log.e(TAG, "Error retrieving keys", e);
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
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Arrays.sort(params); // Server requires the params to be sorted first
        Signature signature = Signature.getInstance(RSA_SIGN_SCHEME);
        signature.initSign(privateSignKey);
        String paramsStr = TextUtils.join("", params);
        signature.update(paramsStr.getBytes(StandardCharsets.UTF_8));
        byte[] bytes = signature.sign();
        return toBase64(bytes);
    }

    private static String toBase64(byte[] bytes) {
        return Base64.encodeToString(bytes, Base64.NO_WRAP);
    }

    private static String toBase64(String str) {
        return toBase64(str.getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] fromBase64(String base64) {
        return Base64.decode(base64, Base64.DEFAULT);
    }

    private static String toPem(PublicKey key) {
        StringBuilder pem = new StringBuilder();
        pem.append("-----BEGIN PUBLIC KEY-----");
        String encoded = Base64.encodeToString(key.getEncoded(), Base64.NO_WRAP);
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
        byte[] decoded = Base64.decode(pem, Base64.DEFAULT);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(spec);
    }

    public void addListener(RegisterEventListener listener) {
        registerEventListeners.add(listener);
    }

    public void addListener(DownloadKeyEventListener listener) {
        downloadKeyEventListeners.add(listener);
    }

    public void removeListener(RegisterEventListener listener) {
        registerEventListeners.remove(listener);
    }

    public void removeListener(DownloadKeyEventListener listener) {
        downloadKeyEventListeners.remove(listener);
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

    private void onDownloadKeySuccessful(String uuid) {
        for (DownloadKeyEventListener listener : downloadKeyEventListeners) {
            listener.onSuccessfulImport(uuid);
        }
    }

    private void onDownloadKeyFailed() {
        for (DownloadKeyEventListener listener : downloadKeyEventListeners) {
            listener.onFailedImport();
        }
    }

    private void onDownloadKeyError(Exception e) {
        for (DownloadKeyEventListener listener : downloadKeyEventListeners) {
            listener.onError(e);
        }
    }
}