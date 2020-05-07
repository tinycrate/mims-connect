package com.tiny.mims.connect;

import android.content.Context;
import android.os.Looper;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.text.TextUtils;
import android.util.Base64;
import android.util.Log;
import com.android.volley.*;
import com.android.volley.toolbox.RequestFuture;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import io.socket.client.Ack;
import io.socket.client.IO;
import io.socket.client.Socket;
import io.socket.emitter.Emitter;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.json.JSONArray;
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
import java.util.concurrent.*;

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

    /**
     * Event handler for sending message
     * Register one using addListener();
     */
    public interface SendMessageEventListener {
        /**
         * The message is sent successfully
         *
         * @param messageId The id of the message
         */
        void onSent(String messageId);

        /**
         * Error occurred while sending. It could be a network error
         *
         * @param messageId The id of the message
         * @param error     The error
         */
        void onFailed(String messageId, Exception error);

        /**
         * The recipient of the message does not exist
         *
         * @param messageId The id of the message
         */
        void onFailedNoUser(String messageId);
    }

    /**
     * Event handler for receiving message
     * Register one using addListener();
     */
    public interface ChatServiceEventListener {
        /**
         * A message is received
         *
         * @param senderUuid The uuid of the sender
         * @param message    The message
         */
        void onMessageReceive(String senderUuid, String message);

        /**
         * Called if a message is received but cannot be decrypted
         * The message will be dropped as a result
         *
         * @param senderUuid The (claimed) sender of such message
         */
        void onMessageDecryptFailed(String senderUuid);

        /** Connected to the chat service */
        void onConnected();

        /** Disconnected form the chat service */
        void onDisconnect();

        /**
         * Disconnected form the chat service due to an error
         * It will also be called if the connection is not successful
         */
        void onDisconnectWithError(Exception e);
    }

    /**
     * Event handler for updating user info
     */
    public interface UserInfoUpdateListener {
        String TYPE_DISPLAY_NAME = "display_name";
        String TYPE_DISPLAY_STATUS = "display_status";

        /** Called when update is successful */
        void onSuccess(String updateType);

        /** Called when update is failed */
        void onFailure(String updateType, Exception e);
    }

    public static class PublicKeys {
        public PublicKey publicEncryptKey;
        public PublicKey publicSignKey;

        public PublicKeys(PublicKey publicEncryptKey, PublicKey publicSignKey) {
            this.publicEncryptKey = publicEncryptKey;
            this.publicSignKey = publicSignKey;
        }
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
    private final String ENDPOINT_REGISTER_UUID = "register_uuid";
    private final String ENDPOINT_UPLOAD_KEYS = "upload_keys";
    private final String ENDPOINT_GET_SALT = "get_key_salt";
    private final String ENDPOINT_DOWNLOAD_KEYS = "download_keys";
    private final String ENDPOINT_REQUEST_PUBLIC_KEYS = "request_public_keys";
    private final String ENDPOINT_SEND_MESSAGE = "send_message";
    private final String ENDPOINT_SOCKET_IO = "socket.io";
    private final String ENDPOINT_UPDATE_DISPLAY_NAME = "set_display_name";
    private final String ENDPOINT_UPDATE_DISPLAY_STATUS = "set_display_status";
    private final String ENDPOINT_UPDATE_DISPLAY_ICON = "set_display_icon";


    /* Key names for keystore retrieval */
    private final String KEY_ALIAS_ENC = "KEY_ALIAS_ENC";
    private final String KEY_ALIAS_SIGN = "KEY_ALIAS_SIGN";

    /* Event listeners */
    private List<RegisterEventListener> registerEventListeners = new ArrayList<>();
    private List<DownloadKeyEventListener> downloadKeyEventListeners = new ArrayList<>();
    private List<SendMessageEventListener> sendMessageEventListeners = new ArrayList<>();
    private List<ChatServiceEventListener> chatServiceEventListeners = new ArrayList<>();
    private List<UserInfoUpdateListener> userInfoUpdateEventListeners = new ArrayList<>();

    /* User information */
    private String uuid = null;

    /* Volley queue and threadpool */
    private final RequestQueue requestQueue;
    private final ExecutorService threadPool = Executors.newCachedThreadPool();

    /* Socket io */
    private io.socket.client.Socket socketIoClient = null;

    /* Cache */
    private ConcurrentHashMap<String, PublicKeys> publicKeyCache = new ConcurrentHashMap<>();

    /**
     * Creates an instance to connect and interface with the MIMS server
     *
     * @param context The Android context, get via getApplicationContext()
     * @param apiUrl  The URL to the api, must specify protocol (https://)
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
        this.apiUri = new URI(apiUrl + "/");
        this.context = context;
        this.requestQueue = Volley.newRequestQueue(context);
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
                final String pksPem = toPem(keyPairSign.getPublic());
                final String pkePem = toPem(keyPairEnc.getPublic());
                final String rsaSig;
                try {
                    rsaSig = getSignature(new String[]{pksPem, pkePem}, keyPairSign.getPrivate());
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    Log.e(TAG, "Error generating signature", e);
                    onRegisterFailed(e);
                    return;
                }
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
                        params.put("rsa_sig", rsaSig);
                        return params;
                    }
                };
                requestQueue.add(req);
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
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
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
                requestQueue.add(req);
            }
        });
    }

    /**
     * Sends a message to a user, returns immediately
     * To check whether the message is sent, register a SendMessageEventListener using addListener()
     *
     * @param recipientUuid The uuid of the user
     * @param message       The message
     * @return The id of the message being processed
     */
    public String sendMessage(final String recipientUuid, final String message) {
        final String messageId = UUID.randomUUID().toString();
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                PublicKeys recipientKeys = getPublicKeysFromServer(recipientUuid);
                if (recipientKeys == null) {
                    onSendMessageFailed(messageId, new Exception("Error retrieving public keys from server"));
                    return;
                }
                if (recipientKeys.publicEncryptKey == null || recipientKeys.publicSignKey == null) {
                    Log.w(TAG, "No user found for uuid " + recipientUuid);
                    onSendMessageFailedNoUser(messageId);
                    return;
                }
                try {
                    SecretKey aesKey = generateAESKey();
                    final String messageEncrypted = toBase64(encryptWithKey(aesKey, message.getBytes()));
                    final String wrapedAESKey = toBase64(wrapAESKey(recipientKeys.publicEncryptKey, aesKey));
                    final String rsaSig;
                    try {
                        rsaSig = getSignature(
                                new String[]{recipientUuid, wrapedAESKey, messageEncrypted, uuid},
                                getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)
                        );
                    } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                        Log.e(TAG, "Error generating signature", e);
                        onSendMessageFailed(messageId, e);
                        return;
                    }
                    StringRequest req = new StringRequest(
                            Request.Method.POST, apiUri.resolve(ENDPOINT_SEND_MESSAGE).toString(),
                            new Response.Listener<String>() {
                                @Override
                                public void onResponse(String responseStr) {
                                    try {
                                        JSONObject response = new JSONObject(responseStr);
                                        if (response.getBoolean("successful")) {
                                            onSendMessageSuccessful(messageId);
                                        } else {
                                            onSendMessageFailed(
                                                    messageId,
                                                    new RuntimeException("Server rejected the message")
                                            );
                                        }
                                    } catch (JSONException e) {
                                        Log.e(TAG, "Error parsing salt", e);
                                        onSendMessageFailed(messageId, e);
                                    }
                                }
                            }, new Response.ErrorListener() {
                        @Override
                        public void onErrorResponse(VolleyError error) {
                            onSendMessageFailed(messageId, error);
                        }
                    }) {
                        @Override
                        protected Map<String, String> getParams() {
                            Map<String, String> params = new HashMap<>();
                            params.put("recipient_uuid", recipientUuid);
                            params.put("aes_key_encrypted", wrapedAESKey);
                            params.put("message", messageEncrypted);
                            params.put("sender_uuid", uuid);
                            params.put("rsa_sig", rsaSig);
                            return params;
                        }
                    };
                    requestQueue.add(req);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
                        | BadPaddingException | IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
                    Log.e(TAG, "Error encrypting message", e);
                    onSendMessageFailed(messageId, e);
                    return;
                }
            }
        });
        return messageId;
    }

    public void updateUserDisplayName(final String displayName) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                final String rsaSig;
                try {
                     rsaSig = getSignature(
                            new String[]{uuid, displayName},
                            getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)
                    );
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_NAME, e);
                    return;
                }
                StringRequest req = new StringRequest(
                        Request.Method.POST, apiUri.resolve(ENDPOINT_UPDATE_DISPLAY_NAME).toString(),
                        new Response.Listener<String>() {
                            @Override
                            public void onResponse(String responseStr) {
                                try {
                                    JSONObject response = new JSONObject(responseStr);
                                    if (response.getBoolean("successful")) {
                                        onUserInfoUpdateSuccess(UserInfoUpdateListener.TYPE_DISPLAY_NAME);
                                    } else {
                                        onUserInfoUpdateFailed(
                                                UserInfoUpdateListener.TYPE_DISPLAY_NAME,
                                                new RuntimeException("Server rejected the message")
                                        );
                                    }
                                } catch (JSONException e) {
                                    Log.e(TAG, "Error parsing response", e);
                                    onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_NAME, e);
                                }
                            }
                        }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_NAME, error);
                    }
                }) {
                    @Override
                    protected Map<String, String> getParams() {
                        Map<String, String> params = new HashMap<>();
                        params.put("uuid", uuid);
                        params.put("display_name", displayName);
                        params.put("rsa_sig", rsaSig);
                        return params;
                    }
                };
                requestQueue.add(req);
            }
        });
    }

    public void updateUserDisplayStatus(final String displayStatus) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                final String rsaSig;
                try {
                    rsaSig = getSignature(
                            new String[]{uuid, displayStatus},
                            getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)
                    );
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
                    onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_STATUS, e);
                    return;
                }
                StringRequest req = new StringRequest(
                        Request.Method.POST, apiUri.resolve(ENDPOINT_UPDATE_DISPLAY_STATUS).toString(),
                        new Response.Listener<String>() {
                            @Override
                            public void onResponse(String responseStr) {
                                try {
                                    JSONObject response = new JSONObject(responseStr);
                                    if (response.getBoolean("successful")) {
                                        onUserInfoUpdateSuccess(UserInfoUpdateListener.TYPE_DISPLAY_STATUS);
                                    } else {
                                        onUserInfoUpdateFailed(
                                                UserInfoUpdateListener.TYPE_DISPLAY_STATUS,
                                                new RuntimeException("Server rejected the message")
                                        );
                                    }
                                } catch (JSONException e) {
                                    Log.e(TAG, "Error parsing response", e);
                                    onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_STATUS, e);
                                }
                            }
                        }, new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        onUserInfoUpdateFailed(UserInfoUpdateListener.TYPE_DISPLAY_STATUS, error);
                    }
                }) {
                    @Override
                    protected Map<String, String> getParams() {
                        Map<String, String> params = new HashMap<>();
                        params.put("uuid", uuid);
                        params.put("display_status", displayStatus);
                        params.put("rsa_sig", rsaSig);
                        return params;
                    }
                };
                requestQueue.add(req);
            }
        });
    }

    /**
     * Connect to chat service and receive messages
     * Returning true does not mean it has successfully connected
     * You should register an event handler to handle chat events
     *
     * @return True if the request is successful
     */
    public boolean connectToChatService() {
        if (uuid == null) return false;
        if (socketIoClient != null) socketIoClient.close();
        IO.Options options = new IO.Options();
        URI socketIoApi = apiUri.resolve(ENDPOINT_SOCKET_IO);
        options.path = socketIoApi.getPath();
        URI apiRoot = socketIoApi.resolve("/");
        socketIoClient = IO.socket(apiRoot, options);
        socketIoClient.on(Socket.EVENT_CONNECT, new Emitter.Listener() {
            @Override
            public void call(Object... args) {
                onChatServiceSubscribeMessage();
            }
        });
        socketIoClient.on(Socket.EVENT_DISCONNECT, new Emitter.Listener() {
            @Override
            public void call(Object... args) {
                onChatServiceDisconnect();
            }
        });
        socketIoClient.on("on_message_received", new Emitter.Listener() {
            @Override
            public void call(Object... args) {
                JSONArray messages = (JSONArray) args[0];
                for (int i = 0; i < messages.length(); i++) {
                    try {
                        JSONObject message = messages.getJSONObject(i);
                        String senderUuid = message.getString("sender_uuid");
                        String messageContent = message.getString("message");
                        String b64AesKey = message.getString("aes_key_encrypted");
                        String rsaSig = message.getString("rsa_sig");
                        onDecryptMessage(senderUuid, messageContent, b64AesKey, rsaSig);
                    } catch (JSONException e) {
                        Log.e(TAG, "Unable to parse message, skipping...");
                    }
                }
                Ack ack = (Ack) args[args.length - 1];
                ack.call();
            }
        });
        socketIoClient.connect();
        return true;
    }

    /**
     * Gets the uuid of the current user. Null if current user has no uuid registered
     *
     * @return uuid
     */
    public String getUuid() {
        return uuid;
    }

    private void onDecryptMessage(final String senderUuid, final String message, final String b64AesKey,
                                  final String rsaSig) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    PublicKeys publicKeys = null;
                    for (int i = 0; i < 5; i++) {
                        publicKeys = getPublicKeysFromServer(senderUuid);
                        if (publicKeys != null) break;
                    }
                    if (publicKeys == null || publicKeys.publicSignKey == null || publicKeys.publicEncryptKey == null) {
                        Log.w(TAG, "Unable to retrieve public key info of sender for verification, dropping...");
                        onMessageDecryptFailed(senderUuid);
                        return;
                    }
                    if (!verifySignature(
                            new String[]{uuid, b64AesKey, message, senderUuid},
                            publicKeys.publicSignKey,
                            fromBase64(rsaSig)
                    )) {
                        Log.w(TAG, "Message verification failed");
                        onMessageDecryptFailed(senderUuid);
                        return;
                    }
                    SecretKey aesKey = unwrapAESKeyUsingStoredPrivate(fromBase64(b64AesKey));
                    String messageDecrypted = new String(
                            decryptWithKey(aesKey, fromBase64(message)),
                            StandardCharsets.UTF_8
                    );
                    onReceiveMessage(senderUuid, messageDecrypted);
                } catch (NoSuchPaddingException | InvalidKeyException | NoSuchAlgorithmException
                        | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                        | SignatureException e) {
                    Log.e(TAG, "Unable to decrypt message, dropping...");
                    onMessageDecryptFailed(senderUuid);
                    return;
                }
            }
        });
    }

    private void onChatServiceSubscribeMessage() {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                try {
                    String rsaSig = getSignature(new String[]{uuid}, getPrivateKeyFromKeystore(KEY_ALIAS_SIGN));
                    JSONObject json = new JSONObject();
                    json.put("uuid", uuid);
                    json.put("rsa_sig", rsaSig);
                    socketIoClient.emit("subscribe_messages", json);
                    onChatServiceConnect();
                } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | JSONException e) {
                    Log.e(TAG, "Error subscribing message");
                    socketIoClient.disconnect();
                }
            }
        });
    }

    private void onRegisterUploadKeys(final String uuid, final String username, final String password,
                                      final KeyPair keyEnc, final KeyPair keySign) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                byte[] salt = generateBytes(32);
                SecretKey secretKey = null;
                byte[] keyObject;
                try {
                    secretKey = deriveKey(password, salt);
                    keyObject = buildPrivateKeyObject(secretKey, keyEnc.getPrivate(), keySign.getPrivate(), uuid);
                } catch (InvalidKeySpecException | IllegalBlockSizeException | InvalidKeyException
                        | NoSuchPaddingException | JSONException | NoSuchAlgorithmException
                        | InvalidAlgorithmParameterException | BadPaddingException e) {
                    Log.e(TAG, "Error encrypting keys", e);
                    onRegisterFailed(e);
                    return;
                }
                final String saltEncoded = toBase64(salt);
                final String keyObjectEncoded = toBase64(keyObject);
                final String retrievalHash = toBase64(getSha256(secretKey.getEncoded()));
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
                        return params;
                    }
                };
                req.setRetryPolicy(new DefaultRetryPolicy(
                        10 * 1000,
                        3,
                        DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
                ));
                requestQueue.add(req);
            }
        });
    }

    private void onDownloadExistingKeys(final String username, final String password, final byte[] salt) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
                final SecretKey secretKey;
                try {
                    secretKey = deriveKey(password, salt);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                    Log.e(TAG, "Error deriving key", e);
                    onDownloadKeyError(e);
                    return;
                }
                final String retrievalHash = toBase64(getSha256(secretKey.getEncoded()));
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
                requestQueue.add(req);
            }
        });
    }

    private void onParseDownloadedKeys(final SecretKey secretKey, final String b64Keys) {
        threadPool.submit(new Runnable() {
            @Override
            public void run() {
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
                } catch (JSONException | NoSuchPaddingException | InvalidAlgorithmParameterException
                        | NoSuchAlgorithmException | IllegalBlockSizeException | BadPaddingException
                        | InvalidKeyException e) {
                    Log.e(TAG, "Error parsing retrieved keys", e);
                    onDownloadKeyError(e);
                    return;
                }
            }
        });
    }

    private void onImportDownloadedKeys(final PrivateKey encKey, final PrivateKey signKey, final String uuid) {
        final String rsaSig;
        try {
            rsaSig = getSignature(new String[]{uuid, uuid}, signKey);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.e(TAG, "Error generating signature", e);
            onDownloadKeyError(e);
            return;
        }
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
                params.put("rsa_sig", rsaSig);
                return params;
            }
        };
        req.setRetryPolicy(new DefaultRetryPolicy(
                10 * 1000,
                3,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));
        requestQueue.add(req);
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

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    private byte[] wrapAESKey(PublicKey recipientEncKey, SecretKey keyBeingWraped)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.WRAP_MODE, recipientEncKey);
        return cipher.wrap(keyBeingWraped);
    }

    private SecretKey unwrapAESKeyUsingStoredPrivate(byte[] keyBeingUnwraped)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.UNWRAP_MODE, getPrivateKeyFromKeystore(KEY_ALIAS_ENC));
        return (SecretKey) cipher.unwrap(keyBeingUnwraped, ENCRYPT_ALGRO, Cipher.SECRET_KEY);
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
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
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
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
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
     * Gets the public key from server
     * This is a blocking call, it MUST BE called on another thread
     *
     * @param targetUuid The uuid to receive
     * @return A pair of public encrypt/sign key
     */
    private PublicKeys getPublicKeysFromServer(final String targetUuid) {
        if (Looper.getMainLooper().isCurrentThread()) {
            Log.e(TAG, "getPublicKeysFromServer() is called on UI thread!! Aborting...");
            return null;
        }
        if (this.uuid == null) {
            Log.w(TAG, "No uuid is set for this client, please register or use existing keys");
            return null;
        }
        PublicKeys cachedKeys = publicKeyCache.get(targetUuid);
        if (cachedKeys != null) return cachedKeys;
        RequestFuture<String> future = RequestFuture.newFuture();
        final String rsaSig;
        try {
            rsaSig = getSignature(
                    new String[]{targetUuid, uuid},
                    getPrivateKeyFromKeystore(KEY_ALIAS_SIGN)
            );
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.e(TAG, "Error generating signature", e);
            return null;
        }
        StringRequest req = new StringRequest(
                Request.Method.POST, apiUri.resolve(ENDPOINT_REQUEST_PUBLIC_KEYS).toString(), future, future) {
            @Override
            protected Map<String, String> getParams() {
                Map<String, String> params = new HashMap<>();
                params.put("requesting_uuid", targetUuid);
                params.put("requester_uuid", uuid);
                params.put("rsa_sig", rsaSig);
                return params;
            }
        };
        req.setRetryPolicy(new DefaultRetryPolicy(
                10 * 1000,
                3,
                DefaultRetryPolicy.DEFAULT_BACKOFF_MULT
        ));
        requestQueue.add(req);
        try {
            String responseStr = future.get(35, TimeUnit.SECONDS);
            JSONObject response = new JSONObject(responseStr);
            if (!response.getBoolean("successful")) {
                // No such uuid exist, returns empty public keys
                return new PublicKeys(null, null);
            }
            JSONObject keys = response.getJSONObject("keys");
            String encPem = keys.getString("pke");
            String signPem = keys.getString("pks");
            PublicKey encPublic = fromPem(encPem, RSA_ENC_ALGRO);
            PublicKey signPublic = fromPem(signPem, RSA_SIGN_ALGRO);
            byte[] targetRsaSig = fromBase64(keys.getString("rsa_sig"));
            if (!verifySignature(new String[]{encPem, signPem}, signPublic, targetRsaSig)) {
                Log.e(TAG, "Public key could not be verified. Signature mismatch! Defaulting to cache if any..");
                return publicKeyCache.get(targetUuid);
            }
            publicKeyCache.putIfAbsent(targetUuid, new PublicKeys(encPublic, signPublic));
            // The result is ignored and the cached version is used instead if it's suddenly available
            return publicKeyCache.get(targetUuid);
        } catch (InterruptedException | ExecutionException | TimeoutException | JSONException | NoSuchAlgorithmException
                | InvalidKeySpecException | InvalidKeyException | SignatureException e) {
            Log.e(TAG, "Error getting public keys. Defaulting to cache if any..", e);
            return publicKeyCache.get(targetUuid);
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

    private boolean verifySignature(String[] params, PublicKey publicSignKey, byte[] signatureBytes)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Arrays.sort(params);
        Signature signature = Signature.getInstance(RSA_SIGN_SCHEME);
        signature.initVerify(publicSignKey);
        String paramsStr = TextUtils.join("", params);
        signature.update(paramsStr.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureBytes);
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

    public void addListener(SendMessageEventListener listener) {
        sendMessageEventListeners.add(listener);
    }

    public void addListener(ChatServiceEventListener listener) {
        chatServiceEventListeners.add(listener);
    }

    public void addListener(UserInfoUpdateListener listener) {
        userInfoUpdateEventListeners.add(listener);
    }

    public void removeListener(RegisterEventListener listener) {
        registerEventListeners.remove(listener);
    }

    public void removeListener(DownloadKeyEventListener listener) {
        downloadKeyEventListeners.remove(listener);
    }

    public void removeListener(SendMessageEventListener listener) {
        sendMessageEventListeners.remove(listener);
    }

    public void removeListener(ChatServiceEventListener listener) {
        chatServiceEventListeners.remove(listener);
    }

    public void removeListener(UserInfoUpdateListener listener) {
        userInfoUpdateEventListeners.remove(listener);
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

    private void onSendMessageSuccessful(String messageID) {
        for (SendMessageEventListener listener : sendMessageEventListeners) {
            listener.onSent(messageID);
        }
    }

    private void onSendMessageFailed(String messageID, Exception e) {
        for (SendMessageEventListener listener : sendMessageEventListeners) {
            listener.onFailed(messageID, e);
        }
    }

    private void onSendMessageFailedNoUser(String messageID) {
        for (SendMessageEventListener listener : sendMessageEventListeners) {
            listener.onFailedNoUser(messageID);
        }
    }

    private void onReceiveMessage(String senderUuid, String message) {
        for (ChatServiceEventListener listener : chatServiceEventListeners) {
            listener.onMessageReceive(senderUuid, message);
        }
    }

    private void onMessageDecryptFailed(String senderUuid) {
        for (ChatServiceEventListener listener : chatServiceEventListeners) {
            listener.onMessageDecryptFailed(senderUuid);
        }
    }

    private void onChatServiceConnect() {
        for (ChatServiceEventListener listener : chatServiceEventListeners) {
            listener.onConnected();
        }
    }

    private void onChatServiceDisconnect() {
        for (ChatServiceEventListener listener : chatServiceEventListeners) {
            listener.onDisconnect();
        }
    }

    private void onChatServiceError(Exception e) {
        for (ChatServiceEventListener listener : chatServiceEventListeners) {
            listener.onDisconnectWithError(e);
        }
    }

    private void onUserInfoUpdateSuccess(String updateType) {
        for (UserInfoUpdateListener listener : userInfoUpdateEventListeners) {
            listener.onSuccess(updateType);
        }
    }

    private void onUserInfoUpdateFailed(String updateType, Exception e) {
        for (UserInfoUpdateListener listener : userInfoUpdateEventListeners) {
            listener.onFailure(updateType, e);
        }
    }
}