package nl.afas.cordova.plugin.secureLocalStorage.lib;

import android.content.Context;
import android.os.Build;

import org.apache.cordova.CallbackContext;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

import java.security.KeyStore;

import javax.crypto.SecretKey;

import nl.afas.cordova.plugin.secureLocalStorage.KeyStoreManager;
import nl.afas.cordova.plugin.secureLocalStorage.KeyStoreType;
import nl.afas.cordova.plugin.secureLocalStorage.SecureLocalStorage;
import nl.afas.cordova.plugin.secureLocalStorage.lib.shadow.ShadowKeyStoreManager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

/**
 * Android Headless Integration test (without emulator/device)
 *
 * Verify storage/retrieve data operations of SecureLocalStorage class
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 * @see <a href="http://robolectric.org/getting-started/">Roboletric Getting Started</a>
 */
@RunWith(RobolectricTestRunner .class)
public class SecureLocalStorageTest {


    protected SecureLocalStorage secureLocalStorage;
    protected KeyStore keyStore;
    protected CallbackContext callbackContext;

    class PojoTest {

        protected String name;
        protected String value;

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public void setName(String name) {
            this.name = name;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }

    @Before
    @Config(shadows = ShadowKeyStoreManager.class)
    public void setUp() throws Exception {

        keyStore = KeyStoreManager.getSystemKeyStore(KeyStoreType.DEFAULT);
        callbackContext = mock(CallbackContext.class);
        Context context = mock(Context.class);
        SecretKey secretKey = mock(SecretKey.class);

        secureLocalStorage = SecureLocalStorage.getInstance(context, keyStore, secretKey);
    }

    /**
     * Store a token using {@link SecureLocalStorage#handleAction(SecureLocalStorage.ActionId, JSONArray, CallbackContext)}
     * method
     * @throws Exception
     */
    @Test()
    public void runHandleActionSetItem() throws Exception {

        final String tokenToSave = "e1pN0yDS-Wk:APA91Ze4axvAHUWAK_GL6";

        JSONArray params = new JSONArray()
                .put(0, "token")
                .put(1, tokenToSave);

        boolean result = secureLocalStorage.handleAction(SecureLocalStorage.ActionId.ACTION_SETITEM, params, callbackContext);

        assertTrue(result);
    }

    /**
     * Get a stored hash token like a String
     * @throws Exception
     */
    @Test()
    public void getStoredToken() throws Exception {

        String tokenToSave = "e1pN0yDS-Wk:APA91Ze4axvAHUWAK_GL6";
        secureLocalStorage.setItem("token", tokenToSave);

        String token = (String) secureLocalStorage.getItem("token");

        assertNotNull(token);
        assertEquals(tokenToSave, token);
    }

    /**
     * Get the secret key to encrypt storage data without any exceptions
     * @throws Exception
     */
    @Test()
    public void getSecreKeyWithoutErrors() throws Exception {

        SecretKey secretKey = secureLocalStorage.getSecretKey(keyStore);
        assertNotNull(secretKey);
    }

    /**
     * @todo Refactor this test to works with
     *       {@link java.security.KeyPairGenerator#getInstance(String, String)}
     *       Got Exception : "java.security.NoSuchAlgorithmException: no such algorithm: RSA for provider AndroidKeyStore"
     *
     * @throws Exception
     */
    @Config(sdk = Build.VERSION_CODES.P, shadows = ShadowKeyStoreManager.class)
    @Test
    @Ignore
    public void generateKeyWithoutErrors() throws Exception {

        secureLocalStorage.initEncryptStorage();
        secureLocalStorage.generateKey(keyStore);
    }

    /**
     * Initialize encrypt storage (generate keys, store all previous data to a hashMap)
     * without any exceptions
     * @throws Exception
     */
    @Test()
    public void initializeStorageWithoutErrors() throws Exception {

        secureLocalStorage.initEncryptStorage();
    }

    /**
     * Set a json string and retrieve a JSONObject instance
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String, Class)
     */
    @Test
    public void getStringAsJsonObject() {

        String json = "{\"key\":\"A key\", \"value\": \"A json value\"}";

        try {
            boolean stored = secureLocalStorage.setItem("jsonToConvert", json);
            if (stored) {
                Object value = secureLocalStorage.getItem("jsonToConvert");
                assertNotNull(value);
                assertEquals("A key", ((JSONObject) value).optString("key"));
                assertEquals("A json value", ((JSONObject) value).optString("value"));
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set a json array string and retrieve a JSONArray instance
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String, Class)
     */
    @Test
    public void getStringAsJsonArray() {

        String json = "[{\"key\":\"A key\", \"value\": \"A json value\"}]";

        try {
            boolean stored = secureLocalStorage.setItem("jsonToConvert", json);
            if (stored) {
                JSONArray value = (JSONArray) secureLocalStorage.getItem("jsonToConvert");
                assertNotNull(value);
                assertEquals("A key", value.optJSONObject(0).optString("key"));
                assertEquals("A json value", value.optJSONObject(0).optString("value"));
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set a POJO object and retrieve a JSONObject instance
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String, Class)
     */
    @Test
    public void getClassObjectAsJson() {

        PojoTest pojo = new PojoTest();
        pojo.setName("test");
        pojo.setValue("foo");

        try {
            boolean stored = secureLocalStorage.setItem("pojoObject", pojo);
            if (stored) {
                Object value = secureLocalStorage.getItem("pojoObject");
                assertNotNull(value);
                assertEquals("test", ((JSONObject) value).optString("name"));
                assertEquals("foo", ((JSONObject) value).optString("value"));
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set a POJO object and retrieve the same POJO instance
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String, Class)
     */
    @Test()
    public void getClassObjectAsInstance() {

        PojoTest pojo = new PojoTest();
        pojo.setName("test");
        pojo.setValue("foo");

        try {

            boolean stored = secureLocalStorage.setItem("pojoObject", pojo);

            if (stored) {
                PojoTest value = secureLocalStorage.getItem("pojoObject", PojoTest.class);

                assertNotNull(value);
                assertEquals("test", value.getName());
                assertEquals("foo", value.getValue());
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set a Boolean and retrieve the same boolean value
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String, Class)
     */
    @Test
    public void getBoolean() {

        try {

            boolean stored = secureLocalStorage.setItem("myFlag", true);

            if (stored) {
                Object value = secureLocalStorage.getItem("myFlag");
                assertTrue((boolean) value);
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Set a Integer and retrieve the same int value
     *
     * @see SecureLocalStorage#setItem(String, Object)
     * @see SecureLocalStorage#getItem(String)
     */
    @Test
    public void getInteger() {

        try {

            boolean stored = secureLocalStorage.setItem("myFlag", 1);

            if (stored) {
                Object value = secureLocalStorage.getItem("myFlag");
                assertEquals(1, value);
            }

        } catch (SecureLocalStorage.SecureLocalStorageException e) {
            fail(e.getMessage());
            e.printStackTrace();
        }
    }
}