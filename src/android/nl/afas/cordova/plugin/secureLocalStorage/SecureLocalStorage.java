/*
The MIT License (MIT)

Copyright (c) 2015 Dick Verweij dickydick1969@hotmail.com, d.verweij@afas.nl

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
package nl.afas.cordova.plugin.secureLocalStorage;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.os.Build;
import android.security.KeyPairGeneratorSpec;
import android.util.Log;

import com.google.gson.Gson;
import com.google.gson.JsonIOException;
import com.google.gson.JsonSyntaxException;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaWebView;
import org.apache.cordova.PluginResult;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

public class SecureLocalStorage extends CordovaPlugin {

  public enum ActionId {
    ACTION_NONE,
    ACTION_CLEARIFINVALID,
    ACTION_CLEAR,
    ACTION_GETITEM,
    ACTION_SETITEM,
    ACTION_REMOVEITEM
  }

  public class SecureLocalStorageException extends Exception{
    public SecureLocalStorageException(String message){
      super(message);
    }
    public SecureLocalStorageException(String message,Exception ex){
      super(message,ex);
    }
  }

  protected HashMap<String, Object> hashMap = new HashMap<String, Object>();
  protected Gson gson = new Gson();

  protected KeyStore keyStore;
  protected Context context;

  // encrypted local storage
  private static final String SECURELOCALSTORAGEFILE = "secureLocalStorage.sdat";
  // encrypted key
  private static final String SECURELOCALSTORAGEKEY =  "secureLocalStorage.kdat";
  private static final String SECURELOCALSTORAGEALIAS = "SECURELOCALSTORAGEPPKEYALIAS";

  private final ReentrantLock lock = new ReentrantLock();
  private static SecretKey _key = null;

  private CordovaInterface _cordova;

  public SecureLocalStorage() {}

  public SecureLocalStorage(Context context) {
    this.context = context;
  }

  public SecureLocalStorage(Activity activity) {

    if (activity != null) {
      this.context = activity.getBaseContext();
    }

  }

  @Override
  public void initialize(CordovaInterface cordova, CordovaWebView webView) {
    super.initialize(cordova, webView);
    _cordova = cordova;
  }

  @Override
  public boolean execute(final String action, final JSONArray args, final CallbackContext callbackContext) {

    final ActionId actionId = getActionId(action);
    if (actionId == ActionId.ACTION_NONE) {
      return false;
    }

    PluginResult pluginResult = new PluginResult(PluginResult.Status.NO_RESULT);
    pluginResult.setKeepCallback(true);
    callbackContext.sendPluginResult(pluginResult);

    // start thread
    _cordova.getThreadPool().execute(new Runnable() {
      @Override
      public void run() {

        try {
          handleAction(actionId, args, callbackContext);
        } catch (Exception ex) {
          handleException(ex, callbackContext);
        }
      }
    });

    return true;
  }

  public void initEncryptStorage() throws SecureLocalStorageException {

    if (keyStore == null) {

      keyStore = initKeyStore();
    }

    context = getContext();
    File file = context.getFileStreamPath(SECURELOCALSTORAGEFILE);

    if (!file.exists()) {
      // generate key and store in keyStore
      generateKey(keyStore);

      writeAndEncryptStorage(keyStore, hashMap);
    }

    // read current storage hashmap
    hashMap = readAndDecryptStorage(keyStore);

  }

  private Context getContext() throws SecureLocalStorageException {
    context = _cordova != null ? _cordova.getActivity().getBaseContext() : context;
    if (context == null) {
      throw new SecureLocalStorageException("The Android Context is required. Verify if the 'activity' or 'context' are passed by constructor");
    }

    return context;
  }

  public boolean setItem(String key, Object value) throws SecureLocalStorageException {

    if (key == null || key.length() == 0) {
      throw new SecureLocalStorageException("Key is empty or null");
    }

    if(!lock.isLocked()) {
      lock.lock();
    }

    try {

      this.initEncryptStorage();

      if (value == null) {
        throw new SecureLocalStorageException("Value is null");
      }

      hashMap.put(key, value);

      // store back
      writeAndEncryptStorage(keyStore, hashMap);

    } finally {

      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }

      return true;
    }
  }

  public void setItem(final String key, final Object value, CallbackContext callbackContext) throws SecureLocalStorageException, JSONException {

    final Boolean result = this.setItem(key, value);

    if (result && _cordova != null && callbackContext != null) {

      JSONObject success = new JSONObject() {{
        put("success", result);
        put("storedValue", value);
      }};

      callbackContext.success(success);

    } else {

      JSONObject error = new JSONObject() {{
        put("success", result);
        put("name", "SetValueException");
        put("message", String.format("The key=>value '%s=>%' cannot be set", key, value));
      }};

      callbackContext.error(error);
    }

  }

  public Object getItem(String key) throws SecureLocalStorageException {

    Object value = null;

    if (key == null || key.length() == 0) {
      throw new SecureLocalStorageException("Key is empty or null");
    }

    if (!lock.isLocked()) {
      lock.lock();
    }

    try {

      this.initEncryptStorage();

      if (hashMap.containsKey(key)) {

        value = hashMap.get(key);

        try {

          JSONObject jsonResult = new JSONObject((String) value);

          if (jsonResult.has("nameValuePairs")) {
            value = jsonResult.getJSONObject("nameValuePairs");
          }
        } catch (Exception jsonErr) {
          jsonErr.printStackTrace();
          Log.e("SecureStorage", jsonErr.getMessage(), jsonErr);
        }
      }

    } catch(Exception err) {
      Log.e("SecureStorage", err.getMessage(), err);
      throw err;
    } finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    return value;
  }

  /**
   * Reference: How to Validate JSON with Jackson JSON
   * https://stackoverflow.com/questions/10226897/how-to-validate-json-with-jackson-json
   * @param key
   * @param pojoClass
   * @param <T>
   * @return
   * @throws IOException
   * @throws SecureLocalStorageException
   */
  public <T extends Object> T getItem(String key, Class<T> pojoClass) throws JsonSyntaxException, SecureLocalStorageException {

    Object value = this.getItem(key);
    String valueStr = value.toString();

    if(valueStr != null && valueStr.length() > 0) {

      return gson.fromJson(valueStr, pojoClass);
    }

    return null;
  }

  public void getItem(String key, CallbackContext callbackContext) throws JSONException {

    try {

      Object value = this.getItem(key);

      if (value instanceof JSONObject ) {

        callbackContext.success((JSONObject) value);
      } else {
        callbackContext.success((String) value);
      }

    } catch (final Exception err) {

      JSONObject error = new JSONObject() {{
        put("success", false);
        put("name", err.getClass().getName());
        put("message", err.getMessage());
      }};

      callbackContext.error(error);
      return;
    }
  }

  public HashMap<String, Object> getRawItems() throws SecureLocalStorageException {

    if(!lock.isLocked()) {
      lock.lock();
    }

    try{

      if (hashMap.size() == 0) {
        this.initEncryptStorage();
      }
    }finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    return hashMap.size() > 0 ? hashMap : null;
  }

  /**
   * Reference: Convert Map to JSON using Jackson
   * https://stackoverflow.com/questions/29340383/convert-map-to-json-using-jackson
   * @return
   * @throws JSONException
   * @throws SecureLocalStorageException
   */
  public JSONObject getItems() throws JSONException, SecureLocalStorageException {

    if(!lock.isLocked()) {
      lock.lock();
    }

    try{

      if (hashMap.size() == 0) {
        this.initEncryptStorage();
      }
    }finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    if (hashMap.size() > 0) {
      String json = gson.toJson(hashMap);

      return new JSONObject(json);
    }

    return null;
  }

  public boolean removeItem(String key) throws SecureLocalStorageException {

    if (key == null || key.length() == 0) {
      throw new SecureLocalStorageException("Key is empty or null");
    }

    if(!lock.isLocked()) {
      lock.lock();
    }

    try {

      this.initEncryptStorage();

      hashMap.remove(key);

      // store back
      writeAndEncryptStorage(keyStore, hashMap);
    } finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    return !hashMap.containsKey(key);
  }

  public void removeItem(String key, CallbackContext callbackContext) throws SecureLocalStorageException {
    boolean result = this.removeItem(key);

    PluginResult pluginResult = new PluginResult(result? PluginResult.Status.OK : PluginResult.Status.ERROR);
    pluginResult.setKeepCallback(false);
    callbackContext.sendPluginResult(pluginResult);
  }

  public boolean containsItem(String key) throws SecureLocalStorageException {

    if(!lock.isLocked()) {
      lock.lock();
    }

    try{

      if (hashMap.size() == 0) {
        this.initEncryptStorage();
      }
    }finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    return hashMap.size() > 0 && hashMap.containsKey(key);
  }

  public boolean isEmpty() throws SecureLocalStorageException {

    if(!lock.isLocked() && lock.isHeldByCurrentThread()) {
      lock.lock();
    }

    try{

      if (hashMap.size() == 0) {
        this.initEncryptStorage();
      }
    }finally {
      if(lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }

    return hashMap.size() == 0;
  }

  private void handleException(Exception ex, CallbackContext callbackContext) {

    Log.e("SecureLocalStorage", "exception", ex);

    PluginResult pluginResult;
    JSONObject error = new JSONObject();

    try {
      error.put("success", false);
      error.put("message", ex.getMessage());
      error.put("trace", Log.getStackTraceString(ex));
      pluginResult =new PluginResult(PluginResult.Status.ERROR,error);
    }
    catch(JSONException jsex) {
      Log.e("SecureStorage", jsex.getMessage(), jsex);
      pluginResult = new PluginResult(PluginResult.Status.ERROR, ex.getMessage());
    }

    pluginResult.setKeepCallback(false);
    callbackContext.sendPluginResult(pluginResult);
  }

  private void handleAction(ActionId actionId, JSONArray args, CallbackContext callbackContext) throws SecureLocalStorageException, JSONException {

    if (Build.VERSION.SDK_INT < 18) {
      throw new SecureLocalStorageException("Invalid API Level (must be >= 18");
    }

    context = getContext();
    File file = context.getFileStreamPath(SECURELOCALSTORAGEFILE);

    // lock the access
    lock.lock();
    try {

      keyStore = initKeyStore();

      // clear just deletes the storage file
      if (actionId == ActionId.ACTION_CLEAR) {
        clear(file, keyStore);
        try {
          keyStore = initKeyStore();
          generateKey(keyStore);
        }
        catch(SecureLocalStorageException ex2) {
          Log.e("SecureStorage", ex2.getMessage(), ex2);
          throw ex2;
        }
        PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
        pluginResult.setKeepCallback(false);
        callbackContext.sendPluginResult(pluginResult);
      } else {

        // clear localStorage if invalid
        if (actionId == ActionId.ACTION_CLEARIFINVALID) {

          try {
            checkValidity();

            if (file.exists()) {

              // save hashmap for re-initializing certificate
              hashMap = readAndDecryptStorage(keyStore);

              // only clear file if untouched for 10 days
              if ((new Date().getTime() - file.lastModified()) > (10 * 24 * 60 * 60 * 1000)) {

                clear(file, keyStore);

                keyStore = initKeyStore();

                generateKey(keyStore);

                writeAndEncryptStorage(keyStore, hashMap);

              }
            }
          } catch (SecureLocalStorageException ex) {
            clear(file, keyStore);
            try {
              keyStore = initKeyStore();
              generateKey(keyStore);
            }
            catch(SecureLocalStorageException ex2) {
              Log.e("SecureStorage", ex2.getMessage(), ex2);
              throw ex2;
            }
          }
          PluginResult pluginResult = new PluginResult(PluginResult.Status.OK);
          pluginResult.setKeepCallback(false);
          callbackContext.sendPluginResult(pluginResult);
        } else {

          String key = args.getString(0);

          if (actionId == ActionId.ACTION_GETITEM) {

            this.getItem(key, callbackContext);

          } else if (actionId == ActionId.ACTION_SETITEM) {


            Object value = null;
            try {
              value = args.getJSONObject(1);
            } catch (JSONException valueJsonErr) {

              valueJsonErr.printStackTrace();
              Log.e("SecureStorage", valueJsonErr.getMessage(), valueJsonErr);

              value = args.getString(1);
            }finally {

              this.setItem(key, value, callbackContext);
            }


          } else if (actionId == ActionId.ACTION_REMOVEITEM) {

            this.removeItem(key, callbackContext);
          }
        }
      }

    } finally {
      if (lock.isLocked() && lock.isHeldByCurrentThread()) {
        lock.unlock();
      }
    }
  }

  private ActionId getActionId(final String action) {

    if (action.equals("clear")){
      return ActionId.ACTION_CLEAR;
    }
    if (action.equals("getItem")){
      return ActionId.ACTION_GETITEM;
    }
    if (action.equals("setItem")){
      return ActionId.ACTION_SETITEM;
    }
    if (action.equals("removeItem")){
      return ActionId.ACTION_REMOVEITEM;
    }
    if (action.equals("clearIfInvalid")){
      return ActionId.ACTION_CLEARIFINVALID;
    }
    return ActionId.ACTION_NONE;
  }

  @TargetApi(18)
  private KeyStore initKeyStore() throws SecureLocalStorageException {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);

      if (!keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {

        Calendar start = Calendar.getInstance();
        Calendar end = Calendar.getInstance();
        end.add(Calendar.YEAR, 3);

        context = getContext();

        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(context)
                .setAlias(SECURELOCALSTORAGEALIAS)
                .setSubject(new X500Principal(String.format("CN=%s, O=%s", "SecureLocalStorage", context.getPackageName())))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(start.getTime())
                .setEndDate(end.getTime())
                .build();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
        generator.initialize(spec);

        generator.generateKeyPair();
      }

      return keyStore;
    }
    catch (Exception e){
      Log.e("SecureStorage","Could not initialize keyStore", e);
      throw new SecureLocalStorageException("Could not initialize keyStore", e);
    }
  }

  public void clear(File file, KeyStore keyStore) throws SecureLocalStorageException {
    if (file.exists()) {
      if (!file.delete()) {
        throw new SecureLocalStorageException("Could not delete storage file");
      }
    }
    try {
      if (keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
        keyStore.deleteEntry(SECURELOCALSTORAGEALIAS);
      }
    } catch (Exception e) {
      Log.e("SecureStorage",e.getMessage(), e);
      throw new SecureLocalStorageException(e.getMessage(), e);
    }
  }

  public void clear() throws SecureLocalStorageException {

    context = getContext();
    File file = context.getFileStreamPath(SECURELOCALSTORAGEFILE);

    if (keyStore == null) {

      keyStore = initKeyStore();
    }

    this.clear(file, keyStore);

    try {
      keyStore = initKeyStore();
      generateKey(keyStore);
    }
    catch(SecureLocalStorageException ex2) {
      Log.e("SecureStorage",ex2.getMessage(), ex2);
      throw ex2;
    }
  }

  private void checkValidity() throws SecureLocalStorageException {
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);


      if (keyStore.containsAlias(SECURELOCALSTORAGEALIAS)) {
        Certificate c = keyStore.getCertificate(SECURELOCALSTORAGEALIAS);
        if (c.getType().equals("X.509")) {
          ((X509Certificate) c).checkValidity();
        }
      }
    } catch (Exception e) {
      Log.e("SecureStorage",e.getMessage(), e);
      throw new SecureLocalStorageException(e.getMessage(), e);
    }
  }

  private SecretKey getSecretKey(KeyStore keyStore) throws
          NoSuchAlgorithmException,
          UnrecoverableEntryException,
          KeyStoreException,
          NoSuchPaddingException,
          InvalidKeyException,
          IOException,
          ClassNotFoundException,
          SecureLocalStorageException {

    if (_key != null) {
      return _key;
    }

    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);


    SecretKey key;

    context = getContext();
    FileInputStream fis = context.openFileInput(SECURELOCALSTORAGEKEY);

    try {

      Cipher output = Cipher.getInstance("RSA/ECB/PKCS1Padding");

      output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());


      CipherInputStream cipherInputStream = new CipherInputStream(
              fis, output);
      try {

        ObjectInputStream ois = new ObjectInputStream(cipherInputStream);

        key = (SecretKey) ois.readObject();

      }
      finally {
        cipherInputStream.close();
      }
    }
    finally {
      fis.close();
    }

    // store key for the lifetime for the app
    _key = key;
    return key;
  }

  private void generateKey(KeyStore keyStore) throws SecureLocalStorageException {

    try {
      _key = null;

      SecretKey key = KeyGenerator.getInstance("DES").generateKey();
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try {
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        try {
          oos.writeObject(key);
        } finally {
          oos.close();
        }
      } finally {
        bos.close();
      }

      // store key encrypted with keystore key pair
      KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(SECURELOCALSTORAGEALIAS, null);

      Cipher input = Cipher.getInstance("RSA/ECB/PKCS1Padding");
      input.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

      context = getContext();
      FileOutputStream fos = context.openFileOutput(SECURELOCALSTORAGEKEY, Context.MODE_PRIVATE);

      try {
        CipherOutputStream cipherOutputStream = new CipherOutputStream(
                fos, input);
        try {
          cipherOutputStream.write(bos.toByteArray());
        } finally {
          cipherOutputStream.close();
        }
      } finally {
        fos.close();
      }

    } catch (Exception e) {
      Log.e("SecureStorage","Read",e);
      throw new SecureLocalStorageException("Error generating key", e);
    }
  }


  @SuppressWarnings("unchecked")
  private HashMap<String, Object> readAndDecryptStorage(KeyStore keyStore) throws SecureLocalStorageException {


    try {
      // obtain encrypted key
      SecretKey key = getSecretKey(keyStore);

      context = getContext();
      FileInputStream fis = context.openFileInput(SECURELOCALSTORAGEFILE);
      ArrayList<Byte> values = new ArrayList<Byte>();

      try {

        Cipher output = Cipher.getInstance("DES");
        output.init(Cipher.DECRYPT_MODE, key);

        CipherInputStream cipherInputStream = new CipherInputStream(
                fis, output);
        try {

          int nextByte;
          while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte) nextByte);
          }
        }
        finally {
          cipherInputStream.close();
        }
      }
      finally {
        fis.close();
      }

      byte[] bytes = new byte[values.size()];
      for (int i = 0; i < bytes.length; i++) {
        bytes[i] = values.get(i);
      }



      HashMap<String, Object> hashMap;
      ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes));
      try {
        hashMap = (HashMap<String, Object>) ois.readObject();
      }
      finally {
        ois.close();
      }
      return hashMap;
    }
    catch(Exception e) {
      Log.e("SecureStorage","Write",e);
      throw new SecureLocalStorageException("Error decrypting storage",e);
    }
  }

  private void writeAndEncryptStorage(KeyStore keyStore, HashMap<String, Object> hashMap) throws SecureLocalStorageException {

    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try {
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        try {
          oos.writeObject(hashMap);
        } finally {
          oos.close();
        }
      } finally {
        bos.close();
      }

      SecretKey key = getSecretKey(keyStore);

      Cipher input = Cipher.getInstance("DES");
      input.init(Cipher.ENCRYPT_MODE, key);

      // encrypt the hashmap
      context = getContext();
      FileOutputStream fos = context.openFileOutput(SECURELOCALSTORAGEFILE, Context.MODE_PRIVATE);

      try {
        CipherOutputStream cipherOutputStream = new CipherOutputStream(
                fos, input);
        try {
          cipherOutputStream.write(bos.toByteArray());
        } finally {
          cipherOutputStream.flush();
          cipherOutputStream.close();
        }
      } finally {
        fos.flush();
        fos.close();
      }

    }
    catch (Exception e){
      Log.e("SecureStorage","Write",e);
      throw new SecureLocalStorageException("Error encrypting storage",e);
    }
  }
}