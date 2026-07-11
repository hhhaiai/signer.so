package com.adjust.research;

import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Iterator;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

public final class AndroidRuntimeJni extends AbstractJni {

    private static final String GET_PACKAGE_NAME =
            "android/content/Context->getPackageName()Ljava/lang/String;";

    private final String packageName;
    private final byte[] certificateBytes;
    private final byte[] hmacKey;

    public AndroidRuntimeJni(String packageName) {
        this(packageName,
                "adjust-signature-fixture-certificate".getBytes(StandardCharsets.UTF_8), null);
    }

    public AndroidRuntimeJni(String packageName, byte[] certificateBytes) {
        this(packageName, certificateBytes, null);
    }

    public AndroidRuntimeJni(String packageName, byte[] certificateBytes, byte[] hmacKey) {
        this.packageName = Objects.requireNonNull(packageName, "packageName");
        this.certificateBytes = Arrays.copyOf(
                Objects.requireNonNull(certificateBytes, "certificateBytes"), certificateBytes.length);
        this.hmacKey = hmacKey == null ? null : Arrays.copyOf(hmacKey, hmacKey.length);
    }

    public DvmObject<?> wrapContext(VM vm) {
        return vm.resolveClass("android/content/Context").newObject(packageName);
    }

    public DvmObject<?> wrapParameters(VM vm, LinkedHashMap<String, String> parameters) {
        return vm.resolveClass("java/util/Map").newObject(Objects.requireNonNull(parameters, "parameters"));
    }

    @Override
    public DvmObject<?> callObjectMethodV(
            BaseVM vm, DvmObject<?> receiver, String signature, VaList args) {
        DvmObject<?> handled = handleObjectCall(vm, receiver, signature,
                index -> args == null ? null : args.getObjectArg(index));
        if (handled != Unhandled.VALUE) {
            return handled;
        }
        try {
            return super.callObjectMethodV(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public DvmObject<?> callObjectMethod(
            BaseVM vm, DvmObject<?> receiver, String signature, VarArg args) {
        DvmObject<?> handled = handleObjectCall(vm, receiver, signature,
                index -> args == null ? null : args.getObjectArg(index));
        if (handled != Unhandled.VALUE) {
            return handled;
        }
        try {
            return super.callObjectMethod(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public boolean callBooleanMethodV(
            BaseVM vm, DvmObject<?> receiver, String signature, VaList args) {
        if ("java/util/Iterator->hasNext()Z".equals(signature)) {
            return ((Iterator<?>) receiver.getValue()).hasNext();
        }
        if ("android/content/pm/SigningInfo->hasMultipleSigners()Z".equals(signature)) {
            return false;
        }
        if ("java/util/Map->containsKey(Ljava/lang/Object;)Z".equals(signature)) {
            return ((Map<?, ?>) receiver.getValue()).containsKey(unwrap(args.getObjectArg(0)));
        }
        try {
            return super.callBooleanMethodV(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public boolean callBooleanMethod(
            BaseVM vm, DvmObject<?> receiver, String signature, VarArg args) {
        if ("java/util/Iterator->hasNext()Z".equals(signature)) {
            return ((Iterator<?>) receiver.getValue()).hasNext();
        }
        if ("android/content/pm/SigningInfo->hasMultipleSigners()Z".equals(signature)) {
            return false;
        }
        if ("java/util/Map->containsKey(Ljava/lang/Object;)Z".equals(signature)) {
            return ((Map<?, ?>) receiver.getValue()).containsKey(unwrap(args.getObjectArg(0)));
        }
        try {
            return super.callBooleanMethod(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public int callIntMethodV(BaseVM vm, DvmObject<?> receiver, String signature, VaList args) {
        if ("java/util/Map->size()I".equals(signature)) {
            return ((Map<?, ?>) receiver.getValue()).size();
        }
        if ("java/util/ArrayList->size()I".equals(signature)
                || "java/util/List->size()I".equals(signature)) {
            return ((List<?>) receiver.getValue()).size();
        }
        try {
            return super.callIntMethodV(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> receiver, String signature, VarArg args) {
        if ("java/util/Map->size()I".equals(signature)) {
            return ((Map<?, ?>) receiver.getValue()).size();
        }
        if ("java/util/ArrayList->size()I".equals(signature)
                || "java/util/List->size()I".equals(signature)) {
            return ((List<?>) receiver.getValue()).size();
        }
        try {
            return super.callIntMethod(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public void callVoidMethodV(BaseVM vm, DvmObject<?> receiver, String signature, VaList args) {
        if ("java/security/MessageDigest->update([B)V".equals(signature)) {
            ByteArray input = args.getObjectArg(0);
            ((MessageDigest) receiver.getValue()).update(input.getValue());
            return;
        }
        if ("java/security/KeyStore->load(Ljava/security/KeyStore$LoadStoreParameter;)V"
                .equals(signature)) {
            return;
        }
        if ("javax/crypto/Mac->init(Ljava/security/Key;)V".equals(signature)) {
            DvmObject<?> keyObject = args.getObjectArg(0);
            try {
                ((Mac) receiver.getValue()).init((Key) keyObject.getValue());
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("invalid fixture HMAC key", e);
            }
            return;
        }
        if ("javax/crypto/Mac->update([B)V".equals(signature)) {
            ByteArray input = args.getObjectArg(0);
            ((Mac) receiver.getValue()).update(input.getValue());
            return;
        }
        try {
            super.callVoidMethodV(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> receiver, String signature, VarArg args) {
        if ("java/security/MessageDigest->update([B)V".equals(signature)) {
            ByteArray input = args.getObjectArg(0);
            ((MessageDigest) receiver.getValue()).update(input.getValue());
            return;
        }
        if ("java/security/KeyStore->load(Ljava/security/KeyStore$LoadStoreParameter;)V"
                .equals(signature)) {
            return;
        }
        if ("javax/crypto/Mac->init(Ljava/security/Key;)V".equals(signature)) {
            DvmObject<?> keyObject = args.getObjectArg(0);
            try {
                ((Mac) receiver.getValue()).init((Key) keyObject.getValue());
            } catch (InvalidKeyException e) {
                throw new IllegalArgumentException("invalid fixture HMAC key", e);
            }
            return;
        }
        if ("javax/crypto/Mac->update([B)V".equals(signature)) {
            ByteArray input = args.getObjectArg(0);
            ((Mac) receiver.getValue()).update(input.getValue());
            return;
        }
        try {
            super.callVoidMethod(vm, receiver, signature, args);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public DvmObject<?> getObjectField(BaseVM vm, DvmObject<?> receiver, String signature) {
        if ("android/content/pm/PackageInfo->signatures:[Landroid/content/pm/Signature;"
                .equals(signature)) {
            DvmObject<?> signatureObject = vm.resolveClass("android/content/pm/Signature")
                    .newObject(Arrays.copyOf(certificateBytes, certificateBytes.length));
            return new ArrayObject(signatureObject);
        }
        if ("android/content/pm/PackageInfo->signingInfo:Landroid/content/pm/SigningInfo;"
                .equals(signature)) {
            return vm.resolveClass("android/content/pm/SigningInfo")
                    .newObject(Arrays.copyOf(certificateBytes, certificateBytes.length));
        }
        if ("android/content/pm/ApplicationInfo->publicSourceDir:Ljava/lang/String;"
                .equals(signature)) {
            return new StringObject(vm, "/data/app/" + packageName + "/base.apk");
        }
        try {
            return super.getObjectField(vm, receiver, signature);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public int getIntField(BaseVM vm, DvmObject<?> receiver, String signature) {
        if ("android/util/DisplayMetrics->widthPixels:I".equals(signature)) {
            return 1080;
        }
        if ("android/util/DisplayMetrics->heightPixels:I".equals(signature)) {
            return 1920;
        }
        try {
            return super.getIntField(vm, receiver, signature);
        } catch (UnsupportedOperationException e) {
            throw unsupported(receiver, signature, e);
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethodV(
            BaseVM vm, DvmClass dvmClass, String signature, VaList args) {
        DvmObject<?> handled = handleStaticObjectCall(vm, signature,
                index -> args == null ? null : args.getObjectArg(index));
        if (handled != Unhandled.VALUE) {
            return handled;
        }
        try {
            return super.callStaticObjectMethodV(vm, dvmClass, signature, args);
        } catch (UnsupportedOperationException e) {
            throw new UnsupportedOperationException("Unsupported static JNI call: " + signature, e);
        }
    }

    @Override
    public DvmObject<?> callStaticObjectMethod(
            BaseVM vm, DvmClass dvmClass, String signature, VarArg args) {
        DvmObject<?> handled = handleStaticObjectCall(vm, signature,
                index -> args == null ? null : args.getObjectArg(index));
        if (handled != Unhandled.VALUE) {
            return handled;
        }
        try {
            return super.callStaticObjectMethod(vm, dvmClass, signature, args);
        } catch (UnsupportedOperationException e) {
            throw new UnsupportedOperationException("Unsupported static JNI call: " + signature, e);
        }
    }

    private DvmObject<?> handleObjectCall(
            BaseVM vm, DvmObject<?> receiver, String signature, ObjectArgument args) {
        switch (signature) {
            case GET_PACKAGE_NAME:
            case "android/app/Application->getPackageName()Ljava/lang/String;":
            case "android/content/ContextWrapper->getPackageName()Ljava/lang/String;":
                return new StringObject(vm, packageName);
            case "java/util/Map->get(Ljava/lang/Object;)Ljava/lang/Object;": {
                Object key = unwrap(args.get(0));
                return wrapHost(vm, ((Map<?, ?>) receiver.getValue()).get(key));
            }
            case "java/util/Map->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;": {
                Object key = unwrap(args.get(0));
                Object value = unwrap(args.get(1));
                @SuppressWarnings("unchecked")
                Map<Object, Object> map = (Map<Object, Object>) receiver.getValue();
                return wrapHost(vm, map.put(key, value));
            }
            case "java/util/Map->entrySet()Ljava/util/Set;":
                return wrapHost(vm, ((Map<?, ?>) receiver.getValue()).entrySet());
            case "java/util/Set->iterator()Ljava/util/Iterator;":
                return wrapHost(vm, ((Set<?>) receiver.getValue()).iterator());
            case "java/util/Iterator->next()Ljava/lang/Object;":
                return wrapHost(vm, ((Iterator<?>) receiver.getValue()).next());
            case "java/util/Map$Entry->getKey()Ljava/lang/Object;":
                return wrapHost(vm, ((Map.Entry<?, ?>) receiver.getValue()).getKey());
            case "java/util/Map$Entry->getValue()Ljava/lang/Object;":
                return wrapHost(vm, ((Map.Entry<?, ?>) receiver.getValue()).getValue());
            case "java/lang/Object->toString()Ljava/lang/String;":
            case "java/util/Map->toString()Ljava/lang/String;":
                return new StringObject(vm, String.valueOf(receiver.getValue()));
            case "java/lang/String->getBytes()[B":
                return new ByteArray(vm,
                        ((String) receiver.getValue()).getBytes(StandardCharsets.UTF_8));
            case "android/content/pm/Signature->toByteArray()[B":
                return new ByteArray(vm, Arrays.copyOf(certificateBytes, certificateBytes.length));
            case "android/content/pm/SigningInfo->getSigningCertificateHistory()"
                    + "[Landroid/content/pm/Signature;": {
                DvmObject<?> signatureObject = vm.resolveClass("android/content/pm/Signature")
                        .newObject(Arrays.copyOf(certificateBytes, certificateBytes.length));
                return new ArrayObject(signatureObject);
            }
            case "android/content/Context->getSystemService(Ljava/lang/String;)Ljava/lang/Object;": {
                Object serviceName = unwrap(args.get(0));
                if ("sensor".equals(serviceName)) {
                    return vm.resolveClass("android/hardware/SensorManager").newObject(serviceName);
                }
                throw new UnsupportedOperationException(
                        "Unsupported Android system service: " + serviceName);
            }
            case "android/hardware/SensorManager->getSensorList(I)Ljava/util/List;":
                return vm.resolveClass("java/util/ArrayList").newObject(new ArrayList<>());
            case "android/content/res/Resources->getDisplayMetrics()Landroid/util/DisplayMetrics;":
                return vm.resolveClass("android/util/DisplayMetrics").newObject("1080x1920@420");
            case "android/content/pm/PackageManager->getApplicationInfo(Ljava/lang/String;I)Landroid/content/pm/ApplicationInfo;":
                return vm.resolveClass("android/content/pm/ApplicationInfo")
                        .newObject(packageName);
            case "java/lang/Thread->getStackTrace()[Ljava/lang/StackTraceElement;": {
                StackTraceElement[] stackTrace = ((Thread) receiver.getValue()).getStackTrace();
                DvmObject<?>[] elements = new DvmObject<?>[stackTrace.length];
                DvmClass elementClass = vm.resolveClass("java/lang/StackTraceElement");
                for (int i = 0; i < stackTrace.length; i++) {
                    elements[i] = elementClass.newObject(stackTrace[i]);
                }
                return new ArrayObject(elements);
            }
            case "java/lang/StackTraceElement->getClassName()Ljava/lang/String;":
                return new StringObject(vm,
                        ((StackTraceElement) receiver.getValue()).getClassName());
            case "java/lang/StackTraceElement->getMethodName()Ljava/lang/String;":
                return new StringObject(vm,
                        ((StackTraceElement) receiver.getValue()).getMethodName());
            case "java/security/KeyStore->getKey(Ljava/lang/String;[C)Ljava/security/Key;": {
                String alias = (String) unwrap(args.get(0));
                if (!"key2".equals(alias) || hmacKey == null) {
                    return null;
                }
                return vm.resolveClass("java/security/Key")
                        .newObject(new SecretKeySpec(hmacKey, "HmacSHA256"));
            }
            case "java/security/MessageDigest->digest()[B":
                return new ByteArray(vm, ((MessageDigest) receiver.getValue()).digest());
            case "java/security/MessageDigest->digest([B)[B": {
                ByteArray input = (ByteArray) args.get(0);
                return new ByteArray(vm,
                        ((MessageDigest) receiver.getValue()).digest(input.getValue()));
            }
            case "javax/crypto/Mac->doFinal()[B":
                return new ByteArray(vm, ((Mac) receiver.getValue()).doFinal());
            default:
                return Unhandled.VALUE;
        }
    }

    private DvmObject<?> handleStaticObjectCall(
            BaseVM vm, String signature, ObjectArgument args) {
        if ("android/content/res/Resources->getSystem()Landroid/content/res/Resources;"
                .equals(signature)) {
            return vm.resolveClass("android/content/res/Resources").newObject("system");
        }
        if ("java/lang/Thread->currentThread()Ljava/lang/Thread;".equals(signature)) {
            return vm.resolveClass("java/lang/Thread").newObject(Thread.currentThread());
        }
        if ("java/security/KeyStore->getInstance(Ljava/lang/String;)Ljava/security/KeyStore;"
                .equals(signature)) {
            String type = (String) unwrap(args.get(0));
            if (!"AndroidKeyStore".equals(type)) {
                throw new IllegalArgumentException("unsupported key store type " + type);
            }
            return vm.resolveClass("java/security/KeyStore").newObject(type);
        }
        if ("javax/crypto/Mac->getInstance(Ljava/lang/String;)Ljavax/crypto/Mac;"
                .equals(signature)) {
            String algorithm = (String) unwrap(args.get(0));
            try {
                return vm.resolveClass("javax/crypto/Mac")
                        .newObject(Mac.getInstance(algorithm));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("unsupported MAC algorithm " + algorithm, e);
            }
        }
        if ("java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
                .equals(signature)) {
            String algorithm = (String) unwrap(args.get(0));
            try {
                return vm.resolveClass("java/security/MessageDigest")
                        .newObject(MessageDigest.getInstance(algorithm));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException("unsupported digest algorithm " + algorithm, e);
            }
        }
        return Unhandled.VALUE;
    }

    private static Object unwrap(DvmObject<?> value) {
        return value == null ? null : value.getValue();
    }

    private static DvmObject<?> wrapHost(BaseVM vm, Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof String) {
            return new StringObject(vm, (String) value);
        }
        if (value instanceof byte[]) {
            return new ByteArray(vm, (byte[]) value);
        }
        if (value instanceof Map.Entry) {
            return vm.resolveClass("java/util/Map$Entry").newObject(value);
        }
        if (value instanceof Iterator) {
            return vm.resolveClass("java/util/Iterator").newObject(value);
        }
        if (value instanceof Set) {
            return vm.resolveClass("java/util/Set").newObject(value);
        }
        if (value instanceof Map) {
            return vm.resolveClass("java/util/Map").newObject(value);
        }
        if (value instanceof MessageDigest) {
            return vm.resolveClass("java/security/MessageDigest").newObject(value);
        }
        return vm.resolveClass("java/lang/Object").newObject(value);
    }

    private static UnsupportedOperationException unsupported(
            DvmObject<?> receiver, String signature, UnsupportedOperationException cause) {
        String receiverType = receiver == null ? "<static/null>" : receiver.getObjectType().getName();
        return new UnsupportedOperationException(
                "Unsupported JNI call: " + signature + " receiver=" + receiverType, cause);
    }

    @FunctionalInterface
    private interface ObjectArgument {
        DvmObject<?> get(int index);
    }

    private static final class Unhandled extends DvmObject<Object> {
        private static final Unhandled VALUE = new Unhandled();

        private Unhandled() {
            super(null, null);
        }
    }
}
