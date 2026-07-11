#ifndef ADJUST_LIBSIGNER_JNI_CONTRACT_H
#define ADJUST_LIBSIGNER_JNI_CONTRACT_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Java declaration recovered from the shipped 3.62.0 classes.jar:
 *
 *   private native byte[] nSign(
 *       android.content.Context context,
 *       java.lang.Object parameters,   // observed runtime type: Map<String,String>
 *       byte[] hmac,
 *       int sdkLevel);
 *
 * Exact descriptor:
 *   nSign(Landroid/content/Context;Ljava/lang/Object;[BI)[B
 *
 * This is an instance native method, so the second C argument is jobject thiz,
 * not jclass.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nSign(
    JNIEnv *env,
    jobject thiz,
    jobject context,
    jobject parameters,
    jbyteArray java_hmac,
    jint sdk_level);

/* Java declaration: private native void nOnResume(); */
JNIEXPORT void JNICALL
Java_com_adjust_sdk_sig_NativeLibHelper_nOnResume(JNIEnv *env, jobject thiz);

#ifdef __cplusplus
}
#endif

#endif

