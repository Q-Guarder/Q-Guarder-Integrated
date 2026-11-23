# ────────────────────────────────────────────────────────────────
# Q-Guard ProGuard / R8 Rules
# ────────────────────────────────────────────────────────────────

# 스택 트레이스 복구용 (크래시 리포팅 서비스와 함께 사용)
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ── Retrofit ────────────────────────────────────────────────────
-keepattributes Signature, InnerClasses, EnclosingMethod, Exceptions
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations
-keepclassmembers,allowshrinking,allowobfuscation interface * {
    @retrofit2.http.* <methods>;
}
-dontwarn org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement
-dontwarn javax.annotation.**
-dontwarn kotlin.Unit
-dontwarn retrofit2.KotlinExtensions

# ── Gson / JSON DTO ──────────────────────────────────────────────
# DTO 클래스 (역직렬화 시 필드명 보존 필요)
-keep class com.qguarder.android.data.remote.dto.** { *; }
-keepclassmembers,allowobfuscation class * {
    @com.google.gson.annotations.SerializedName <fields>;
}

# ── Room ─────────────────────────────────────────────────────────
-keep class * extends androidx.room.RoomDatabase
-keep @androidx.room.Entity class *
-keep @androidx.room.Dao interface *
-dontwarn androidx.room.paging.**

# ── Hilt / Dagger ────────────────────────────────────────────────
-dontwarn com.google.errorprone.annotations.**
-keepclasseswithmembernames class * {
    @dagger.* <methods>;
}

# ── 네트워크/보안 핵심 클래스 보호 ──────────────────────────────────
# R8이 데드코드로 판단해 제거하거나 인라인화하면 토큰 갱신 로직 전체가 무너짐
-keep class com.qguarder.android.data.remote.AuthInterceptor { *; }
-keep class com.qguarder.android.data.remote.RefreshApiServiceHolder { *; }
-keep class com.qguarder.android.data.local.TokenManager { *; }
-keep class com.qguarder.android.data.local.EncryptedCookieJar { *; }

# ── OkHttp / Okio ────────────────────────────────────────────────
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase

# ── ML Kit Barcode ───────────────────────────────────────────────
-keep class com.google.mlkit.** { *; }
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.mlkit.**

# ── CameraX ──────────────────────────────────────────────────────
-keep class androidx.camera.** { *; }
-dontwarn androidx.camera.**

# ── Kotlin / Coroutines ──────────────────────────────────────────
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**

# ── Log 제거 (릴리즈 빌드) ───────────────────────────────────────
# R8에게 "이 메서드는 부작용 없음 → 호출 자체를 지워도 된다"고 알림.
# 릴리즈 APK에서 Log.v/d/i/w/e 호출이 완전히 제거되어 로그 노출 방지.
# 주의: isMinifyEnabled = true 빌드에서만 적용됨.
-assumenosideeffects class android.util.Log {
    public static boolean isLoggable(java.lang.String, int);
    public static int v(java.lang.String, java.lang.String);
    public static int v(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int d(java.lang.String, java.lang.String);
    public static int d(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int i(java.lang.String, java.lang.String);
    public static int i(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int w(java.lang.String, java.lang.String);
    public static int w(java.lang.String, java.lang.String, java.lang.Throwable);
    public static int e(java.lang.String, java.lang.String);
    public static int e(java.lang.String, java.lang.String, java.lang.Throwable);
}
