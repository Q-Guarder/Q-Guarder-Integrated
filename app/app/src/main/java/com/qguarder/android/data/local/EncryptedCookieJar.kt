package com.qguarder.android.data.local

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import org.json.JSONArray
import org.json.JSONObject
import javax.inject.Inject
import javax.inject.Singleton

/**
 * refresh_token 쿠키를 EncryptedSharedPreferences에 영구 저장
 * 앱 재시작해도 쿠키 유지 → 자동 토큰 갱신 가능
 */
@Singleton
class EncryptedCookieJar @Inject constructor(
    @ApplicationContext val context: Context
) : CookieJar {

    companion object {
        private const val PREFS_NAME = "qguarder_cookie_prefs"
        private const val KEY_COOKIES = "saved_cookies"
    }

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // 메모리 캐시 (빠른 접근용)
    private val memoryCache = mutableMapOf<String, List<Cookie>>()

    override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
        if (cookies.isEmpty()) return

        Log.d("CookieJar", "URL: $url")
        Log.d("CookieJar", "새로 받은: ${cookies.map { it.name }}")

        // 기존 쿠키 로드 후 병합 (name+domain+path 기준, 만료된 쿠키 제외)
        val now = System.currentTimeMillis()
        val existing = loadForRequest(url)
            .filter { it.expiresAt > now }
            .associateBy { Triple(it.name, it.domain, it.path) }.toMutableMap()
        for (cookie in cookies) {
            existing[Triple(cookie.name, cookie.domain, cookie.path)] = cookie
        }
        val merged = existing.values.toList()

        memoryCache[url.host] = merged

        val jsonArray = JSONArray()
        merged.forEach { cookie ->
            val obj = JSONObject().apply {
                put("name",     cookie.name)
                put("value",    cookie.value)
                put("domain",   cookie.domain)
                put("path",     cookie.path)
                put("expiresAt", cookie.expiresAt)
                put("secure",   cookie.secure)
                put("httpOnly", cookie.httpOnly)
            }
            jsonArray.put(obj)
        }
        prefs.edit()
            .putString("${KEY_COOKIES}_${url.host}", jsonArray.toString())
            .apply()
    }

    override fun loadForRequest(url: HttpUrl): List<Cookie> {
        // 메모리 캐시 먼저 확인
        memoryCache[url.host]?.let { return it }

        // 없으면 EncryptedSharedPreferences에서 복원
        val json = prefs.getString("${KEY_COOKIES}_${url.host}", null)
            ?: return emptyList()

        return try {
            val jsonArray = JSONArray(json)
            val cookies = mutableListOf<Cookie>()
            val now = System.currentTimeMillis()
            for (i in 0 until jsonArray.length()) {
                val obj = jsonArray.getJSONObject(i)
                val expiresAt = obj.getLong("expiresAt")
                // 만료된 쿠키는 건너뜀
                if (expiresAt != Long.MAX_VALUE && expiresAt <= now) continue
                val cookie = Cookie.Builder()
                    .name(obj.getString("name"))
                    .value(obj.getString("value"))
                    .domain(obj.getString("domain"))
                    .path(obj.getString("path"))
                    .expiresAt(expiresAt)
                    .apply {
                        if (obj.getBoolean("secure"))   secure()
                        if (obj.getBoolean("httpOnly")) httpOnly()
                    }
                    .build()
                cookies.add(cookie)
            }
            // 메모리 캐시에도 올려둠
            memoryCache[url.host] = cookies
            cookies
        } catch (e: Exception) {
            emptyList()
        }
    }

    /** refresh_token 쿠키가 저장되어 있는지 확인 */
    fun hasRefreshCookie(): Boolean {
        for ((_, cookies) in memoryCache) {
            if (cookies.any { it.name == "refresh_token" }) return true
        }
        val allPrefs = prefs.all
        for ((key, value) in allPrefs) {
            if (key.startsWith(KEY_COOKIES) && value is String) {
                try {
                    val jsonArray = JSONArray(value)
                    for (i in 0 until jsonArray.length()) {
                        if (jsonArray.getJSONObject(i).getString("name") == "refresh_token") {
                            return true
                        }
                    }
                } catch (_: Exception) {}
            }
        }
        return false
    }

    // 로그아웃 시 쿠키 전체 삭제
    fun clear() {
        memoryCache.clear()
        prefs.edit().clear().apply()
    }
}