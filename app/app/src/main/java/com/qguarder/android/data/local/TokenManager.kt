package com.qguarder.android.data.local

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * JWT Access Token 보안 저장소
 *
 * Access Token  → EncryptedSharedPreferences (AES256)
 * Refresh Token → HttpOnly 쿠키 (서버가 관리, 앱에서 직접 저장 안 함)
 */
@Singleton
class TokenManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val PREFS_NAME   = "qrguard_secure_prefs"
        private const val KEY_ACCESS   = "access_token"
        private const val KEY_USER_ID  = "user_id"
        private const val KEY_NICKNAME = "nickname"
        private const val KEY_EMAIL    = "email"
    }

    // 토큰 갱신 실패 시 강제 로그아웃 이벤트 — MainActivity가 구독해서 로그인 화면으로 이동
    private val _forceLogoutEvent = MutableSharedFlow<Unit>(extraBufferCapacity = 1)
    val forceLogoutEvent: SharedFlow<Unit> = _forceLogoutEvent

    fun emitForceLogout() {
        _forceLogoutEvent.tryEmit(Unit)
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
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    /** 로그인 성공 시 토큰 저장 */
    fun saveAfterLogin(accessToken: String, email: String) {
        prefs.edit().apply {
            putString(KEY_ACCESS, accessToken)
            putString(KEY_EMAIL,  email)
        }.apply()
    }

    /** 프로필 조회 후 유저 정보 저장 (register 직후 or GET /users/me 이후) */
    fun saveUserProfile(userId: String, nickname: String, email: String) {
        prefs.edit().apply {
            putString(KEY_USER_ID,  userId)
            putString(KEY_NICKNAME, nickname)
            putString(KEY_EMAIL,    email)
        }.apply()
    }

    /** 토큰 만료 시 갱신 */
    fun updateAccessToken(newToken: String) {
        prefs.edit().putString(KEY_ACCESS, newToken).apply()
    }

    fun getAccessToken(): String? = prefs.getString(KEY_ACCESS,   null)
    fun getUserId():      String? = prefs.getString(KEY_USER_ID,  null)
    fun getNickname():    String? = prefs.getString(KEY_NICKNAME, null)
    fun getEmail():       String? = prefs.getString(KEY_EMAIL,    null)
    fun isLoggedIn():     Boolean = getAccessToken() != null

    /** 로그아웃 시 전부 삭제 */
    fun clear() = prefs.edit().clear().apply()
}