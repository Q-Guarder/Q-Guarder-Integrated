package com.qguarder.android.data.local

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import javax.inject.Inject
import javax.inject.Singleton

/**
 * 사용자 앱 설정 저장소 (다크모드, 히스토리 보관 기간)
 * 보안 민감 데이터가 아니므로 일반 SharedPreferences 사용
 */
@Singleton
class UserPreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val PREFS_NAME            = "user_preferences"
        private const val KEY_DARK_MODE         = "dark_mode"
        private const val KEY_HISTORY_RETENTION = "history_retention_days"
        const val RETENTION_ALL = -1
    }

    private val prefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private val _darkModeEnabled = MutableStateFlow(
        prefs.getBoolean(KEY_DARK_MODE, false)
    )
    val darkModeEnabled: StateFlow<Boolean> = _darkModeEnabled.asStateFlow()

    private val _historyRetentionDays = MutableStateFlow(
        prefs.getInt(KEY_HISTORY_RETENTION, RETENTION_ALL)
    )
    val historyRetentionDays: StateFlow<Int> = _historyRetentionDays.asStateFlow()

    fun setDarkMode(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_DARK_MODE, enabled).apply()
        _darkModeEnabled.value = enabled
    }

    fun setHistoryRetention(days: Int) {
        prefs.edit().putInt(KEY_HISTORY_RETENTION, days).apply()
        _historyRetentionDays.value = days
    }

    fun isDarkModeEnabled(): Boolean = prefs.getBoolean(KEY_DARK_MODE, false)
    fun getHistoryRetentionDays(): Int = prefs.getInt(KEY_HISTORY_RETENTION, RETENTION_ALL)
}
