package com.qguarder.android.util

/**
 * 순수 Kotlin 검증 유틸
 *
 * android.util.Patterns.EMAIL_ADDRESS를 사용하지 않는 이유:
 * JVM 단위 테스트(src/test)에서 Android stub이 static field를 null로 반환해
 * NullPointerException이 발생하기 때문에 순수 정규식으로 대체.
 */
object ValidationUtils {

    // RFC 5321 간소화 버전 — @와 최소 1개의 점(TLD) 요구
    private val EMAIL_REGEX = Regex(
        """^[a-zA-Z0-9+._%\-]{1,256}@[a-zA-Z0-9][a-zA-Z0-9\-]{0,63}(\.[a-zA-Z]{2,})+$"""
    )

    fun isValidEmail(email: String): Boolean = EMAIL_REGEX.matches(email)
}
