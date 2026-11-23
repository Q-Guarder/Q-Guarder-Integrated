package com.qguarder.android.ui.result

/* Secured·Warning 화면에서 공통으로 사용하는 XAI 피처명 한글화 유틸 */
internal object XaiUtils {
    fun formatFeatureName(raw: String): String {
        val map = mapOf(
            "url_length"       to "URL 길이",
            "has_https"        to "HTTPS 여부",
            "domain_age"       to "도메인 나이",
            "special_chars"    to "특수문자 수",
            "subdomain_count"  to "서브도메인 수",
            "path_depth"       to "경로 깊이",
            "has_ip_address"   to "IP 주소 포함",
            "entropy"          to "URL 복잡도",
        )
        return map[raw] ?: raw.replace('_', ' ')
    }
}
