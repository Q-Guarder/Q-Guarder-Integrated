package com.qguarder.android.domain.model

enum class RiskLevel(val label: String) {
    SECURED("안전"),
    SUSPICIOUS("주의"),
    BLOCKED("위험");

    val isBlocked:    Boolean get() = this == BLOCKED
    val isSuspicious: Boolean get() = this == SUSPICIOUS
    val isSafe:       Boolean get() = this == SECURED

    companion object {
        // 알 수 없는 값은 BLOCKED으로 처리 — 보안 앱 원칙상 모르면 차단이 안전
        fun from(value: String) = entries.firstOrNull { it.name == value } ?: BLOCKED

        /** 이력 목록(scan-logs, visits, bookmarks)에서 risk_level 문자열 → 한글 레이블 */
        fun labelOf(code: String): String = when (code) {
            "SECURED"    -> "안전"
            "SUSPICIOUS" -> "주의"
            "BLOCKED"    -> "위험"
            "REPORTED"   -> "신고됨"
            else         -> code
        }
    }
}

data class ScanResult(
    val scanId:            String,
    val url:               String,
    val riskLevel:         RiskLevel,
    val riskLabel:         String,      // 서버 제공 한글 레이블 ("안전", "주의", "위험")
    val riskDescription:   String,      // 서버 제공 설명 문구
    val finalScore:        Int,         // 0~100 정수
    val vtTotalEngines:    Int,
    val vtDetectedEngines: Int,
    val xaiFeatures:       List<XaiItem>,
    val scannedAt:         String,
)

data class XaiItem(
    val title:        String,   // 한글 피처명 (서버 제공)
    val description:  String,   // 사용자 설명 문구 (서버 제공)
    val severity:     String,   // "high" | "medium" | "low"
    val contribution: Int,      // 기여도 0~100 (정수)
)

data class ScanStats(
    val totalScans:      Int,
    val securedCount:    Int,
    val suspiciousCount: Int = 0,
    val blockedCount:    Int,
    val reportedCount:   Int,
)

data class LogEntry(
    val scanId:    String,
    val url:       String,
    val riskLevel: RiskLevel,
    val scannedAt: String,
)

data class Bookmark(
    val bookmarkId: String,
    val url:        String,
    val title:      String?,
    val riskLevel:  RiskLevel,
    val createdAt:  String,
)

data class VisitEntry(
    val url:       String,
    val riskLevel: RiskLevel,
    val visitedAt: String,
)

data class User(
    val userId:   String,
    val email:    String,
    val nickname: String,
)