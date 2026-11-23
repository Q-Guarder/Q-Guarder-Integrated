package com.qguarder.android.data.remote.dto

import com.google.gson.annotations.SerializedName

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 공통 Envelope
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class ApiResponse<T>(
    val success:   Boolean,
    val data:      T?,
    val error:     ApiError?,
    val timestamp: String,
)
data class ApiError(val code: String, val message: String)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Auth — 이메일/비밀번호
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class RegisterRequest(
    val email:    String,
    val password: String,
    val nickname: String,
)
data class RegisterResponse(
    @SerializedName("user_id")    val userId:    String,
    val email:                                   String,
    val nickname:                                String,
    @SerializedName("created_at") val createdAt: String,
)

// GET /api/v1/users/me — register 응답과 동일한 구조이므로 typealias 사용
typealias MeResponse = RegisterResponse

data class LoginRequest(
    val email:    String,
    val password: String,
)
data class LoginResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("token_type")   val tokenType:   String,
)
// Refresh Token은 HttpOnly 쿠키로 자동 관리 — 별도 필드 없음
data class RefreshResponse(
    @SerializedName("access_token") val accessToken: String,
    @SerializedName("token_type")   val tokenType:   String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Scan — v4.0 (risk_level 객체, final_score 정수, xai_features 리스트)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class ScanRequest(
    val url:    String,
    val source: String = SOURCE_CAMERA,
) {
    companion object {
        const val SOURCE_CAMERA = "camera"
        const val SOURCE_MANUAL = "manual"
    }
}

data class ScanResponse(
    @SerializedName("scan_id")              val scanId:             String,
    val url:                                                        String,
    @SerializedName("risk_level")           val riskLevel:          RiskLevelDto,
    @SerializedName("final_score")          val finalScore:         Int,     // 0 ~ 100 (정수)
    @SerializedName("vt_total_engines")     val vtTotalEngines:     Int,
    @SerializedName("vt_detected_engines")  val vtDetectedEngines:  Int,
    @SerializedName("xai_features")         val xaiFeatures:        List<XaiFeatureDetailDto>,
    @SerializedName("scanned_at")           val scannedAt:          String,
)

/** risk_level 객체 — 서버에서 code/label/description 제공 */
data class RiskLevelDto(
    val code:        String,   // SECURED | SUSPICIOUS | BLOCKED
    val label:       String,   // 안전 | 주의 | 위험
    val description: String,   // 사용자 안내 문구
)

/** XAI 피처 상세 — 서버에서 한글 title/description 제공, contribution 내림차순 최대 5개 */
data class XaiFeatureDetailDto(
    val title:        String,   // 한글 피처명
    val description:  String,   // 사용자 설명 문구
    val severity:     String,   // "high" | "medium" | "low"
    val contribution: Int,      // 기여도 0~100 (정수)
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Report
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class ReportRequest(
    @SerializedName("scan_log_id") val scanLogId: String,
    val url:                                      String,
    val reason:                                   String,
)
data class ReportResponse(
    @SerializedName("report_id") val reportId: String,
    val status:                                String,
    val message:                               String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Scan Logs (대시보드)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class ScanLogsResponse(
    val total:   Int = 0,
    val summary: ScanSummaryDto,
    val logs:    List<ScanLogItemDto>,
)
data class ScanSummaryDto(
    @SerializedName("total_scans")      val totalScans:      Int,
    @SerializedName("secured_count")    val securedCount:    Int,
    @SerializedName("suspicious_count") val suspiciousCount: Int = 0,
    @SerializedName("blocked_count")    val blockedCount:    Int,
    @SerializedName("reported_count")   val reportedCount:   Int,
)
data class ScanLogItemDto(
    @SerializedName("scan_id")     val scanId:    String,
    val url:                                      String,
    @SerializedName("risk_level")  val riskLevel: String,
    @SerializedName("final_score") val finalScore: Int = 0,
    @SerializedName("scanned_at")  val scannedAt: String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Bookmarks
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class BookmarksResponse(val total: Int = 0, val items: List<BookmarkItemDto>)
data class BookmarkItemDto(
    @SerializedName("bookmark_id") val bookmarkId: String,
    val url:                                       String,
    val title:                                     String?,
    @SerializedName("risk_level")  val riskLevel:  String,
    @SerializedName("created_at")  val createdAt:  String,
)
data class AddBookmarkRequest(
    val url:   String,
    val title: String? = null,
)
data class AddBookmarkResponse(
    @SerializedName("bookmark_id") val bookmarkId: String,
    @SerializedName("created_at")  val createdAt:  String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Visit History (신규 v3.0)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class AddVisitRequest(
    val url:        String,
    @SerializedName("risk_level") val riskLevel: String,
)
data class AddVisitResponse(
    @SerializedName("visit_id")   val visitId:   String,
    @SerializedName("visited_at") val visitedAt: String,
)
data class VisitsResponse(
    val items: List<VisitItemDto>,
    val total: Int,
)
data class VisitItemDto(
    val url:                                       String,
    @SerializedName("risk_level")  val riskLevel:  String,
    @SerializedName("visited_at")  val visitedAt:  String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// User Update
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class UpdateNicknameRequest(
    val nickname: String,
)
data class UpdatePasswordRequest(
    @SerializedName("current_password") val currentPassword: String,
    @SerializedName("new_password")     val newPassword:     String,
)
data class DeleteAccountRequest(
    val password: String,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Health
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
data class HealthData(
    val status:  String,
    val version: String,
    val model:   String,
    val checks:  Map<String, String>,
)
