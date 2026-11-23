package com.qguarder.android.data.local

import androidx.room.*
import kotlinx.coroutines.flow.Flow

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Entity (테이블 구조)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/* 안전한 URL 화이트리스트 — 이 목록에 있으면 서버 요청 없이 바로 Safe */
@Entity(tableName = "whitelist")
data class WhitelistEntity(
    @PrimaryKey val url: String,
    val addedAt: Long = System.currentTimeMillis(),
)

/* 즐겨찾기 로컬 캐시 — 서버 동기화 전 빠른 조회용 */
@Entity(tableName = "favorites_cache")
data class FavoriteCacheEntity(
    @PrimaryKey val favoriteId: String,
    val url:       String,
    val title:     String?,
    val riskLevel: String?,
    val addedAt:   String,
)

/* 스캔 로그 캐시 - 오프라인 대비용 */
@Entity(tableName = "scan_log_cache")
data class ScanLogCacheEntity(
    @PrimaryKey val scanId: String,
    val url: String, val riskLevel: String,
    val finalScore: Int = 0, val scannedAt: String,
)

@Entity(tableName = "scan_summary_cache")
data class ScanSummaryCacheEntity(
    @PrimaryKey val id: Int = 0,  // 항상 단일 행
    val totalScans: Int, val securedCount: Int,
    val suspiciousCount: Int = 0,
    val blockedCount: Int, val reportedCount: Int,
)

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DAO (데이터 접근 객체)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@Dao
interface WhitelistDao {
    @Query("SELECT COUNT(*) > 0 FROM whitelist WHERE url = :url")
    suspend fun isWhitelisted(url: String): Boolean

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insert(entity: WhitelistEntity)

    @Delete
    suspend fun delete(entity: WhitelistEntity)

    @Query("SELECT * FROM whitelist ORDER BY addedAt DESC")
    suspend fun getAll(): List<WhitelistEntity>
}

@Dao
interface FavoriteCacheDao {

    @Query("SELECT COUNT(*) > 0 FROM favorites_cache WHERE url = :url")
    suspend fun isFavorited(url: String): Boolean

    // flow로 목록 실시간 반영 - suspend제거
    @Query("SELECT * FROM favorites_cache ORDER BY addedAt DESC")
    fun getAll(): Flow<List<FavoriteCacheEntity>>

    // room 단건 추가, replace로 중복추가 방지 용도
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: FavoriteCacheEntity)

    // 서버 유저 동기화용
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(favorites: List<FavoriteCacheEntity>)

    // 즐겨찾기 여부 확인용
    @Query("SELECT * FROM favorites_cache WHERE url = :url LIMIT 1")
    suspend fun getByUrl(url: String): FavoriteCacheEntity?

    // 트랜잭션으로 감싸기
    @Transaction
    suspend fun replaceAll(entities: List<FavoriteCacheEntity>) {
        clearAll()
        insertAll(entities)
    }

    // room 단건 삭제, id는 프라이머리키라서 url로 대체
    @Query("DELETE FROM favorites_cache WHERE url = :url")
    suspend fun deleteByUrl(url: String)

    // 서버 동기화용
    @Query("DELETE FROM favorites_cache")
    suspend fun clearAll()
}

@Dao
interface ScanLogCacheDao {

    @Query("SELECT * FROM scan_log_cache ORDER BY scannedAt DESC")
    suspend fun getLogs(): List<ScanLogCacheEntity>

    /** 서버 장애 시 URL로 이전 스캔 결과 조회 (가장 최근 것) */
    @Query("SELECT * FROM scan_log_cache WHERE url = :url ORDER BY scannedAt DESC LIMIT 1")
    suspend fun getByUrl(url: String): ScanLogCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertLogs(logs: List<ScanLogCacheEntity>)

    @Query("DELETE FROM scan_log_cache")
    suspend fun clearLogs()

    @Query("SELECT * FROM scan_summary_cache WHERE id = 0 LIMIT 1")
    suspend fun getSummary(): ScanSummaryCacheEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSummary(summary: ScanSummaryCacheEntity)

    @Transaction
    suspend fun replaceAll(logs: List<ScanLogCacheEntity>, summary: ScanSummaryCacheEntity) {
        clearLogs()
        insertLogs(logs)
        saveSummary(summary)
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Database
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@Database(
    entities = [WhitelistEntity::class, FavoriteCacheEntity::class, ScanLogCacheEntity::class, ScanSummaryCacheEntity::class],
    version = 3,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun whitelistDao(): WhitelistDao
    abstract fun favoriteCacheDao(): FavoriteCacheDao
    abstract fun scanLogCacheDao(): ScanLogCacheDao
}
