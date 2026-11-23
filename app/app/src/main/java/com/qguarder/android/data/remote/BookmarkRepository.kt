package com.qguarder.android.data.remote

import com.qguarder.android.data.local.FavoriteCacheDao
import com.qguarder.android.data.local.FavoriteCacheEntity
import com.qguarder.android.data.remote.dto.AddBookmarkRequest
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BookmarkRepository @Inject constructor(
    private val apiService: ApiService,
    private val favoriteCacheDao: FavoriteCacheDao
) {
    // 서버에서 북마크 목록 가져와서 로컬 DB에 저장
    // @return true = 동기화 성공, false = 실패 (ViewModel에서 에러 처리)
    /**
     * 서버에서 북마크 전체 동기화 (첫 페이지 기준)
     * @param page 페이지 번호 (1부터)
     * @param size 페이지 크기
     */
    suspend fun syncFromServer(page: Int = 1, size: Int = 100): Boolean {
        return try {
            val response = apiService.getBookmarks(page = page, size = size)
            if (response.isSuccessful) {
                val items = response.body()?.items ?: return false
                val entities = items.map {
                    FavoriteCacheEntity(
                        favoriteId = it.bookmarkId,
                        url        = it.url,
                        title      = it.title,
                        riskLevel  = it.riskLevel,
                        addedAt    = it.createdAt
                    )
                }
                if (page == 1) {
                    favoriteCacheDao.replaceAll(entities)
                } else {
                    favoriteCacheDao.insertAll(entities)
                }
                true
            } else false
        } catch (_: Exception) {
            false  // 네트워크 오류 — 로컬 캐시 유지, 실패 결과 반환
        }
    }

    // 서버에 북마크 추가 → 서버가 준 bookmark_id로 로컬 DB에 저장
    suspend fun add(url: String, title: String?, riskLevel: String): Boolean {
        return try {
            val response = apiService.addBookmark(AddBookmarkRequest(url, title))
            if (response.isSuccessful) {
                val body = response.body() ?: return false
                favoriteCacheDao.insert(
                    FavoriteCacheEntity(
                        favoriteId = body.bookmarkId,  // 서버가 준 ID 사용
                        url        = url,
                        title      = title,
                        riskLevel  = riskLevel,
                        addedAt    = body.createdAt
                    )
                )
                true
            } else false
        } catch (_: Exception) {
            false  // 네트워크 오류 시 실패 반환
        }
    }

    /** @return true면 삭제 성공, false면 실패 */
    suspend fun remove(url: String): Boolean {
        val entity = favoriteCacheDao.getByUrl(url) ?: return false
        val response = apiService.deleteBookmark(entity.favoriteId)
        if (response.isSuccessful) {
            favoriteCacheDao.deleteByUrl(url)
            return true
        }
        return false
    }
}
