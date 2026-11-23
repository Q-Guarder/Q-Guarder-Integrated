package com.qguarder.android.ui.result

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.local.FavoriteRepository
import com.qguarder.android.data.remote.BookmarkRepository
import com.qguarder.android.data.remote.UrlRepository
import com.qguarder.android.domain.model.RiskLevel
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class ResultViewModel @Inject constructor(
    private val favoriteRepository: FavoriteRepository,
    private val bookmarkRepository: BookmarkRepository,
    private val urlRepository: UrlRepository,
) : ViewModel() {

    private val _isFavorite = MutableStateFlow(false)
    val isFavorite = _isFavorite.asStateFlow()

    fun checkFavorite(url: String) {
        viewModelScope.launch {
            _isFavorite.value = favoriteRepository.isFavorite(url)
        }
    }

    fun recordVisit(url: String, riskLevel: RiskLevel) {
        viewModelScope.launch {
            urlRepository.recordVisit(url, riskLevel)
        }
    }

    fun toggleFavorite(url: String, title: String?, riskLevel: String) {
        viewModelScope.launch {
            try {
                if (_isFavorite.value) {
                    bookmarkRepository.remove(url)
                    // remove는 서버 성공 시에만 로컬도 삭제하므로, 로컬 상태 재확인
                    _isFavorite.value = favoriteRepository.isFavorite(url)
                } else {
                    val success = bookmarkRepository.add(url, title, riskLevel)
                    if (success) _isFavorite.value = true
                }
            } catch (_: Exception) {
                // 네트워크 에러 시 상태 유지 (아무것도 안 함)
            }
        }
    }
}