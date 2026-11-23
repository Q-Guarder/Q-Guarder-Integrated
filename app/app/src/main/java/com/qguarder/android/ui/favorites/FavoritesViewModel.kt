package com.qguarder.android.ui.favorites

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.qguarder.android.data.local.FavoriteCacheEntity
import com.qguarder.android.data.local.FavoriteRepository
import com.qguarder.android.data.remote.BookmarkRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class FavoritesViewModel @Inject constructor(
    private val favoriteRepository: FavoriteRepository,
    private val bookmarkRepository: BookmarkRepository
) : ViewModel() {

    val favorites: StateFlow<List<FavoriteCacheEntity>> =
        favoriteRepository.getAll()
            .stateIn(
                scope = viewModelScope,
                started = SharingStarted.WhileSubscribed(5000),
                initialValue = emptyList()
            )

    // 에러 핸들링 변수
    private val _error = MutableSharedFlow<String>()
    val error: SharedFlow<String> = _error

    // 서버와 동기
    private val _isSyncing = MutableStateFlow(true)  // 처음엔 동기 중
    val isSyncing: StateFlow<Boolean> = _isSyncing.asStateFlow()

    init { refresh() }

    /** 서버에서 즐겨찾기 동기화 (init + Pull-to-Refresh 공용) */
    fun refresh() {
        viewModelScope.launch {
            _isSyncing.value = true
            val success = bookmarkRepository.syncFromServer()
            if (!success) _error.emit("즐겨찾기를 불러올 수 없습니다")
            _isSyncing.value = false
        }
    }

    fun delete(url: String) {
        viewModelScope.launch {
            try {
                val success = bookmarkRepository.remove(url)
                if (!success) _error.emit("삭제에 실패했습니다")
            } catch (e: Exception) {
                _error.emit("삭제에 실패했습니다")
            }
        }
    }
}