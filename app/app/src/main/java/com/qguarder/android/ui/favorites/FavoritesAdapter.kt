package com.qguarder.android.ui.favorites

import android.content.res.ColorStateList
import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.qguarder.android.data.local.FavoriteCacheEntity
import com.qguarder.android.databinding.ItemFavoriteBinding

class FavoritesAdapter(
    private val onItemClick: (String) -> Unit,
    private val onDeleteClick: (String) -> Unit
) : ListAdapter<FavoriteCacheEntity, FavoritesAdapter.FavoriteViewHolder>(DiffCallback) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): FavoriteViewHolder {
        val binding = ItemFavoriteBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return FavoriteViewHolder(binding)
    }

    override fun onBindViewHolder(holder: FavoriteViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class FavoriteViewHolder(private val binding: ItemFavoriteBinding) :
        RecyclerView.ViewHolder(binding.root) {

        fun bind(favorite: FavoriteCacheEntity) {
            binding.tvUrl.text = favorite.url

            // riskLevel에 따라 아이콘 배경색 변경
            val bgColor = when (favorite.riskLevel?.uppercase()) {
                "BLOCKED"    -> 0xFFE53935.toInt()  // 빨강
                "SUSPICIOUS" -> 0xFFFF8F00.toInt()  // 주황
                else         -> 0xFF3D5AFE.toInt()  // 파랑 (SECURED or null)
            }
            binding.viewRiskBg.backgroundTintList = ColorStateList.valueOf(bgColor)

            binding.root.setOnClickListener { onItemClick(favorite.url) }
            binding.btnDelete.setOnClickListener { onDeleteClick(favorite.url) }
        }
    }

    companion object {
        private val DiffCallback = object : DiffUtil.ItemCallback<FavoriteCacheEntity>() {
            override fun areItemsTheSame(oldItem: FavoriteCacheEntity, newItem: FavoriteCacheEntity): Boolean {
                return oldItem.favoriteId == newItem.favoriteId
            }

            override fun areContentsTheSame(oldItem: FavoriteCacheEntity, newItem: FavoriteCacheEntity): Boolean {
                return oldItem == newItem
            }
        }
    }
}