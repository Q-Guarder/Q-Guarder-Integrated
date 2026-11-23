package com.qguarder.android.ui.favorites

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AnimationUtils
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import com.qguarder.android.R
import com.qguarder.android.data.local.CustomTabsHelper
import com.qguarder.android.databinding.FragmentFavoritesBinding
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.launch

@AndroidEntryPoint
class FavoritesFragment : Fragment() {

    private var _binding: FragmentFavoritesBinding? = null
    private val binding get() = _binding!!
    private var hasAnimatedList = false

    private val favoritesAdapter by lazy {
        FavoritesAdapter(
            onItemClick   = { url -> CustomTabsHelper.open(requireContext(), url) },
            onDeleteClick = { url -> viewModel.delete(url) }
        )
    }

    private val viewModel: FavoritesViewModel by viewModels()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        _binding = FragmentFavoritesBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.rvFavorites.adapter = favoritesAdapter
        binding.rvFavorites.layoutManager = LinearLayoutManager(requireContext())

        // Pull-to-Refresh
        binding.swipeRefresh.setColorSchemeColors(0xFF3D5AFE.toInt())
        binding.swipeRefresh.setOnRefreshListener { viewModel.refresh() }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    viewModel.favorites.collect { list ->
                        favoritesAdapter.submitList(list)

                        val empty = list.isEmpty()
                        // 빈 상태 크로스페이드
                        if (empty) {
                            binding.rvFavorites.animate().alpha(0f).setDuration(250).withEndAction {
                                binding.rvFavorites.visibility = View.GONE
                            }.start()
                            binding.layoutEmpty.visibility = View.VISIBLE
                            binding.layoutEmpty.alpha = 0f
                            binding.layoutEmpty.animate().alpha(1f).setDuration(250).start()
                        } else {
                            binding.layoutEmpty.animate().alpha(0f).setDuration(250).withEndAction {
                                binding.layoutEmpty.visibility = View.GONE
                            }.start()
                            binding.rvFavorites.visibility = View.VISIBLE
                            binding.rvFavorites.alpha = 1f
                            // 최초 데이터 수신 시 layoutAnimation 적용
                            if (!hasAnimatedList) {
                                hasAnimatedList = true
                                val anim = AnimationUtils.loadLayoutAnimation(
                                    requireContext(), R.anim.layout_animation_fall_down
                                )
                                binding.rvFavorites.layoutAnimation = anim
                                binding.rvFavorites.scheduleLayoutAnimation()
                            }
                        }
                    }
                }
                launch {
                    viewModel.error.collect { message ->
                        Toast.makeText(requireContext(), message, Toast.LENGTH_SHORT).show()
                    }
                }
                launch {
                    viewModel.isSyncing.collect { syncing ->
                        binding.swipeRefresh.isRefreshing = syncing
                        // 동기화 중 alpha 전환 (즉시 → 부드럽게)
                        val target = if (syncing) 0.5f else 1f
                        binding.rvFavorites.animate().alpha(target).setDuration(200).start()
                    }
                }
            }
        }
    }

    override fun onDestroyView() { super.onDestroyView(); _binding = null }
}
