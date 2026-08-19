package ai.passman.design.core

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.pager.PagerScope
import androidx.compose.foundation.pager.PagerState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier

@OptIn(ExperimentalFoundationApi::class)
@Composable
expect fun HorizontalTabCompat(
    pageCount: Int,
    state: PagerState,
    pageContent: @Composable PagerScope.(page: Int) -> Unit,
    modifier: Modifier,
)
