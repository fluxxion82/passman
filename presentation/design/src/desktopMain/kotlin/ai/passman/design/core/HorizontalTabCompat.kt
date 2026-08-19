package ai.passman.design.core

import androidx.compose.foundation.gestures.Orientation
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.pager.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
actual fun HorizontalTabCompat(
    pageCount: Int,
    state: PagerState,
    pageContent: @Composable PagerScope.(page: Int) -> Unit,
    modifier: Modifier,
) {
    HorizontalPager(
        modifier = modifier,
        state = state,
        pageSpacing = 0.dp,
        userScrollEnabled = true,
        reverseLayout = false,
        contentPadding = PaddingValues(0.dp),
        pageSize = PageSize.Fill,
        flingBehavior = PagerDefaults.flingBehavior(state = state),
        key = null,
        pageNestedScrollConnection = PagerDefaults.pageNestedScrollConnection(
            state,
            Orientation.Horizontal
        ),
        pageContent = pageContent
    )
}
