package ai.passman.design.core

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight

@Composable
fun TabTitle(
    selectedTabIndex: Int,
    tabNames: List<String>,
    onTabSelected: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
   // SecondaryTabRow rather than PrimaryTabRow: the deprecated TabRow + TabRowDefaults
   // .Indicator pair this replaces is the secondary style, so this keeps the existing look.
   // tabIndicatorOffset here is TabIndicatorScope's, which takes the selected index; the
   // deprecated TabRowDefaults version took a TabPosition.
   SecondaryTabRow(
       modifier = modifier,
       selectedTabIndex = selectedTabIndex,
       indicator = {
           TabRowDefaults.SecondaryIndicator(
               modifier = Modifier.tabIndicatorOffset(selectedTabIndex),
               color = MaterialTheme.colorScheme.onSurface,
           )
       }
   )  {
       tabNames.forEachIndexed { index, tabName ->
           val isTabSelected = selectedTabIndex == index

           Tab(
               content = {
                   Text(
                       modifier = Modifier,
                       text = tabName,
                       fontWeight = if (isTabSelected) FontWeight.Bold else FontWeight.Normal,
                       color = MaterialTheme.colorScheme.onSurface,
                   )
               },
               onClick = {
                   onTabSelected(index)
               },
               selected = isTabSelected,
           )
       }
   }
}
