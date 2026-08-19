package ai.passman.design.home

import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.DrawerBody
import ai.passman.design.core.DrawerTopBar
import ai.passman.design.core.model.MenuItem
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.DrawerState
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material3.ripple
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

@Composable
fun MainContent(
    title: String,
    menuItems: List<MenuItem>,
    showDrawer: Boolean,
    showBackButton: Boolean,
    showActionButton: Boolean,
    fabMenu: Map<String, ()-> Unit>,
    drawerState: DrawerState,
    snackbarHostState: SnackbarHostState,
    onLeftButtonClick: () -> Unit,
    onMenuItemClick: (MenuItem) -> Unit,
    onActionButtonClick: () -> Unit,
    topBarActions: @Composable RowScope.() -> Unit = {},
    topBarOverride: (@Composable () -> Unit)? = null,
    mainContent: @Composable () -> Unit,
) {
    val scope = rememberCoroutineScope()
    var menuExpanded by remember { mutableStateOf(false) }
    ModalNavigationDrawer(
        drawerState = drawerState,
        gesturesEnabled = showDrawer,
        drawerContent = {
            ModalDrawerSheet {
                DrawerBody(
                    modifier = Modifier.windowInsetsPadding(WindowInsets.statusBars),
                    menuItems = menuItems,
                    drawerState = drawerState,
                    scope = scope,
                    onItemClick = {
                        scope.launch {
                            drawerState.close()
                            onMenuItemClick(it)
                        }
                    },
                )
            }
        },
    ) {
        Scaffold(
            topBar = {
                if (topBarOverride != null) {
                    topBarOverride()
                } else {
                    DrawerTopBar(
                        modifier = Modifier.background(MaterialTheme.colorScheme.primary),
                        title = title,
                        imageVector = if (showBackButton) {
                            Icons.AutoMirrored.Filled.ArrowBack
                        } else if (showDrawer) {
                            Icons.Default.Menu
                        } else null,
                        onButtonClick = onLeftButtonClick,
                        actions = topBarActions,
                    )
                }
            },
            snackbarHost = { SnackbarHost(snackbarHostState) },
            // The top bar consumes the status-bar inset itself (and paints primary behind it);
            // letting the scaffold add the system insets again would shove the whole bar down
            // and leave a background-colored strip above it.
            contentWindowInsets = WindowInsets(0, 0, 0, 0),
            floatingActionButton = {
                if (showActionButton) {
                    Column {
                        if (fabMenu.isNotEmpty() && menuExpanded) {
                            fabMenu.forEach { (key, value) ->
                                // Primary fill + outline edge, matching the FAB below: the old
                                // surface fill floated white-on-white over list screens in
                                // light mode.
                                PassmanPrimaryButton(
                                    text = key,
                                    onClick = {
                                        menuExpanded = !menuExpanded
                                        value()
                                    },
                                    modifier = Modifier
                                        .padding(10.dp)
                                        .clickable(
                                            interactionSource = remember { MutableInteractionSource() },
                                            indication = ripple(bounded = false),
                                            onClick = {}
                                        ),
                                    fontSize = 18.sp,
                                )
                            }
                        }

                        FloatingActionButton(
                            modifier = Modifier.align(Alignment.End),
                            onClick = {
                                if (fabMenu.isNotEmpty()) {
                                    menuExpanded = !menuExpanded
                                } else {
                                    onActionButtonClick()
                                }
                            },
                            containerColor = MaterialTheme.colorScheme.primary,
                            contentColor = MaterialTheme.colorScheme.onPrimary,
                        ) {
                            Icon(Icons.Filled.Add, "")
                        }
                    }
                }
            },
        ) { paddingValues ->
            // M3's Scaffold overlays content behind the top bar and reports the bar's height
            // through paddingValues — unlike M2, which reserved the bar's space in the layout.
            // Consuming it here restores the M2 placement every screen was written against.
            Box(Modifier.padding(paddingValues)) {
                mainContent()
            }
        }
    }
}
