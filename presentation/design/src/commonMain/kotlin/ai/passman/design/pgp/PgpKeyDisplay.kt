package ai.passman.design.pgp

import ai.passman.design.core.button.passmanButtonBorder
import ai.passman.design.passmanColors
import ai.passman.domain.pgp.model.PgpKeyPair
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedIconButton
import androidx.compose.material3.SecondaryTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

private val tabs = mutableListOf("Primary Key", "User Ids", "Sub Keys")

@Composable
fun PgpKeyDisplay(
    pgpKeyPair: PgpKeyPair,
    onToolsClicked: () -> Unit,
    onAddUserId: () -> Unit,
    onRemoveUserId: (Int) -> Unit,
    onRevokeUserId: (Int) -> Unit,
    onAddSubKey: () -> Unit,
    onRevokeSubKey: (Int) -> Unit,
    onRemoveSubKey: (Int) -> Unit,
    onChangeExpirationDate: () -> Unit,
    onChangeExpirationDateSub: (Int) -> Unit,
    onChangePassword: () -> Unit,
    onShareKeyClick: () -> Unit,
    onExportPrivateKey: () -> Unit,
    onDeleteKeyClick: () -> Unit,
) {
    var selectedTabIndex by remember { mutableStateOf(0) }

    Column(
        modifier = Modifier.background(MaterialTheme.colorScheme.background)
    ) {
        SecondaryTabRow(
            selectedTabIndex = selectedTabIndex,
            indicator = {
                TabRowDefaults.SecondaryIndicator(
                    modifier = Modifier.tabIndicatorOffset(selectedTabIndex),
                    color = MaterialTheme.colorScheme.onSurface,
                )
            },
        ) {
            tabs.forEachIndexed { index, text ->
                Tab(
                    modifier = Modifier.background(MaterialTheme.colorScheme.primary),
                    text = {
                        Text(
                            modifier = Modifier.padding(5.dp),
                            text = text,
                        )
                    },
                    selected = selectedTabIndex == index,
                    onClick = { selectedTabIndex = index }
                )
            }
        }

        Card(
            modifier = Modifier.fillMaxSize(),
            elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
        ) {
            when (selectedTabIndex) {
                0 -> PgpKeyDetails(
                    pgpKeyPair = pgpKeyPair,
                    onToolsClicked = onToolsClicked,
                    onChangeExpirationDate = onChangeExpirationDate,
                    onChangePassword = onChangePassword,
                    onShareKeyClick = onShareKeyClick,
                    onExportPrivateKey = onExportPrivateKey,
                    onDeleteKeyClick = onDeleteKeyClick,
                )

                1 -> UserIds(
                    keyPair = pgpKeyPair,
                    onAddUserId = onAddUserId,
                    onRemoveUserId = onRemoveUserId,
                    onRevokeUserId = onRevokeUserId,
                )

                2 -> SubKeyDetails(
                    keyPair = pgpKeyPair,
                    onAddSubKey = onAddSubKey,
                    onRemoveSubKey = onRemoveSubKey,
                    onRevokeSubKey = onRevokeSubKey,
                    onChangeExpirationDateSub = onChangeExpirationDateSub,
                )
            }
        }
    }
}

@Composable
fun PgpKeyDetails(
    pgpKeyPair: PgpKeyPair,
    onToolsClicked: () -> Unit,
    onChangeExpirationDate: () -> Unit,
    onChangePassword: () -> Unit,
    onShareKeyClick:() -> Unit,
    onExportPrivateKey: () -> Unit,
    onDeleteKeyClick: () -> Unit,
) {
    Column(modifier = Modifier.padding(16.dp)) {
        pgpKeyPair.publicKey.fileName.takeIf { it.isNotBlank() }?.let { fileName ->
            Text(
                text = fileName,
                style = MaterialTheme.typography.titleMedium,
            )
            Spacer(modifier = Modifier.height(8.dp))
        }
        Row(
            modifier = Modifier.fillMaxWidth(),
            // horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                // name, email
                // type: Sec and pub, or pub
                Text("Key Type: ${when {
                    pgpKeyPair.secretKey != null -> "Sec/Pub"
                    pgpKeyPair.secretKey == null -> "Pub"
                    else -> error("not supported")
                }}")
                Text("Key ID: ${longToHex(pgpKeyPair.publicKey.keyId).takeLast(8)}")
                Text("Algorithm: ${pgpKeyPair.publicKey.algorithm}")
                Text("Bit Strength: ${pgpKeyPair.publicKey.bitStrength}")
                Text("Creation Time: ${Instant.fromEpochMilliseconds(pgpKeyPair.publicKey.creationTime).toLocalDateTime(TimeZone.currentSystemDefault()).date}")
                pgpKeyPair.publicKey.expirationTime?.let {
                    Text("Expiration Time: ${Instant.fromEpochMilliseconds(pgpKeyPair.publicKey.creationTime).toLocalDateTime(TimeZone.currentSystemDefault()).date}")
                }
                // Text("User IDs: ${key.userIds.joinToString()}")
                Spacer(modifier = Modifier.height(8.dp))
                Text("Fingerprint: ${pgpKeyPair.publicKey.fingerprint}")
            }
        }

        Icon(
            imageVector = if (pgpKeyPair.publicKey.isRevoked) Icons.Filled.Warning else Icons.Filled.Check,
            contentDescription = if (pgpKeyPair.publicKey.isRevoked) "Revoked" else "Active",
            tint = if (pgpKeyPair.publicKey.isRevoked) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.passmanColors.success
            },
            modifier = Modifier.align(Alignment.End),
        )

        Spacer(modifier = Modifier.weight(1f))

        KeyDetailsActionRow(
            onToolsClicked = onToolsClicked,
            onChangeExpirationDate = onChangeExpirationDate,
            onChangePassword = onChangePassword,
            onShareKeyClick = onShareKeyClick,
            onDeleteKeyClick = onDeleteKeyClick,
        )

        // Deliberately separate from the Share icon: Share only ever emits the public ring,
        // export is its own guarded flow and exists only when a secret key is present.
        if (pgpKeyPair.secretKey != null) {
            TextButton(
                modifier = Modifier.align(Alignment.CenterHorizontally),
                onClick = onExportPrivateKey,
            ) {
                Text("Export private key…")
            }
        }
    }
}

val userIdHeaders = mutableListOf("Name", "Email")
@Composable
fun UserIds(
    keyPair: PgpKeyPair,
    onAddUserId: () -> Unit,
    onRemoveUserId: (Int) -> Unit,
    onRevokeUserId: (Int) -> Unit,
) {
    val selectedRow = remember { mutableStateOf(-1) }  // -1 means no selection
    val key = keyPair.publicKey

    Column(
        modifier = Modifier.padding(16.dp),
    ) {
        Row {
            userIdHeaders.forEach { title ->
                Text(
                    text = title,
                    modifier = Modifier
                        .weight(1f)
                        .padding(8.dp),
//                    color = MaterialTheme.colorScheme.onSurface,
//                    style = MaterialTheme.typography.titleLarge,
//                    fontWeight = FontWeight.SemiBold,
//                    textAlign = TextAlign.Start,
                )
            }
        }

        HorizontalDivider()

        LazyColumn {
            items(key.userIds) {
                val index = key.userIds.indexOf(it)
                val isSelected = selectedRow.value == index
                Row(
                    modifier = Modifier
                        .clickable { selectedRow.value = if (isSelected) -1 else index }
                        .background(
                            if (isSelected) MaterialTheme.colorScheme.secondary.copy(alpha = 0.3f) else Color.Transparent,
                        )
                ) {
                    Text(
                        text = it.name,
                        modifier = Modifier.weight(1f).padding(8.dp),
                        style = TextStyle(textDecoration = if (it.isRevoked) TextDecoration.LineThrough else TextDecoration.None)
                    )
                    Text(
                        text = it.email,
                        modifier = Modifier.weight(1f).padding(8.dp),
                        style = TextStyle(textDecoration = if (it.isRevoked) TextDecoration.LineThrough else TextDecoration.None)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        if (keyPair.secretKey != null) {
            // add
            // revoke
            Row(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                if (selectedRow.value > -1) {
                    // Outlined icon buttons: the old transparent-container Buttons had zero
                    // affordance — nothing marked the icons as pressable.
                    OutlinedIconButton(
                        onClick = {
                            onRemoveUserId(selectedRow.value)
                        },
                        border = passmanButtonBorder(),
                    ) {
                        Icon(imageVector = Icons.Filled.Delete, contentDescription = "Remove user id")
                    }

                    OutlinedIconButton(
                        onClick = {
                            onRevokeUserId(selectedRow.value)
                        },
                        modifier = Modifier.padding(start = 8.dp),
                        border = passmanButtonBorder(),
                    ) {
                        Icon(imageVector = Icons.Filled.Clear, contentDescription = "Revoke user id")
                    }
                } else {
                    ExtendedFloatingActionButton(
                        onClick = onAddUserId,
                        icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                        text = { Text("Add user ID") },
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    )
                }
            }
        }
    }
}

@Composable
fun SubKeyDetails(
    keyPair: PgpKeyPair,
    onAddSubKey: () -> Unit,
    onRemoveSubKey: (Int) -> Unit,
    onRevokeSubKey: (Int) -> Unit,
    onChangeExpirationDateSub: (Int) -> Unit,
) {
    val selectedRow = remember { mutableStateOf(-1) }  // -1 means no selection
    val key = keyPair.publicKey

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(key.subKeys) {
                val index = key.subKeys.indexOf(it)
                val isSelected = selectedRow.value == index
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { selectedRow.value = if (isSelected) -1 else index },
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) {
                            MaterialTheme.colorScheme.secondary.copy(alpha = 0.3f)
                        } else {
                            MaterialTheme.colorScheme.surfaceContainer
                        },
                        contentColor = MaterialTheme.colorScheme.onSurface,
                    ),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(4.dp),
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(
                                text = longToHex(it.keyId).takeLast(8),
                                modifier = Modifier.weight(1f),
                                style = MaterialTheme.typography.titleMedium.copy(
                                    fontFamily = FontFamily.Monospace,
                                    textDecoration = if (it.isRevoked) TextDecoration.LineThrough else TextDecoration.None,
                                ),
                            )
                            if (it.isRevoked) {
                                Surface(
                                    color = MaterialTheme.colorScheme.errorContainer,
                                    contentColor = MaterialTheme.colorScheme.onErrorContainer,
                                    shape = MaterialTheme.shapes.small,
                                ) {
                                    Text(
                                        text = "Revoked",
                                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                            }
                        }
                        Text(
                            text = "${it.algorithm} · ${it.bitStrength} bit",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                        val creationDate = Instant.fromEpochMilliseconds(it.creationTime)
                            .toLocalDateTime(TimeZone.currentSystemDefault())
                            .date
                        val expirationText = it.expirationTime?.let { expirationTime ->
                            "Expires ${Instant.fromEpochMilliseconds(expirationTime).toLocalDateTime(TimeZone.currentSystemDefault()).date}"
                        } ?: "No expiry"
                        Text(
                            text = "Created $creationDate · $expirationText",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        if (keyPair.secretKey != null) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                if (selectedRow.value > -1) {
                    TextButton(
                        onClick = { onRemoveSubKey(selectedRow.value) },
                    ) {
                        Text(
                            text = "Remove",
                            color = MaterialTheme.colorScheme.error,
                        )
                    }

                    TextButton(
                        onClick = { onRevokeSubKey(selectedRow.value) },
                    ) {
                        Text("Revoke")
                    }
                } else {
                    ExtendedFloatingActionButton(
                        onClick = onAddSubKey,
                        icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                        text = { Text("Add subkey") },
                        containerColor = MaterialTheme.colorScheme.primary,
                        contentColor = MaterialTheme.colorScheme.onPrimary,
                    )
                }
            }
        }
    }
}

// longToHex moved to HexFormatting.kt in commonMain
