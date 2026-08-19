package ai.passman.screens.ui.settings

import ai.passman.design.core.button.PassmanPrimaryButton
import ai.passman.design.core.button.PassmanSecondaryButton
import ai.passman.design.pass.QrCameraScannerDialog
import ai.passman.design.pass.QrCodeImage
import ai.passman.design.pass.cameraQrScanningSupported
import ai.passman.design.passmanColors
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.viewmodel.connectivity.TrustedDevicesViewModel
import ai.passman.viewmodel.connectivity.TrustedDevicesViewModel.PairingEntryMode
import ai.passman.viewmodel.connectivity.TrustedDevicesViewModel.PairingState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.navigation.NavController
import kotlin.time.Instant
import kotlinx.datetime.TimeZone
import kotlinx.datetime.number
import kotlinx.datetime.toLocalDateTime

@Composable
fun TrustedDevicesScreen(navController: NavController, presenter: TrustedDevicesViewModel) {
    val devices by presenter.devices.collectAsState()
    val ownFingerprint by presenter.ownFingerprint.collectAsState()
    val ownIp by presenter.ownIp.collectAsState()
    val pairAddress by presenter.pairAddress.collectAsState()
    val pairName by presenter.pairName.collectAsState()
    val safetyNumberCompared by presenter.safetyNumberCompared.collectAsState()
    val pairingState by presenter.pairingState.collectAsState()
    val entryMode by presenter.entryMode.collectAsState()
    val canConfirm by presenter.canConfirm.collectAsState()

    // Owned by the screen, not by the branch that opens it. The camera stays up across pairing
    // states on purpose: an inbound push that verifies while the user is still lining up the peer's
    // code flips pairingState, and a dialog scoped to the entry branch would be torn down mid-scan —
    // camera released, frame lost — by nothing more than a recomposition.
    var showScanner by remember { mutableStateOf(false) }
    if (showScanner) {
        QrCameraScannerDialog(
            onResult = { scanned ->
                showScanner = false
                presenter.onScanResult(scanned)
            },
            onDismiss = { showScanner = false },
        )
    }

    val scroll = rememberScrollState()
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .verticalScroll(scroll)
            .imePadding()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            text = "Manage paired devices",
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp,
        )

        OwnIdentityCard(ownFingerprint, ownIp)

        HorizontalDivider()

        Text(
            text = "Paired devices",
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp,
        )
        if (devices.isEmpty()) {
            Text(
                text = "No paired devices yet. Pair a device below to enable verified sync.",
                color = MaterialTheme.colorScheme.onSurface,
            )
        } else {
            LazyColumn(
                modifier = Modifier.height((devices.size * 190).dp.coerceAtMost(560.dp)),
                contentPadding = PaddingValues(vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(devices, key = { it.name }) { device ->
                    TrustedDeviceRow(
                        device = device,
                        onRemove = { presenter.onRemoveDevice(device.name) },
                        onToggleOp = { op, enabled -> presenter.onToggleDeviceOp(device, op, enabled) },
                        onUpgrade = { presenter.onUpgradePairingClick(device) },
                    )
                }
            }
        }

        HorizontalDivider()

        Text(
            text = "Pair a device",
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp,
        )

        // The entry states are the only ones the mode speaks for: a compare, a confirmation, or a
        // failure mid-ceremony is the same card whichever entry the user arrived through.
        //
        // In QR mode neither transient state is a resting place the manual entry could stand in for.
        // Idle is the sub-second window while the nonce is being armed, and Fetching is a scan
        // already in flight — swapping in the address field would flash a control the user did not
        // ask for and would invite them to type into a ceremony that is already running. Both stay
        // in the code's own card with a spinner where the code will be.
        when (val state = pairingState) {
            is PairingState.Idle -> when (entryMode) {
                PairingEntryMode.QR -> PairingQrCard(
                    code = null,
                    status = "Preparing code…",
                    onScanClick = { showScanner = true },
                    onEnterManualMode = presenter::onEnterManualMode,
                )

                PairingEntryMode.MANUAL -> PairingEntry(
                    pairAddress = pairAddress,
                    busy = false,
                    error = null,
                    presenter = presenter,
                    onScanClick = { showScanner = true },
                )
            }

            // Gated on the mode like every other entry state, defensively: the view model retires a
            // code the user turned away from mid-build rather than publishing it, but a QR card
            // standing over the address field they asked for is bad enough to be worth two answers.
            is PairingState.ShowingQr -> when (entryMode) {
                PairingEntryMode.QR -> PairingQrCard(
                    code = state.code,
                    status = null,
                    onScanClick = { showScanner = true },
                    onEnterManualMode = presenter::onEnterManualMode,
                    onCopy = presenter::onCopyCodeClick,
                )

                PairingEntryMode.MANUAL -> PairingEntry(
                    pairAddress = pairAddress,
                    busy = false,
                    error = null,
                    presenter = presenter,
                    onScanClick = { showScanner = true },
                )
            }

            is PairingState.Fetching -> when (entryMode) {
                // A scan already contacting the peer owns the screen, so the card's own actions are
                // gone rather than greyed: the exchange can hang, and the way out of one is the only
                // thing left to offer.
                PairingEntryMode.QR -> PairingQrCard(
                    code = null,
                    status = "Contacting peer…",
                    onScanClick = { showScanner = true },
                    onEnterManualMode = presenter::onEnterManualMode,
                    onCancel = presenter::onCancelPairingClick,
                )

                PairingEntryMode.MANUAL -> PairingEntry(
                    pairAddress = pairAddress,
                    busy = true,
                    error = null,
                    presenter = presenter,
                    onScanClick = { showScanner = true },
                )
            }

            // Nothing returns from a failure on its own — the QR card's own recovery is the reshow,
            // which arms the fresh nonce the old code no longer has.
            is PairingState.Failed -> when (entryMode) {
                PairingEntryMode.QR -> PairingFailedCard(
                    message = state.message,
                    onShowQr = presenter::onShowQrClick,
                    onEnterManualMode = presenter::onEnterManualMode,
                )

                PairingEntryMode.MANUAL -> PairingEntry(
                    pairAddress = pairAddress,
                    busy = false,
                    error = state.message,
                    presenter = presenter,
                    onScanClick = { showScanner = true },
                )
            }

            is PairingState.CompareSafetyNumber -> CompareSafetyNumberCard(
                state = state,
                pairName = pairName,
                safetyNumberCompared = safetyNumberCompared,
                canConfirm = canConfirm,
                presenter = presenter,
            )

            is PairingState.Confirmed -> ConfirmedCard(
                deviceName = state.deviceName,
                onDone = presenter::onPairingDismissed,
            )
        }
    }
}

@Composable
private fun OwnIdentityCard(ownFingerprint: String?, ownIp: String) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(text = "This device", fontWeight = FontWeight.SemiBold)
            Text(text = "Address", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurface)
            SelectionContainer {
                Text(
                    text = ownIp.ifBlank { "Unavailable" },
                    fontFamily = FontFamily.Monospace,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.SemiBold,
                )
            }
            Spacer(modifier = Modifier.height(4.dp))
            Text(text = "Public identity", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurface)
            if (ownFingerprint == null) {
                Text(
                    text = "Unavailable (sign in first)",
                    fontSize = 12.sp,
                    color = MaterialTheme.colorScheme.error,
                )
            } else {
                Text(
                    text = "Ready",
                    fontSize = 12.sp,
                    color = MaterialTheme.passmanColors.success,
                    fontWeight = FontWeight.SemiBold,
                )
                SelectionContainer {
                    Text(
                        text = ownFingerprint,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                    )
                }
            }
            Text(
                text = "Read this address out to the peer. Pairing runs from both sides: enter " +
                    "the peer's address here while they enter yours on their screen.",
                fontSize = 12.sp,
            )
        }
    }
}

/**
 * Manual address entry — the secondary way in, for a peer whose code cannot be scanned or pasted.
 * The QR card is what the screen rests on; this is reached by asking for it and left by "Show QR
 * instead", so the mode it belongs to is sticky rather than a state the screen falls back into.
 */
@Composable
private fun PairingEntry(
    pairAddress: String,
    busy: Boolean,
    error: String?,
    presenter: TrustedDevicesViewModel,
    onScanClick: () -> Unit,
) {
    Text(
        text = "Enter the peer's address and start pairing. Both devices must keep this screen " +
            "open; each side starts pairing toward the other, then compares the same safety number.",
        color = MaterialTheme.colorScheme.onSurface,
    )

    OutlinedTextField(
        value = pairAddress,
        onValueChange = presenter::onPairAddressChanged,
        label = { Text("Peer address or pairing code", color = MaterialTheme.colorScheme.onSurface) },
        singleLine = true,
        enabled = !busy,
        modifier = Modifier.fillMaxWidth(),
    )

    error?.let {
        Text(text = it, color = MaterialTheme.colorScheme.error)
    }

    PassmanPrimaryButton(
        text = if (busy) "Contacting peer…" else "Start pairing",
        onClick = presenter::onBeginPairingClick,
        enabled = !busy && pairAddress.isNotBlank(),
        modifier = Modifier.fillMaxWidth(),
    )

    // The QR skips the digit-by-digit compare, so it is offered alongside the manual address —
    // showing a code needs no address at all, and scanning one supplies its own.
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        PassmanSecondaryButton(
            text = "Show QR instead",
            onClick = presenter::onShowQrClick,
            enabled = !busy,
            modifier = Modifier.weight(1f),
        )
        if (cameraQrScanningSupported) {
            PassmanSecondaryButton(
                text = "Scan QR",
                onClick = onScanClick,
                enabled = !busy,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

/**
 * This device's pairing code — the screen's resting view, shown while its nonce is armed. The QR
 * stays black-on-white for scanners; the same string is selectable and copyable so two desktops
 * (no camera) can pair by pasting it into the peer's address field.
 *
 * A null [code] is the card waiting on one: the nonce being armed on entry, or a scan already
 * contacting the peer. The container is identical either way, with the spinner drawn in the square
 * the code will occupy — the code appears in place rather than the layout jumping under a user who
 * is already pointing a camera at it. Everything the code itself is needed for (copying it, and
 * scanning the peer's, which drops the one on screen) waits with it. Leaving for the address field
 * does not: that is the way out of a card that never managed to show a code, so it is always live.
 *
 * [onCancel] is the escape from a state the user cannot otherwise leave — a scan already contacting
 * the peer, which can hang. Passing it replaces the card's actions rather than joining them: nothing
 * else is worth offering while an exchange the screen does not own is in flight.
 *
 * [onCopy] goes back to the ViewModel rather than reaching for the Compose clipboard here: the copy
 * belongs to the same domain path — and the same clipboard policy — as every other copy in the app.
 * It defaults to nothing for the same reason the button is gated: with no code there is no copy.
 */
@Composable
private fun PairingQrCard(
    code: String?,
    status: String?,
    onScanClick: () -> Unit,
    onEnterManualMode: () -> Unit,
    onCopy: () -> Unit = {},
    onCancel: (() -> Unit)? = null,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            // Names the card, not its contents: it heads a spinner as often as a code, and a header
            // promising a code over an empty square is a header that lied.
            Text(text = "Pair with this device", fontWeight = FontWeight.SemiBold)
            // Padding sits outside the aspect ratio so the square is the drawn code, not the code
            // plus its inset. Capped and centred because a full-width QR on a desktop window is a
            // wall of black-and-white that no camera needs and no layout wants.
            val codeSlot = Modifier
                .align(Alignment.CenterHorizontally)
                .padding(8.dp)
                .widthIn(max = 280.dp)
                .fillMaxWidth()
                .aspectRatio(1f)
            if (code == null) {
                Box(modifier = codeSlot, contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(32.dp),
                        strokeWidth = 3.dp,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            } else {
                QrCodeImage(content = code, modifier = codeSlot)
                SelectionContainer {
                    Text(
                        text = code,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
            status?.let {
                Text(
                    text = it,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (code != null) {
                PassmanSecondaryButton(
                    text = "Copy code",
                    onClick = onCopy,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text = "Scan this with the other device's camera, or copy the code and paste " +
                        "it into its address field. Prefer typing? Enter the address manually below.",
                    fontSize = 12.sp,
                )
            }
            if (onCancel != null) {
                PassmanSecondaryButton(
                    text = "Cancel",
                    onClick = onCancel,
                    modifier = Modifier.fillMaxWidth(),
                )
            } else {
                // Scanning the peer's code is the other half of the same gesture and gets the
                // prominent button; typing an address is the fallback for the device that can do
                // neither, and stays available even while there is no code — a card stuck without
                // one is exactly when the user needs it.
                //
                // Stacked rather than shared across a row: "Enter address manually" does not fit
                // half a phone's width, and half a label is worse than a taller card.
                if (cameraQrScanningSupported) {
                    PassmanPrimaryButton(
                        text = "Scan QR",
                        onClick = onScanClick,
                        enabled = code != null,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
                PassmanSecondaryButton(
                    text = "Enter address manually",
                    onClick = onEnterManualMode,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

/**
 * A pairing failure with the QR mode still selected: the code that failed is gone with its nonce,
 * and nothing brings the next one up on its own. Reshowing arms a fresh nonce, so it is offered as
 * the primary action; the manual entry stays reachable for a peer the code cannot reach at all.
 */
@Composable
private fun PairingFailedCard(message: String, onShowQr: () -> Unit, onEnterManualMode: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "Pairing failed", fontWeight = FontWeight.SemiBold)
            Text(text = message, color = MaterialTheme.colorScheme.error, fontSize = 12.sp)
            PassmanPrimaryButton(
                text = "Show QR again",
                onClick = onShowQr,
                modifier = Modifier.fillMaxWidth(),
            )
            PassmanSecondaryButton(
                text = "Enter address manually",
                onClick = onEnterManualMode,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
private fun CompareSafetyNumberCard(
    state: PairingState.CompareSafetyNumber,
    pairName: String,
    safetyNumberCompared: Boolean,
    canConfirm: Boolean,
    presenter: TrustedDevicesViewModel,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
        ),
        shape = RoundedCornerShape(8.dp),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(text = "Safety number for ${state.peerAddress}", fontWeight = FontWeight.SemiBold)
            SelectionContainer {
                Text(
                    text = state.safetyNumber,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            // The number stays visible either way: an auto-verified pairing should still be
            // checkable by hand if the user wants to.
            if (state.verifiedViaQr) {
                // The success green is tuned for the surface palette and lands at about 1.05:1 on
                // this card's primary container in dark mode — the strongest signal on the screen,
                // rendered invisible. The card's own contentColor is the pair that is guaranteed to
                // read against it, so the check icon carries the "verified" meaning instead of hue.
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Icon(
                        imageVector = Icons.Default.Check,
                        contentDescription = null,
                        modifier = Modifier.size(16.dp),
                    )
                    Text(
                        text = "Verified via QR — both devices confirmed each other cryptographically.",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = LocalContentColor.current,
                    )
                }
            } else {
                Text(
                    text = "The peer must start pairing toward this device to see its number. Both " +
                        "screens must show exactly these digits — if they differ, cancel: someone " +
                        "may be intercepting the connection.",
                    fontSize = 12.sp,
                )
            }
        }
    }

    OutlinedTextField(
        value = pairName,
        onValueChange = presenter::onPairNameChanged,
        label = { Text("Device name (e.g. \"Sterling's Pixel\")", color = MaterialTheme.colorScheme.onSurface) },
        singleLine = true,
        modifier = Modifier.fillMaxWidth(),
    )

    // The attestation is what the manual ceremony rests on; the possession proof already made it,
    // so asking for it again would only teach the user to tick boxes without looking.
    if (!state.verifiedViaQr) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(
                checked = safetyNumberCompared,
                onCheckedChange = presenter::onSafetyNumberComparedChanged,
            )
            Text(text = "I compared these values on both devices and they match")
        }
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        PassmanSecondaryButton(
            text = "Cancel",
            onClick = presenter::onCancelPairingClick,
            modifier = Modifier.weight(1f),
        )
        PassmanPrimaryButton(
            text = "Confirm pairing",
            onClick = presenter::onConfirmPairingClick,
            enabled = canConfirm,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun ConfirmedCard(deviceName: String, onDone: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(
                text = "Paired with $deviceName",
                fontWeight = FontWeight.SemiBold,
                color = MaterialTheme.passmanColors.success,
            )
            Text(
                text = "Sync with this device now requires post-quantum signed payloads bound to " +
                    "the confirmed identity.",
                fontSize = 12.sp,
            )
            PassmanPrimaryButton(text = "Done", onClick = onDone, modifier = Modifier.fillMaxWidth())
        }
    }
}

@Composable
private fun TrustedDeviceRow(
    device: TrustedDevice,
    onRemove: () -> Unit,
    onToggleOp: (op: String, enabled: Boolean) -> Unit,
    onUpgrade: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
    ) {
        Column(modifier = Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(text = device.name, fontWeight = FontWeight.SemiBold)
                    PairingSecurityLabel(device.pairingSecurity)
                    Text(
                        text = "Last host: ${device.lastHost}",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Text(
                        text = "Last sync: ${formatLastSync(device.lastSyncedAt)}",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                }
                IconButton(onClick = onRemove) {
                    Icon(imageVector = Icons.Default.Delete, contentDescription = "Remove device")
                }
            }
            Text(text = "Allowed sync", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(4.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                OpToggle("Passwords", SyncOps.PASSWORDS, device.allowedOps, onToggleOp)
                OpToggle("PGP", SyncOps.PGP, device.allowedOps, onToggleOp)
                OpToggle("Keystore", SyncOps.KEYSTORE, device.allowedOps, onToggleOp)
            }
            when (device.pairingSecurity) {
                PairingSecurity.LegacyRsa -> {
                    PassmanSecondaryButton(
                        text = "Upgrade pairing security",
                        onClick = onUpgrade,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                PairingSecurity.AwaitingConfirmation -> {
                    PassmanSecondaryButton(
                        text = "Re-verify pairing",
                        onClick = onUpgrade,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                PairingSecurity.SignedHybridRequired -> Unit
            }
        }
    }
}

@Composable
private fun PairingSecurityLabel(security: PairingSecurity) {
    when (security) {
        PairingSecurity.LegacyRsa -> Text(
            text = "Legacy transport pin",
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.passmanColors.warning,
        )

        PairingSecurity.AwaitingConfirmation -> Text(
            text = "Re-verification needed — sync is paused until the safety number is re-confirmed",
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.error,
        )

        PairingSecurity.SignedHybridRequired -> Text(
            text = "Post-quantum signed sync",
            fontSize = 12.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.passmanColors.success,
        )
    }
}

private fun formatLastSync(timestampMs: Long): String {
    if (timestampMs <= 0L) return "never"
    val local = Instant.fromEpochMilliseconds(timestampMs).toLocalDateTime(TimeZone.currentSystemDefault())
    val minute = local.minute.toString().padStart(2, '0')
    return "${local.date.day}/${local.date.month.number}/${local.date.year} ${local.hour}:$minute"
}

@Composable
private fun OpToggle(
    label: String,
    op: String,
    allowedOps: Set<String>,
    onToggleOp: (op: String, enabled: Boolean) -> Unit,
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(
            checked = op in allowedOps,
            onCheckedChange = { onToggleOp(op, it) },
        )
        Text(text = label, fontSize = 11.sp)
    }
}
