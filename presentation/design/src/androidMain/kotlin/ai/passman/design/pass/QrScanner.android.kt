package ai.passman.design.pass

import android.Manifest
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.google.accompanist.permissions.isGranted
import com.google.accompanist.permissions.rememberPermissionState
import com.google.accompanist.permissions.shouldShowRationale
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

actual val cameraQrScanningSupported: Boolean = true

@OptIn(ExperimentalPermissionsApi::class)
@Composable
actual fun QrCameraScannerDialog(onResult: (String) -> Unit, onDismiss: () -> Unit) {
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false),
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = MaterialTheme.colorScheme.surface,
        ) {
            val permission = rememberPermissionState(Manifest.permission.CAMERA)
            if (permission.status.isGranted) {
                CameraQrPreview(onResult)
            } else {
                LaunchedEffect(Unit) { permission.launchPermissionRequest() }
                Column(
                    modifier = Modifier.fillMaxSize().padding(32.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally,
                ) {
                    Text(
                        text = if (permission.status.shouldShowRationale) {
                            "Scanning the setup QR needs the camera. Nothing is recorded — frames are read on-device and discarded."
                        } else {
                            "Camera permission is required to scan. If no prompt appears, enable Camera for PassMan in system settings."
                        },
                        color = MaterialTheme.colorScheme.onSurface,
                    )
                    Button(
                        modifier = Modifier.fillMaxWidth().padding(top = 24.dp),
                        onClick = { permission.launchPermissionRequest() },
                    ) {
                        Text("Grant camera access")
                    }
                    TextButton(onClick = onDismiss) {
                        Text("Cancel")
                    }
                }
            }
        }
    }
}

@Composable
private fun CameraQrPreview(onResult: (String) -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    // One delivery per scanner: frames keep arriving after the first hit until unbind runs.
    val delivered = remember { AtomicBoolean(false) }
    val analysisExecutor = remember { Executors.newSingleThreadExecutor() }
    val mainExecutor = remember { ContextCompat.getMainExecutor(context) }

    Box(modifier = Modifier.fillMaxSize()) {
        androidx.compose.ui.viewinterop.AndroidView(
            modifier = Modifier.fillMaxSize(),
            factory = { ctx ->
                val previewView = PreviewView(ctx)
                val providerFuture = ProcessCameraProvider.getInstance(ctx)
                providerFuture.addListener({
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also {
                        it.surfaceProvider = previewView.surfaceProvider
                    }
                    val analysis = ImageAnalysis.Builder()
                        .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                        .build()
                    analysis.setAnalyzer(analysisExecutor) { frame ->
                        val payload = frame.use(::decodeQrFrame)
                        if (payload != null && delivered.compareAndSet(false, true)) {
                            mainExecutor.execute { onResult(payload) }
                        }
                    }
                    provider.unbindAll()
                    provider.bindToLifecycle(
                        lifecycleOwner,
                        CameraSelector.DEFAULT_BACK_CAMERA,
                        preview,
                        analysis,
                    )
                }, mainExecutor)
                previewView
            },
        )
    }

    DisposableEffect(Unit) {
        onDispose {
            // The future resolved long before a dispose can run; get() does not block here.
            runCatching { ProcessCameraProvider.getInstance(context).get().unbindAll() }
            analysisExecutor.shutdown()
        }
    }
}

private val frameHints = mapOf(
    DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
)

/** QR finder patterns make detection orientation-invariant, so no frame rotation is needed. */
private fun decodeQrFrame(frame: ImageProxy): String? {
    val yPlane = frame.planes[0]
    val bytes = ByteArray(yPlane.buffer.remaining()).also { yPlane.buffer.get(it) }
    val source = PlanarYUVLuminanceSource(
        bytes,
        yPlane.rowStride,
        frame.height,
        0,
        0,
        frame.width,
        frame.height,
        false,
    )
    return runCatching {
        MultiFormatReader().decode(BinaryBitmap(HybridBinarizer(source)), frameHints).text
    }.getOrNull()
}
