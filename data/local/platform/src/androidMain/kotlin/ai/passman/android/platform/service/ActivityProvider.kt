package ai.passman.android.platform.service

import ai.passman.domain.app.persistence.ForegroundEventPersistence
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.initialization.AppInitializer
import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.util.Log
import kotlinx.coroutines.launch

internal class ActivityProvider(
    private val application: Application,
    private val coroutinesScopeFacade: CoroutineScopeFacade,
    private val foregroundEventPersistence: ForegroundEventPersistence
) : AppInitializer {

    private var activityOnTop: Activity? = null

    override suspend fun initialize() {
        application.registerActivityLifecycleCallbacks(object : Application.ActivityLifecycleCallbacks {
            override fun onActivityPaused(activity: Activity) {
                Log.i("ActivityProvider", "on activity paused")
                activityOnTop = null
                coroutinesScopeFacade.globalScope.launch {
                    foregroundEventPersistence.update(false)
                }
            }

            override fun onActivityResumed(activity: Activity) {
                Log.i("ActivityProvider", "on activity resumed")
                activityOnTop = activity
                coroutinesScopeFacade.globalScope.launch {
                    foregroundEventPersistence.update(true)
                }
            }

            override fun onActivityStarted(activity: Activity) = Unit

            override fun onActivityDestroyed(activity: Activity) = Unit

            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit

            override fun onActivityStopped(activity: Activity) = Unit

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) = Unit
        })
    }

    fun get(): Activity? = activityOnTop
}
