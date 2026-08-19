package ai.passman.android.di

import org.koin.dsl.module

/**
 * Release logging is disabled.
 *
 * Debug output records vault paths, keystore file names, user names, and provider error text.
 * Warnings and errors can carry the same data, so a production build intentionally registers
 * no AndroidLogger. KLogger therefore has no sink and does not evaluate its lazy messages.
 */
val buildTypeModule = module { }
