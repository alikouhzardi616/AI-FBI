[app]
title = AI FBI
package.name = aifbi
package.domain = org.alikouhzardi
source.dir = .
source.include_exts = py,json
source.exclude_dirs = tests,__pycache__,.git,dist,build
version = 1.0.0
author = Ali Kouhzardi
description = Local-first heuristic security scanner and monitor
requirements = python3,kivy
orientation = all
fullscreen = 0

[buildozer]
log_level = 2
warn_on_root = 1

[android]
android.api = 35
android.minapi = 23
android.archs = arm64-v8a
android.permissions = READ_EXTERNAL_STORAGE,WRITE_EXTERNAL_STORAGE
android.allow_backup = False
