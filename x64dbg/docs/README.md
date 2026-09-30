# docs

Documentation repository for [x64dbg](http://x64dbg.com) at [Read the Docs](https://readthedocs.org/projects/x64dbg).

## Building

Run `makechm.bat`. It will build the .CHM help file.

When first building the .CHM help file, it automatically downloads
[python 2.7.18 portable](https://github.com/x64dbg/docs/releases/download/python27-portable/python-2.7.18.amd64.portable.7z) and
[Microsoft HTML Help Compiler 4.74.8702](https://github.com/x64dbg/deps/releases/download/dependencies/hhc-4.74.8702.7z) from GitHub.
Then, `7z` is used to extract the downloaded archive, so make sure [7-zip](https://7-zip.org/) is installed, and `7z` command can be accessed from
the current directory.

Note: The following patch was applied:


Add `relpath = relpath.replace(os.path.sep, '/')` after `C:\Python27\Lib\site-packages\recommonmark\transform.py` line `63`
