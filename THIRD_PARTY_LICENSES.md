# Third-party licences

## ProjectDiscovery Nuclei and nuclei-templates (MIT)

Used at run time (Nuclei) and adapted in `templates/windows/rdp-open.yaml` (nuclei-templates).

```
MIT License

Copyright (c) ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Eclipse Temurin / OpenJDK Java runtime (GPL v2 with the Classpath Exception)

The self-contained release bundles (`...-windows-x64.zip`, `...-linux-*.tar.gz`, `...-macos-*.tar.gz`) include a Java 17
runtime built with `jpackage` from Eclipse Temurin (https://adoptium.net), an OpenJDK build licensed under the GNU General Public
License version 2 with the Classpath Exception. The runtime is unmodified and separate from this project's Apache-2.0 code. Its
licence texts and notices are included in the bundle, in the `legal` folder inside the runtime folder (for example
`lib/runtime/legal` on Linux), and the OpenJDK source code is available from https://github.com/openjdk/jdk17u. The jar-only
downloads contain no Java runtime.
