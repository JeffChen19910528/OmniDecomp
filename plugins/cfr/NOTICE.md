# CFR plugin

This directory only contains a manifest. OmniDecomp does not bundle or redistribute CFR.

- Engine: CFR, MIT license, https://github.com/leibnitz27/cfr
- CFR ships as a jar. Create a small launcher named `cfr` (an `.exe` on Windows, a script on Unix; batch
  files are refused) that runs `java -jar <path-to-cfr.jar> "$@"`, and put it on PATH.
- Verified with CFR 0.152 and a minimal launcher that runs `java -jar cfr-0.152.jar <args>` (see docs/ACCEPTANCE.md).
- Enable: `omnidecomp plugins enable cfr`
- Use: `omnidecomp decompile Main.class --engine cfr --allow-external-exec`

The manifest is MIT-licensed along with the rest of OmniDecomp. The engine keeps its own license.
