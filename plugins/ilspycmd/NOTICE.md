# ilspycmd plugin

This directory only contains a manifest. OmniDecomp does not bundle or redistribute ILSpy.

- Engine: ILSpy command line (`ilspycmd`), MIT license, https://github.com/icsharpcode/ILSpy
- Install it yourself, for example `dotnet tool install -g ilspycmd`, so that `ilspycmd` is on PATH.
- Enable: `omnidecomp plugins enable ilspycmd`
- Use: `omnidecomp decompile app.dll --engine ilspycmd --allow-external-exec`

The manifest is MIT-licensed along with the rest of OmniDecomp. The engine keeps its own license.
