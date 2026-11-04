' NFRp 开机自启包装（Windows）
'
' 用法：把本文件与 frpc.exe、frpc.toml 放在同一目录，用「任务计划程序」或
' 「启动」文件夹调用：
'     wscript.exe /nologo frpc-autostart.vbs
'
' 作用：frpc 0.7.5 起，开机时网络/代理/KCP 未就绪只会退避重试，正常不会再
' 自己退出。这里再加一层兜底：万一进程崩溃/被杀，包装会等待后重新拉起，
' 避免 vbs 拉起一次就再也不管。
'
' 注意：如果 frpc 是因为「服务端明确拒绝登录」（令牌错等）而快速退出，
' 本包装会每 30 秒重试一次并在 frpc.log 里留下同样的错误；改好配置后
' 无需重启电脑，下一次重试就会成功。

Option Explicit

Dim fso, ws, here, started, rc, elapsed

Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")

' 以脚本所在目录为工作目录，避免依赖固定的 scoop 路径
here = fso.GetParentFolderName(WScript.ScriptFullName)
ws.CurrentDirectory = here

Do
    On Error Resume Next
    started = Timer
    rc = ws.Run("frpc.exe -c frpc.toml", 0, True)
    elapsed = Timer - started
    If elapsed < 0 Then elapsed = elapsed + 86400   ' 跨午夜回绕
    On Error GoTo 0

    If elapsed < 60 Then
        ' 秒退：配置错误 / 端口占用 / 被杀，慢一点重试，避免刷屏
        WScript.Sleep 30000
    Else
        ' 长跑后正常退出：快速重连
        WScript.Sleep 5000
    End If
Loop
