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
' ★ 0.7.6：**必须把 frpc 的输出落盘**。
'
' 原先这里用隐藏窗口（window style 0）直接 `ws.Run("frpc.exe ...")` ——
' stdout/stderr 没有控制台承接，全部丢失；模板里 `[log] to` 又是默认关闭的。
' 结果是开机自启出问题时**一份日志都没有**，用户只能看到面板里的空列表。
' 现在统一用 `cmd /c ... >> frpc.log 2>&1` 追加写盘（超过 5 MB 自动滚动）。
'
' 注意：如果 frpc 是因为「服务端明确拒绝登录」（令牌错等）而快速退出，
' 本包装会每 30 秒重试一次并在 frpc.log 里留下同样的错误；改好配置后
' 无需重启电脑，下一次重试就会成功。

Option Explicit

Dim fso, ws, here, logPath, started, rc, elapsed

Set fso = CreateObject("Scripting.FileSystemObject")
Set ws = CreateObject("WScript.Shell")

' 以脚本所在目录为工作目录，避免依赖固定的 scoop 路径
here = fso.GetParentFolderName(WScript.ScriptFullName)
ws.CurrentDirectory = here
logPath = fso.BuildPath(here, "frpc.log")

Do
    ' 日志滚动：超过 5 MB 直接清空。自启场景只关心"最近一次为什么失败"，
    ' 留着历史日志把磁盘写满反而是新的故障源。
    On Error Resume Next
    If fso.FileExists(logPath) Then
        If fso.GetFile(logPath).Size > 5 * 1024 * 1024 Then
            fso.DeleteFile logPath, True
        End If
    End If
    On Error GoTo 0

    On Error Resume Next
    started = Timer
    rc = ws.Run("cmd /c ""frpc.exe -c frpc.toml >> frpc.log 2>&1""", 0, True)
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
